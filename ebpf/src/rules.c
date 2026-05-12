/* SPDX-License-Identifier: GPL-2.0
 * rules.c — v2.1 rule enforcement, two programs sharing one map set.
 *
 *   SEC("xdp") xdp_rules          → attached to eth0 (pre-tunnel, WAN).
 *                                    Sees Ethernet-framed packets.
 *   SEC("tc")  tc_rules_wg0       → attached to wg0 clsact ingress
 *                                    (post-decryption). wg0 is a pure
 *                                    L3 device (ARPHRD_NONE); skb->data
 *                                    already points at the iphdr.
 *
 * v2.1 — per-packet iteration. The v2.0 LPM-by-source design held one
 * rule per src_cidr in a trie, so two rules sharing a source silently
 * overwrote each other. v2.1 stores every active rule in a packed
 * BPF_MAP_TYPE_ARRAY (rule_table_v4 / rule_table_v6) keyed by slot
 * index and walks the whole list per packet via bpf_loop. The first
 * full match (priority-sorted on the userspace side) wins.
 *
 * Both XDP and TC programs feed the same decide_v4/decide_v6 path:
 *   1. Build a match_ctx with packet fields (addrs, protocol, ports,
 *      direction, byte count).
 *   2. bpf_loop(count, evaluate_rule_v[46], &ctx, 0). The callback
 *      reads one record from rule_table_v[46], does inline CIDR +
 *      protocol + port matching, and on a full match stamps ctx
 *      with the verdict and returns 1 (stop). Returning 0 continues.
 *   3. Dispatch the action stored in ctx.verdict.
 *
 * Verdicts flow as XDP codes throughout; the TC wrapper translates
 * XDP_DROP → TC_ACT_SHOT at the top of tc_rules_wg0. Keeping the
 * internal verdict representation uniform means decide_* and
 * rate_check_* need no per-hook branching.
 *
 * IPv4 and IPv6 live in separate rule tables because record sizes
 * differ (44 B vs 68 B). A single packet checks the family that
 * matches its ethtype/skb->protocol and returns.
 *
 * IPv6 extension headers are NOT walked: nexthdr is assumed to be the
 * L4 protocol directly. Rules that need to match through HBH/Routing/
 * Fragment headers will miss in the meantime — documented limitation,
 * worth revisiting once we have production traffic samples.
 *
 * Min kernel: 5.17 for bpf_loop, 5.8 for ringbuf. The capabilities
 * probe surfaces both before the loader tries to install.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>

#include "../headers/bpf_helpers.h"
#include "../headers/nexushub.h"

char LICENSE[] SEC("license") = "GPL";

/* rule_table_v4 — packed array of active IPv4 rules, slot 0..count-1.
 * Slots >= rule_count_v4[0] are unused (is_active=0, but the loop never
 * reaches them anyway). Userspace owns priority ordering. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct rule_v4_record);
    __uint(max_entries, MAX_ACTIVE_RULES_V4);
} rule_table_v4 SEC(".maps");

/* rule_count_v4 — single-slot u32 holding the number of populated
 * slots in rule_table_v4. bpf_loop's iteration count comes from here. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} rule_count_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct rule_v6_record);
    __uint(max_entries, MAX_ACTIVE_RULES_V6);
} rule_table_v6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} rule_count_v6 SEC(".maps");

/* PERCPU_HASH (rule_id, src_addr) → rate_tokens. Per-CPU to avoid
 * the global spinlock cost; the small overshoot from racing CPUs is
 * acceptable for rate-limiting semantics (documented in ADR 0004). */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, struct rate_key_v4);
    __type(value, struct rate_tokens);
    __uint(max_entries, MAX_RATE_STATE);
} rate_state_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, struct rate_key_v6);
    __type(value, struct rate_tokens);
    __uint(max_entries, MAX_RATE_STATE);
} rate_state_v6 SEC(".maps");

/* PERCPU_HASH rule_id → struct rule_hits. Lossless counter ticked
 * on every matched rule regardless of action — the ringbuf can drop
 * under load and only fires for ACTION_LOG, whereas this map
 * captures ALLOW/DENY/RATE_LIMIT matches too. Keyed by the
 * userspace-assigned rule_id stored in each record. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, __u32);
    __type(value, struct rule_hits);
    __uint(max_entries, MAX_RULES);
} rule_hits SEC(".maps");

/* RINGBUF for ACTION_LOG telemetry. Userspace drains it into
 * connection_logs. 1 MiB gives ~18k events of headroom; the kernel-side
 * drop on full is acceptable — logging is best-effort. */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, LOG_RINGBUF_SIZE);
} log_events SEC(".maps");

/* count_hit ticks the per-rule counter. Called once per matched
 * rule, before action dispatch, so every match is recorded even
 * when the action subsequently drops the packet. */
static __always_inline void
count_hit(__u32 rule_id, __u32 bytes)
{
    struct rule_hits *h = bpf_map_lookup_elem(&rule_hits, &rule_id);
    if (h) {
        h->packets += 1;
        h->bytes += bytes;
        return;
    }
    struct rule_hits fresh = { .packets = 1, .bytes = bytes };
    bpf_map_update_elem(&rule_hits, &rule_id, &fresh, BPF_ANY);
}

static __always_inline int
protocol_matches(__u8 want, __u8 got)
{
    if (want == PROTO_ANY)
        return 1;
    if (want == PROTO_TCP && got == IPPROTO_TCP)
        return 1;
    if (want == PROTO_UDP && got == IPPROTO_UDP)
        return 1;
    if (want == PROTO_ICMP && (got == IPPROTO_ICMP || got == IPPROTO_ICMPV6))
        return 1;
    return 0;
}

/* v4_in_cidr — does addr (4 on-wire bytes) fall under cidr/prefix_len?
 * Both inputs are network byte order. The function compares full bytes
 * up to (prefix_len / 8), then masks the remaining bits in the next
 * byte. Bounds are constant so the verifier accepts the indexed
 * accesses without complaint. */
static __always_inline int
v4_in_cidr(const __u8 addr[4], const __u8 cidr[4], __u8 prefix_len)
{
    if (prefix_len == 0)
        return 1;
    if (prefix_len > 32)
        prefix_len = 32;

    __u8 full_bytes = prefix_len >> 3;
    __u8 partial_bits = prefix_len & 7;

    if (full_bytes >= 1 && addr[0] != cidr[0]) return 0;
    if (full_bytes >= 2 && addr[1] != cidr[1]) return 0;
    if (full_bytes >= 3 && addr[2] != cidr[2]) return 0;
    if (full_bytes >= 4) return 1; /* exact /32 */

    if (partial_bits == 0)
        return 1;
    __u8 idx = full_bytes & 3;
    __u8 mask = (__u8)(0xFFu << (8 - partial_bits));
    return (addr[idx] & mask) == (cidr[idx] & mask);
}

/* v6_in_cidr — same idea over 16 bytes. We aggregate the per-byte
 * diff into a single `mismatch` accumulator instead of returning
 * early; this makes the loop body branch-free, which lets clang
 * fully unroll it under -O2 and keeps the verifier happy with 16
 * straight-line bytewise compares. */
static __always_inline int
v6_in_cidr(const __u8 addr[16], const __u8 cidr[16], __u16 prefix_len)
{
    if (prefix_len == 0)
        return 1;
    if (prefix_len > 128)
        prefix_len = 128;

    __u8 full_bytes = prefix_len >> 3;
    __u8 partial_bits = prefix_len & 7;
    __u8 mismatch = 0;

    #pragma unroll
    for (int i = 0; i < 16; i++) {
        __u8 mask_check = (i < full_bytes) ? 0xFFu : 0x00u;
        mismatch |= (addr[i] ^ cidr[i]) & mask_check;
    }
    if (mismatch)
        return 0;
    if (full_bytes >= 16)
        return 1;
    if (partial_bits == 0)
        return 1;
    __u8 idx = full_bytes & 0xF;
    __u8 mask = (__u8)(0xFFu << (8 - partial_bits));
    return (addr[idx] & mask) == (cidr[idx] & mask);
}

/* port_matches returns 1 if the observed port falls inside [from, to]
 * or if both bounds are 0 (wildcard). Ports on the wire are network
 * order; rule records store them in host order. */
static __always_inline int
port_matches(__u16 port_net, __u16 from_host, __u16 to_host)
{
    if (from_host == 0 && to_host == 0)
        return 1;
    __u16 port_host = bpf_ntohs(port_net);
    return port_host >= from_host && port_host <= to_host;
}

/* read_l4_ports pulls src/dst ports from TCP or UDP headers. Returns 1
 * on success and fills the sport and dport pointers (network order).
 * Returns 0 if there's no usable L4 header — caller treats sport=
 * dport=0, which means port-restricted rules won't match (correct)
 * but wildcard rules still match (also correct). */
static __always_inline int
read_l4_ports(void *l4, void *data_end, __u8 proto, __u16 *sport, __u16 *dport)
{
    if (proto != IPPROTO_TCP && proto != IPPROTO_UDP)
        return 0;
    if (l4 + 4 > data_end)
        return 0;
    __u16 *ports = l4;
    *sport = ports[0];
    *dport = ports[1];
    return 1;
}

/* token_bucket_step runs the shared refill + consume math on an
 * already-looked-up bucket. */
static __always_inline int
token_bucket_step(struct rate_tokens *t, __u32 pps, __u64 cap_x1000, __u64 now)
{
    __u64 elapsed = now - t->last_seen_ns;
    if (elapsed > 1000000000ULL)
        elapsed = 1000000000ULL;

    __u64 refill_x1000 = ((__u64)pps * elapsed) / 1000000ULL;
    __u64 new_tokens = t->tokens_x1000 + refill_x1000;
    if (new_tokens > cap_x1000)
        new_tokens = cap_x1000;

    t->last_seen_ns = now;

    if (new_tokens < 1000) {
        t->tokens_x1000 = new_tokens;
        return XDP_DROP;
    }
    t->tokens_x1000 = new_tokens - 1000;
    return XDP_PASS;
}

/* rate_check_v4 implements a token-bucket per (rule_id, src_addr).
 * src_addr_bytes is on-wire (network order). pps/burst come from the
 * matched rule record. Fail-open on map-full. */
static __always_inline int
rate_check_v4(__u32 rule_id, const __u8 src_addr_bytes[4],
              __u32 pps, __u32 burst)
{
    if (pps == 0)
        return XDP_PASS;

    __u32 cap = burst ? burst : pps;
    __u64 cap_x1000 = (__u64)cap * 1000ULL;

    struct rate_key_v4 k = { .rule_id = rule_id };
    __builtin_memcpy(&k.addr, src_addr_bytes, 4);
    __u64 now = bpf_ktime_get_ns();

    struct rate_tokens *t = bpf_map_lookup_elem(&rate_state_v4, &k);
    if (!t) {
        struct rate_tokens fresh = {
            .tokens_x1000 = cap_x1000,
            .last_seen_ns = now,
        };
        if (bpf_map_update_elem(&rate_state_v4, &k, &fresh, BPF_ANY) != 0)
            return XDP_PASS;
        t = bpf_map_lookup_elem(&rate_state_v4, &k);
        if (!t)
            return XDP_PASS;
    }
    return token_bucket_step(t, pps, cap_x1000, now);
}

static __always_inline int
rate_check_v6(__u32 rule_id, const __u8 src_addr[16],
              __u32 pps, __u32 burst)
{
    if (pps == 0)
        return XDP_PASS;

    __u32 cap = burst ? burst : pps;
    __u64 cap_x1000 = (__u64)cap * 1000ULL;

    struct rate_key_v6 k = { .rule_id = rule_id };
    __builtin_memcpy(k.addr, src_addr, 16);
    __u64 now = bpf_ktime_get_ns();

    struct rate_tokens *t = bpf_map_lookup_elem(&rate_state_v6, &k);
    if (!t) {
        struct rate_tokens fresh = {
            .tokens_x1000 = cap_x1000,
            .last_seen_ns = now,
        };
        if (bpf_map_update_elem(&rate_state_v6, &k, &fresh, BPF_ANY) != 0)
            return XDP_PASS;
        t = bpf_map_lookup_elem(&rate_state_v6, &k);
        if (!t)
            return XDP_PASS;
    }
    return token_bucket_step(t, pps, cap_x1000, now);
}

/* emit_log reserves a ringbuf slot and fills a log_event from the match.
 * Best effort — if the ringbuf is full or reserve fails we silently
 * drop the event rather than stalling the datapath. */
static __always_inline void
emit_log(__u32 rule_id, __u8 action, __u8 family, __u8 direction,
         __u32 bytes, __u8 l4_proto, __u16 sport_net, __u16 dport_net,
         const void *src_addr, const void *dst_addr, __u32 addr_len)
{
    struct log_event *ev = bpf_ringbuf_reserve(&log_events, sizeof(*ev), 0);
    if (!ev)
        return;

    ev->ts_ns     = bpf_ktime_get_ns();
    ev->rule_id   = rule_id;
    ev->src_port  = bpf_ntohs(sport_net);
    ev->dst_port  = bpf_ntohs(dport_net);
    ev->bytes     = bytes;
    ev->action    = action;
    ev->protocol  = l4_proto;
    ev->family    = family;
    ev->direction = direction;

    __builtin_memset(ev->src_addr, 0, sizeof(ev->src_addr));
    __builtin_memset(ev->dst_addr, 0, sizeof(ev->dst_addr));
    if (addr_len == 4) {
        __builtin_memcpy(ev->src_addr, src_addr, 4);
        __builtin_memcpy(ev->dst_addr, dst_addr, 4);
    } else if (addr_len == 16) {
        __builtin_memcpy(ev->src_addr, src_addr, 16);
        __builtin_memcpy(ev->dst_addr, dst_addr, 16);
    }

    bpf_ringbuf_submit(ev, 0);
}

/* match_ctx_v4 / _v6 — bpf_loop callback state. The verifier inspects
 * the callback once and proves it terminates within nr_loops; the ctx
 * pointer it carries between iterations must outlive the call (we
 * stack-allocate it in decide_*). All packet bytes the callback needs
 * are copied into the ctx up front so the verifier doesn't have to
 * track packet-pointer provenance across the loop boundary. */
struct match_ctx_v4 {
    __u8  src_addr[4];
    __u8  dst_addr[4];
    __u8  protocol;
    __u8  direction;
    __u8  _pad[2];
    __u16 sport_net;
    __u16 dport_net;
    __u32 bytes;
    int   verdict;
    __u8  matched;
    __u8  _pad2[3];
};

struct match_ctx_v6 {
    __u8  src_addr[16];
    __u8  dst_addr[16];
    __u8  protocol;
    __u8  direction;
    __u8  _pad[2];
    __u16 sport_net;
    __u16 dport_net;
    __u32 bytes;
    int   verdict;
    __u8  matched;
    __u8  _pad2[3];
};

/* evaluate_rule_v4 — bpf_loop callback. Returns 1 to stop the loop
 * (first match wins, priority-sorted by userspace), 0 to continue.
 * The signature is the kernel ABI for bpf_loop callbacks: (idx, ctx). */
static long
evaluate_rule_v4(__u32 idx, void *_ctx)
{
    struct match_ctx_v4 *ctx = _ctx;
    __u32 key = idx;
    struct rule_v4_record *r = bpf_map_lookup_elem(&rule_table_v4, &key);
    if (!r)
        return 1; /* impossible for an ARRAY map; treat as terminate */
    if (!r->is_active)
        return 0;

    /* Direction. Today both hooks pass direction=0 (ingress); a rule
     * created with direction=egress is a no-op until the egress hook
     * lands. DIR_BOTH matches every hook. */
    if (r->direction != DIR_BOTH && r->direction != ctx->direction)
        return 0;

    if (r->has_protocol && !protocol_matches(r->protocol, ctx->protocol))
        return 0;
    if (!r->has_protocol && r->protocol != PROTO_ANY &&
        !protocol_matches(r->protocol, ctx->protocol))
        return 0;

    if (r->has_src && !v4_in_cidr(ctx->src_addr, r->src_addr, r->src_prefix_len))
        return 0;
    if (r->has_dst && !v4_in_cidr(ctx->dst_addr, r->dst_addr, r->dst_prefix_len))
        return 0;

    if (!port_matches(ctx->sport_net, r->src_port_from, r->src_port_to))
        return 0;
    if (!port_matches(ctx->dport_net, r->dst_port_from, r->dst_port_to))
        return 0;

    /* Full match — tick the counter, dispatch the action, stop. */
    count_hit(r->rule_id, ctx->bytes);
    ctx->matched = 1;

    if (r->action == ACTION_RATE_LIMIT) {
        ctx->verdict = rate_check_v4(r->rule_id, ctx->src_addr,
                                     r->rate_pps, r->rate_burst);
        return 1;
    }
    if (r->action == ACTION_LOG) {
        emit_log(r->rule_id, r->action, 2 /*AF_INET*/, ctx->direction,
                 ctx->bytes, ctx->protocol, ctx->sport_net, ctx->dport_net,
                 ctx->src_addr, ctx->dst_addr, 4);
        ctx->verdict = XDP_PASS;
        return 1;
    }
    if (r->action == ACTION_DENY) {
        ctx->verdict = XDP_DROP;
        return 1;
    }
    /* ACTION_ALLOW */
    ctx->verdict = XDP_PASS;
    return 1;
}

static long
evaluate_rule_v6(__u32 idx, void *_ctx)
{
    struct match_ctx_v6 *ctx = _ctx;
    __u32 key = idx;
    struct rule_v6_record *r = bpf_map_lookup_elem(&rule_table_v6, &key);
    if (!r)
        return 1;
    if (!r->is_active)
        return 0;

    if (r->direction != DIR_BOTH && r->direction != ctx->direction)
        return 0;

    if (r->has_protocol && !protocol_matches(r->protocol, ctx->protocol))
        return 0;
    if (!r->has_protocol && r->protocol != PROTO_ANY &&
        !protocol_matches(r->protocol, ctx->protocol))
        return 0;

    if (r->has_src && !v6_in_cidr(ctx->src_addr, r->src_addr, r->src_prefix_len))
        return 0;
    if (r->has_dst && !v6_in_cidr(ctx->dst_addr, r->dst_addr, r->dst_prefix_len))
        return 0;

    if (!port_matches(ctx->sport_net, r->src_port_from, r->src_port_to))
        return 0;
    if (!port_matches(ctx->dport_net, r->dst_port_from, r->dst_port_to))
        return 0;

    count_hit(r->rule_id, ctx->bytes);
    ctx->matched = 1;

    if (r->action == ACTION_RATE_LIMIT) {
        ctx->verdict = rate_check_v6(r->rule_id, ctx->src_addr,
                                     r->rate_pps, r->rate_burst);
        return 1;
    }
    if (r->action == ACTION_LOG) {
        emit_log(r->rule_id, r->action, 10 /*AF_INET6*/, ctx->direction,
                 ctx->bytes, ctx->protocol, ctx->sport_net, ctx->dport_net,
                 ctx->src_addr, ctx->dst_addr, 16);
        ctx->verdict = XDP_PASS;
        return 1;
    }
    if (r->action == ACTION_DENY) {
        ctx->verdict = XDP_DROP;
        return 1;
    }
    ctx->verdict = XDP_PASS;
    return 1;
}

static __always_inline int
decide_v4(struct iphdr *iph, void *data_end, __u8 direction, __u32 bytes)
{
    __u32 ihl = iph->ihl & 0xF;
    if (ihl < 5)
        return XDP_PASS;
    void *l4 = (void *)iph + ihl * 4;

    __u16 sport = 0, dport = 0;
    read_l4_ports(l4, data_end, iph->protocol, &sport, &dport);

    __u32 zero = 0;
    __u32 *count_ptr = bpf_map_lookup_elem(&rule_count_v4, &zero);
    __u32 count = count_ptr ? *count_ptr : 0;
    if (count > MAX_ACTIVE_RULES_V4)
        count = MAX_ACTIVE_RULES_V4;
    if (count == 0)
        return XDP_PASS;

    struct match_ctx_v4 ctx = {
        .protocol  = iph->protocol,
        .direction = direction,
        .sport_net = sport,
        .dport_net = dport,
        .bytes     = bytes,
        .verdict   = XDP_PASS,
        .matched   = 0,
    };
    __builtin_memcpy(ctx.src_addr, &iph->saddr, 4);
    __builtin_memcpy(ctx.dst_addr, &iph->daddr, 4);

    bpf_loop(count, evaluate_rule_v4, &ctx, 0);
    return ctx.verdict;
}

static __always_inline int
decide_v6(struct ipv6hdr *ip6h, void *data_end, __u8 direction, __u32 bytes)
{
    /* No extension-header walk — nexthdr must be the L4 protocol. */
    void *l4 = (void *)(ip6h + 1);

    __u16 sport = 0, dport = 0;
    read_l4_ports(l4, data_end, ip6h->nexthdr, &sport, &dport);

    __u32 zero = 0;
    __u32 *count_ptr = bpf_map_lookup_elem(&rule_count_v6, &zero);
    __u32 count = count_ptr ? *count_ptr : 0;
    if (count > MAX_ACTIVE_RULES_V6)
        count = MAX_ACTIVE_RULES_V6;
    if (count == 0)
        return XDP_PASS;

    struct match_ctx_v6 ctx = {
        .protocol  = ip6h->nexthdr,
        .direction = direction,
        .sport_net = sport,
        .dport_net = dport,
        .bytes     = bytes,
        .verdict   = XDP_PASS,
        .matched   = 0,
    };
    __builtin_memcpy(ctx.src_addr, &ip6h->saddr, 16);
    __builtin_memcpy(ctx.dst_addr, &ip6h->daddr, 16);

    bpf_loop(count, evaluate_rule_v6, &ctx, 0);
    return ctx.verdict;
}

SEC("xdp")
int xdp_rules(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u32 bytes = (__u32)((long)data_end - (long)data);

    __u16 proto = bpf_ntohs(eth->h_proto);

    if (proto == ETH_P_IP) {
        struct iphdr *iph = (void *)(eth + 1);
        if ((void *)(iph + 1) > data_end)
            return XDP_PASS;
        return decide_v4(iph, data_end, 0 /*ingress*/, bytes);
    }

    if (proto == ETH_P_IPV6) {
        struct ipv6hdr *ip6h = (void *)(eth + 1);
        if ((void *)(ip6h + 1) > data_end)
            return XDP_PASS;
        return decide_v6(ip6h, data_end, 0 /*ingress*/, bytes);
    }

    return XDP_PASS;
}

static __always_inline int
xdp_to_tc(int verdict)
{
    return verdict == XDP_DROP ? TC_ACT_SHOT : TC_ACT_OK;
}

SEC("tc")
int tc_rules_wg0(struct __sk_buff *skb)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    __u32 bytes = skb->len;

    __u16 proto = bpf_ntohs(skb->protocol);

    if (proto == ETH_P_IP) {
        struct iphdr *iph = data;
        if ((void *)(iph + 1) > data_end)
            return TC_ACT_OK;
        return xdp_to_tc(decide_v4(iph, data_end, 0 /*ingress*/, bytes));
    }

    if (proto == ETH_P_IPV6) {
        struct ipv6hdr *ip6h = data;
        if ((void *)(ip6h + 1) > data_end)
            return TC_ACT_OK;
        return xdp_to_tc(decide_v6(ip6h, data_end, 0 /*ingress*/, bytes));
    }

    return TC_ACT_OK;
}
