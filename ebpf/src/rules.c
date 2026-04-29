/* SPDX-License-Identifier: GPL-2.0
 * rules.c — full-gate rule enforcement, two programs sharing one map set.
 *
 *   SEC("xdp") xdp_rules          → attached to eth0 (pre-tunnel, WAN).
 *                                    Sees Ethernet-framed packets.
 *   SEC("tc")  tc_rules_wg0       → attached to wg0 clsact ingress
 *                                    (post-decryption). wg0 is a pure
 *                                    L3 device (ARPHRD_NONE); skb->data
 *                                    already points at the iphdr.
 *
 * Both programs feed the same decide_v4/decide_v6 pipeline:
 *   1. LPM lookup on src address in rule_src_v4/v6 → rule_id
 *   2. Hash lookup on rule_id in rule_meta → action + filters
 *   3. Protocol check
 *   4. TCP/UDP src+dst port range check (0/0 = wildcard)
 *   5. Dispatch on action:
 *        DENY        → drop
 *        RATE_LIMIT  → per-(rule, src) token bucket (IPv4); drop when empty
 *        LOG         → emit log_event to ring buffer, then pass
 *        ALLOW       → pass
 *
 * Verdicts flow as XDP codes throughout; the TC wrapper translates
 * XDP_DROP → TC_ACT_SHOT and everything else → TC_ACT_OK at the top.
 * Keeping the internal verdict representation uniform means decide_*
 * and rate_check_v4 need no per-hook branching.
 *
 * Map layout matches ADR 0004. Rate-limit state is split per family
 * (rate_state_v4 + rate_state_v6) because PERCPU_HASH keys are
 * fixed-size and we don't want to waste 12 bytes per v4 bucket just
 * to share a map with v6.
 *
 * IPv4 and IPv6 live in separate LPM maps because trie keys must be
 * fixed-size. A single packet checks the family that matches its
 * ethtype/skb->protocol and returns.
 *
 * This program does NOT consult rule_dst_* yet — that needs an
 * L4-aware AND across both maps to be meaningful. src-only matches the
 * blocklist use case that covers >90% of expected rules.
 *
 * IPv6 extension headers are NOT walked: nexthdr is assumed to be the
 * L4 protocol directly. Rules that need to match through HBH/Routing/
 * Fragment headers will miss in the meantime — documented limitation,
 * worth revisiting once we have production traffic samples.
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

/* HASH rule_id → struct rule_meta. One entry per active rule row. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct rule_meta);
    __uint(max_entries, MAX_RULES);
} rule_meta SEC(".maps");

/* LPM_TRIE src_cidr → rule_id. One map per address family. */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_v4_key);
    __type(value, __u32);
    __uint(max_entries, MAX_LPM_V4);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} rule_src_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_v6_key);
    __type(value, __u32);
    __uint(max_entries, MAX_LPM_V6);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} rule_src_v6 SEC(".maps");

/* Dst maps are declared so the userspace loader can write to them and
 * the program can be extended in place once dst-based matching lands.
 * They're unused by the current decide_* path. */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_v4_key);
    __type(value, __u32);
    __uint(max_entries, MAX_LPM_V4);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} rule_dst_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_v6_key);
    __type(value, __u32);
    __uint(max_entries, MAX_LPM_V6);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} rule_dst_v6 SEC(".maps");

/* PERCPU_HASH (rule_id, src_addr) → rate_tokens. Per-CPU to avoid
 * the global spinlock cost; the small overshoot from racing CPUs is
 * acceptable for rate-limiting semantics (documented in ADR 0004). */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, struct rate_key_v4);
    __type(value, struct rate_tokens);
    __uint(max_entries, MAX_RATE_STATE);
} rate_state_v4 SEC(".maps");

/* v6 rate state. Same semantics as v4 with a wider key. We size both
 * maps to MAX_RATE_STATE independently — a deploy that rate-limits
 * mostly v4 traffic doesn't waste headroom on the v6 map. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, struct rate_key_v6);
    __type(value, struct rate_tokens);
    __uint(max_entries, MAX_RATE_STATE);
} rate_state_v6 SEC(".maps");

/* PERCPU_HASH rule_id → struct rule_hits. Lossless counter ticked
 * on every matched rule regardless of action — the ringbuf can drop
 * under load and only fires for ACTION_LOG, whereas this map
 * captures ALLOW/DENY/RATE_LIMIT matches too. Operators read it via
 * bpf map dump or the userspace loader's PeekRuleHits. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, __u32);
    __type(value, struct rule_hits);
    __uint(max_entries, MAX_RULES);
} rule_hits SEC(".maps");

/* RINGBUF for ACTION_LOG telemetry. Userspace drains it into
 * connection_logs. Size is a power of two per ringbuf ABI; 1 MiB gives
 * ~18k events (56 B each) of headroom before drop, which covers a
 * consumer stall of tens of milliseconds at realistic log-rule rates.
 * The kernel-side drop on full is acceptable: logging is best-effort
 * and we'd rather lose events than stall the datapath. */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, LOG_RINGBUF_SIZE);
} log_events SEC(".maps");

/* count_hit ticks the per-rule counter. Called once per matched
 * rule, before action dispatch, so every match is recorded even
 * when the action subsequently drops the packet. First touch
 * creates the entry with {1, bytes}; subsequent touches accumulate.
 * Failure to update (map full at MAX_RULES) is silently ignored —
 * the counter is operational telemetry, not a policy input, and
 * losing counts beats stalling the datapath. */
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

/* emit_log reserves a ringbuf slot and fills a log_event from the match
 * context. ports/bytes are in host order; src/dst are raw on-wire bytes
 * (network order for IPv4 in the first 4 bytes, zero-padded). Best
 * effort — if the ringbuf is full or reserve fails we silently drop the
 * event rather than stalling the datapath. */
static __always_inline void
emit_log(__u32 rule_id, struct rule_meta *meta, __u8 family, __u8 direction,
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
    ev->action    = meta->action;
    ev->protocol  = l4_proto;
    ev->family    = family;
    ev->direction = direction;

    /* Zero both address slots first so the unused tail of an IPv4 event
     * doesn't leak stack garbage to userspace. */
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

/* token_bucket_step runs the shared refill + consume math on an
 * already-looked-up bucket. Split out from rate_check_* so v4 and v6
 * share the arithmetic; the map-specific lookup/update stays inlined
 * in each caller to keep the verifier's pointer-provenance check
 * happy. */
static __always_inline int
token_bucket_step(struct rate_tokens *t, __u32 pps, __u64 cap_x1000, __u64 now)
{
    /* Refill. Cap elapsed at 1s before multiplying so (pps × elapsed)
     * stays under u64 range even at pathological pps values. An older
     * bucket would hit cap_x1000 anyway after the clamp below. */
    __u64 elapsed = now - t->last_seen_ns;
    if (elapsed > 1000000000ULL)
        elapsed = 1000000000ULL;

    __u64 refill_x1000 = ((__u64)pps * elapsed) / 1000000ULL;
    __u64 new_tokens = t->tokens_x1000 + refill_x1000;
    if (new_tokens > cap_x1000)
        new_tokens = cap_x1000;

    t->last_seen_ns = now;

    if (new_tokens < 1000) {
        /* Not enough tokens to pass a whole packet — drop and keep the
         * (possibly slightly refilled) balance for next time. */
        t->tokens_x1000 = new_tokens;
        return XDP_DROP;
    }
    t->tokens_x1000 = new_tokens - 1000;
    return XDP_PASS;
}

/* rate_check_v4 implements a token-bucket per (rule_id, src_addr).
 * Capacity = rate_burst tokens (or rate_pps if burst is unset);
 * refill rate = rate_pps tokens per second. A packet consumes 1
 * token; when the bucket is empty the packet is dropped.
 *
 * tokens_x1000 is scaled ×1000 so refill keeps sub-packet precision
 * across short inter-arrival times. One packet = 1000 units consumed.
 *
 * Fail-open on bucket allocation failure (map is full): the DoS risk
 * of letting a single flow through beats silently dropping legitimate
 * traffic when the operator didn't size the map right. */
static __always_inline int
rate_check_v4(__u32 rule_id, __u32 src_addr, struct rule_meta *meta)
{
    __u32 pps = meta->rate_pps;
    if (pps == 0)
        return XDP_PASS; /* malformed rule — no throttle configured */

    __u32 burst = meta->rate_burst ? meta->rate_burst : pps;
    __u64 cap_x1000 = (__u64)burst * 1000ULL;

    struct rate_key_v4 k = { .rule_id = rule_id, .addr = src_addr };
    __u64 now = bpf_ktime_get_ns();

    struct rate_tokens *t = bpf_map_lookup_elem(&rate_state_v4, &k);
    if (!t) {
        struct rate_tokens fresh = {
            .tokens_x1000 = cap_x1000,
            .last_seen_ns = now,
        };
        if (bpf_map_update_elem(&rate_state_v4, &k, &fresh, BPF_ANY) != 0)
            return XDP_PASS; /* map full: fail open */
        t = bpf_map_lookup_elem(&rate_state_v4, &k);
        if (!t)
            return XDP_PASS;
    }
    return token_bucket_step(t, pps, cap_x1000, now);
}

/* rate_check_v6 mirrors rate_check_v4 against rate_state_v6. The key
 * is wider (16-byte address) but the map contract and fail-open
 * semantics on map-full are identical. */
static __always_inline int
rate_check_v6(__u32 rule_id, const __u8 src_addr[16], struct rule_meta *meta)
{
    __u32 pps = meta->rate_pps;
    if (pps == 0)
        return XDP_PASS;

    __u32 burst = meta->rate_burst ? meta->rate_burst : pps;
    __u64 cap_x1000 = (__u64)burst * 1000ULL;

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

/* port_matches returns 1 if the observed port falls inside [from, to]
 * or if both bounds are 0 (wildcard). Ports on the wire are network
 * order; rule_meta stores them in host order. */
static __always_inline int
port_matches(__u16 port_net, __u16 from_host, __u16 to_host)
{
    if (from_host == 0 && to_host == 0)
        return 1;
    __u16 port_host = bpf_ntohs(port_net);
    return port_host >= from_host && port_host <= to_host;
}

static __always_inline int
ports_match(struct rule_meta *meta, __u16 sport_net, __u16 dport_net)
{
    if (!port_matches(sport_net, meta->src_port_from, meta->src_port_to))
        return 0;
    if (!port_matches(dport_net, meta->dst_port_from, meta->dst_port_to))
        return 0;
    return 1;
}

/* read_l4_ports pulls src/dst ports from TCP or UDP headers. Returns 1
 * on success and fills the sport and dport pointers (network order). Returns 0 if
 * there's no usable L4 header — caller treats sport=dport=0, which
 * means port-restricted rules won't match (correct) but wildcard
 * rules still match (also correct).
 *
 * Both TCP and UDP lead with src(2) + dst(2); reading four bytes is
 * enough regardless. */
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

static __always_inline int
decide_v4(struct iphdr *iph, void *data_end, __u8 direction, __u32 bytes)
{
    struct lpm_v4_key key = { .prefixlen = 32 };
    __builtin_memcpy(key.addr, &iph->saddr, 4);

    __u32 *rid = bpf_map_lookup_elem(&rule_src_v4, &key);
    if (!rid)
        return XDP_PASS;

    struct rule_meta *meta = bpf_map_lookup_elem(&rule_meta, rid);
    if (!meta || !meta->is_active)
        return XDP_PASS;

    /* Honour the rule's configured direction. DIR_BOTH matches every
     * hook; otherwise the rule's direction must equal the caller's.
     * Both hook entry points currently pass direction=0 (INGRESS)
     * because XDP is pre-routing ingress and our TC hook is clsact
     * ingress — rules created with direction=egress are no-ops until
     * an egress hook is added. */
    if (meta->direction != DIR_BOTH && meta->direction != direction)
        return XDP_PASS;

    if (!protocol_matches(meta->protocol, iph->protocol))
        return XDP_PASS;

    /* ihl is a 4-bit bitfield; mask keeps the verifier happy and
     * guards against compiler-level reinterpretation. Values <5 are
     * malformed (header shorter than 20 bytes) — skip. */
    __u32 ihl = iph->ihl & 0xF;
    if (ihl < 5)
        return XDP_PASS;
    void *l4 = (void *)iph + ihl * 4;

    __u16 sport = 0, dport = 0;
    read_l4_ports(l4, data_end, iph->protocol, &sport, &dport);
    if (!ports_match(meta, sport, dport))
        return XDP_PASS;

    count_hit(*rid, bytes);

    if (meta->action == ACTION_RATE_LIMIT)
        return rate_check_v4(*rid, iph->saddr, meta);

    if (meta->action == ACTION_LOG) {
        emit_log(*rid, meta, 2 /*AF_INET*/, direction, bytes, iph->protocol,
                 sport, dport, &iph->saddr, &iph->daddr, 4);
        return XDP_PASS;
    }

    if (meta->action == ACTION_DENY)
        return XDP_DROP;

    return XDP_PASS;
}

static __always_inline int
decide_v6(struct ipv6hdr *ip6h, void *data_end, __u8 direction, __u32 bytes)
{
    struct lpm_v6_key key = { .prefixlen = 128 };
    __builtin_memcpy(key.addr, &ip6h->saddr, 16);

    __u32 *rid = bpf_map_lookup_elem(&rule_src_v6, &key);
    if (!rid)
        return XDP_PASS;

    struct rule_meta *meta = bpf_map_lookup_elem(&rule_meta, rid);
    if (!meta || !meta->is_active)
        return XDP_PASS;

    /* Honour the rule's configured direction — same rationale as the
     * v4 path above. */
    if (meta->direction != DIR_BOTH && meta->direction != direction)
        return XDP_PASS;

    if (!protocol_matches(meta->protocol, ip6h->nexthdr))
        return XDP_PASS;

    /* No extension-header walk — nexthdr must be the L4 protocol. */
    void *l4 = (void *)(ip6h + 1);

    __u16 sport = 0, dport = 0;
    read_l4_ports(l4, data_end, ip6h->nexthdr, &sport, &dport);
    if (!ports_match(meta, sport, dport))
        return XDP_PASS;

    count_hit(*rid, bytes);

    if (meta->action == ACTION_RATE_LIMIT)
        return rate_check_v6(*rid, (const __u8 *)&ip6h->saddr, meta);

    if (meta->action == ACTION_LOG) {
        emit_log(*rid, meta, 10 /*AF_INET6*/, direction, bytes, ip6h->nexthdr,
                 sport, dport, &ip6h->saddr, &ip6h->daddr, 16);
        return XDP_PASS;
    }

    if (meta->action == ACTION_DENY)
        return XDP_DROP;

    return XDP_PASS;
}

SEC("xdp")
int xdp_rules(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* Byte count is the full L2 frame size. Cast through long so the
     * verifier sees a scalar subtraction rather than two packet ptrs. */
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

/* xdp_to_tc maps our internal XDP verdicts onto TC action codes so the
 * shared decide_* helpers can stay hook-agnostic. XDP_DROP is the only
 * "stop" verdict decide_* ever emits; everything else means "let it
 * through". TC_ACT_OK tells the kernel to keep processing the packet
 * along the normal ingress path (policy routing, iptables, sockets). */
static __always_inline int
xdp_to_tc(int verdict)
{
    return verdict == XDP_DROP ? TC_ACT_SHOT : TC_ACT_OK;
}

/* tc_rules_wg0 — TC clsact ingress program for the WireGuard tunnel.
 *
 * wg0 is registered as ARPHRD_NONE: the kernel delivers skbs with
 * skb->mac_len == 0 and skb->data already positioned at the L3 header.
 * There is no Ethernet frame to skip past.
 *
 * skb->protocol holds the L3 ethertype in network byte order, the same
 * value the WAN-side ethhdr would carry. bpf_ntohs it once and dispatch
 * identically to the XDP path.
 *
 * On any parse/bounds failure we fail open (TC_ACT_OK) — the WAN-side
 * XDP gate has already screened public-internet sources, and dropping
 * decrypted-but-unparseable inner traffic would blackhole peers. */
SEC("tc")
int tc_rules_wg0(struct __sk_buff *skb)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    /* skb->len is the total L3 length the kernel sees; data_end-data may
     * exclude non-linear skb fragments. Both are fine for log reporting;
     * prefer skb->len so truncated telemetry matches traffic counters. */
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
