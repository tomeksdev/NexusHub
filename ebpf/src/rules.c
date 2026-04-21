/* SPDX-License-Identifier: GPL-2.0
 * rules.c — XDP full-gate program for pre-tunnel rule enforcement.
 *
 * Attached to eth0 (the WAN interface). For each incoming packet:
 *   1. LPM lookup on src address in rule_src_v4/v6 → rule_id
 *   2. Hash lookup on rule_id in rule_meta → action + filters
 *   3. Protocol check
 *   4. TCP/UDP src+dst port range check (0/0 = wildcard)
 *   5. Dispatch on action:
 *        DENY        → XDP_DROP
 *        RATE_LIMIT  → per-(rule, src) token bucket (IPv4); drop when empty
 *        ALLOW/LOG   → XDP_PASS (LOG ringbuf lands in a later commit)
 *
 * Map layout matches ADR 0004. IPv6 rate-limiting is intentionally
 * deferred: the rate_state_v4 PERCPU_HASH is v4-only for now, and
 * RATE_LIMIT rules matched on the v6 path fall through to XDP_PASS.
 *
 * IPv4 and IPv6 live in separate LPM maps because trie keys must be
 * fixed-size. A single packet checks the family that matches its
 * ethtype and returns.
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

static __always_inline int
apply_action(struct rule_meta *meta)
{
    /* DENY drops. ALLOW is a positive assertion that the packet should
     * continue; LOG falls through to PASS until ringbuf emission lands.
     * RATE_LIMIT is handled by the caller before reaching here, because
     * it needs the src addr + rule_id for bucket keying. */
    if (meta->action == ACTION_DENY)
        return XDP_DROP;
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
 * on success and fills *sport/*dport in network order. Returns 0 if
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
decide_v4(struct iphdr *iph, void *data_end)
{
    struct lpm_v4_key key = { .prefixlen = 32 };
    __builtin_memcpy(key.addr, &iph->saddr, 4);

    __u32 *rid = bpf_map_lookup_elem(&rule_src_v4, &key);
    if (!rid)
        return XDP_PASS;

    struct rule_meta *meta = bpf_map_lookup_elem(&rule_meta, rid);
    if (!meta || !meta->is_active)
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

    if (meta->action == ACTION_RATE_LIMIT)
        return rate_check_v4(*rid, iph->saddr, meta);

    return apply_action(meta);
}

static __always_inline int
decide_v6(struct ipv6hdr *ip6h, void *data_end)
{
    struct lpm_v6_key key = { .prefixlen = 128 };
    __builtin_memcpy(key.addr, &ip6h->saddr, 16);

    __u32 *rid = bpf_map_lookup_elem(&rule_src_v6, &key);
    if (!rid)
        return XDP_PASS;

    struct rule_meta *meta = bpf_map_lookup_elem(&rule_meta, rid);
    if (!meta || !meta->is_active)
        return XDP_PASS;

    if (!protocol_matches(meta->protocol, ip6h->nexthdr))
        return XDP_PASS;

    /* No extension-header walk — nexthdr must be the L4 protocol. */
    void *l4 = (void *)(ip6h + 1);

    __u16 sport = 0, dport = 0;
    read_l4_ports(l4, data_end, ip6h->nexthdr, &sport, &dport);
    if (!ports_match(meta, sport, dport))
        return XDP_PASS;

    return apply_action(meta);
}

SEC("xdp")
int xdp_rules(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 proto = bpf_ntohs(eth->h_proto);

    if (proto == ETH_P_IP) {
        struct iphdr *iph = (void *)(eth + 1);
        if ((void *)(iph + 1) > data_end)
            return XDP_PASS;
        return decide_v4(iph, data_end);
    }

    if (proto == ETH_P_IPV6) {
        struct ipv6hdr *ip6h = (void *)(eth + 1);
        if ((void *)(ip6h + 1) > data_end)
            return XDP_PASS;
        return decide_v6(ip6h, data_end);
    }

    return XDP_PASS;
}
