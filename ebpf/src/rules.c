/* SPDX-License-Identifier: GPL-2.0
 * rules.c — XDP full-gate program for pre-tunnel rule enforcement.
 *
 * Attached to eth0 (the WAN interface). For each incoming packet:
 *   1. LPM lookup on src address in rule_src_v4/v6 → rule_id
 *   2. Hash lookup on rule_id in rule_meta → action + filters
 *   3. Protocol check
 *   4. Switch on action (DENY → XDP_DROP, everything else → XDP_PASS)
 *
 * Map layout matches ADR 0004. Ports and rate_limit are stubbed: the
 * switch passes through ALLOW/LOG/RATE_LIMIT to XDP_PASS for now, so
 * only DENY rules actually drop. Port matching + L4 parsing + the
 * rate_state PERCPU_HASH follow in a later commit — keeping this
 * program small helps the verifier converge quickly.
 *
 * IPv4 and IPv6 live in separate LPM maps because trie keys must be
 * fixed-size. A single packet checks the family that matches its
 * ethtype and returns.
 *
 * This program does NOT consult rule_dst_* yet — that needs an
 * L4-aware AND across both maps to be meaningful. src-only matches the
 * blocklist use case that covers >90% of expected rules.
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
 * the program can be extended in place once L4 parsing lands. They're
 * unused by the current decide_* path. */
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
    /* Only DENY actually drops for now. ALLOW is a positive assertion
     * that the packet should continue; LOG and RATE_LIMIT fall through
     * until ringbuf + PERCPU_HASH machinery lands. */
    if (meta->action == ACTION_DENY)
        return XDP_DROP;
    return XDP_PASS;
}

static __always_inline int
decide_v4(struct iphdr *iph)
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

    return apply_action(meta);
}

static __always_inline int
decide_v6(struct ipv6hdr *ip6h)
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
        return decide_v4(iph);
    }

    if (proto == ETH_P_IPV6) {
        struct ipv6hdr *ip6h = (void *)(eth + 1);
        if ((void *)(ip6h + 1) > data_end)
            return XDP_PASS;
        return decide_v6(ip6h);
    }

    return XDP_PASS;
}
