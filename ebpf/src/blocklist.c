/* SPDX-License-Identifier: GPL-2.0
 * blocklist.c — XDP program for pre-tunnel IP drop.
 *
 * Attached to eth0 (the WAN interface). Every incoming packet's source
 * address is looked up in an LPM_TRIE; a hit means "this src is in the
 * blocklist, drop immediately". Programs later in Phase 5 layer port
 * and protocol filters on top of this; blocklist is the cheapest drop.
 *
 * IPv4 and IPv6 live in separate maps because LPM_TRIE keys must be
 * fixed-size. A single packet checks the map that matches its ethtype.
 *
 * This program does NOT touch rule_meta or rate_state — it's the
 * minimum viable hook. The "full" XDP gate (protocol/port matching,
 * rate limiting, ring-buffer logging) is a follow-up.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

#include "../headers/bpf_helpers.h"
#include "../headers/nexushub.h"

char LICENSE[] SEC("license") = "GPL";

/* Blocklist maps. A hit — regardless of the value — drops the packet.
 * The value field is a u32 rule_id for future use (lets us attribute
 * the drop to a specific rule row for auditing). */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_v4_key);
    __type(value, __u32);
    __uint(max_entries, MAX_LPM_V4);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} blocklist_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_v6_key);
    __type(value, __u32);
    __uint(max_entries, MAX_LPM_V6);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} blocklist_v6 SEC(".maps");

static __always_inline int
check_v4(void *data, void *data_end)
{
    struct iphdr *iph = data + sizeof(struct ethhdr);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS; /* malformed; let the stack handle it */

    struct lpm_v4_key key = {
        .prefixlen = 32,
    };
    __builtin_memcpy(key.addr, &iph->saddr, 4);

    if (bpf_map_lookup_elem(&blocklist_v4, &key))
        return XDP_DROP;
    return XDP_PASS;
}

static __always_inline int
check_v6(void *data, void *data_end)
{
    struct ipv6hdr *ip6h = data + sizeof(struct ethhdr);
    if ((void *)(ip6h + 1) > data_end)
        return XDP_PASS;

    struct lpm_v6_key key = {
        .prefixlen = 128,
    };
    __builtin_memcpy(key.addr, &ip6h->saddr, 16);

    if (bpf_map_lookup_elem(&blocklist_v6, &key))
        return XDP_DROP;
    return XDP_PASS;
}

SEC("xdp")
int xdp_blocklist(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 proto = bpf_ntohs(eth->h_proto);
    if (proto == ETH_P_IP)
        return check_v4(data, data_end);
    if (proto == ETH_P_IPV6)
        return check_v6(data, data_end);

    return XDP_PASS;
}
