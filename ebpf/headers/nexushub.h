/* SPDX-License-Identifier: GPL-2.0
 * Shared types between C (eBPF) and Go (userspace). Keep in lockstep
 * with ebpf/userspace/types.go — the bpf2go code-gen verifies the two
 * agree, but until that runs these are a manual contract.
 *
 * Layout is little-endian-sensitive. All packed fields, no padding
 * tricks: the Go side mirrors each struct with explicit _pad bytes.
 */
#pragma once

#include <linux/types.h>

/* enum rule_action — mirrors ebpf_rule_action in migration 003. */
enum rule_action {
    ACTION_ALLOW      = 0,
    ACTION_DENY       = 1,
    ACTION_RATE_LIMIT = 2,
    ACTION_LOG        = 3,
};

enum rule_protocol {
    PROTO_ANY  = 0,
    PROTO_TCP  = 1,
    PROTO_UDP  = 2,
    PROTO_ICMP = 3,
};

enum rule_direction {
    DIR_INGRESS = 0,
    DIR_EGRESS  = 1,
    DIR_BOTH    = 2,
};

/* LPM_TRIE keys. prefixlen is measured in BITS, not bytes — kernel
 * walks the trie bit-by-bit up to this depth. addr is network byte
 * order (big-endian) because that's the packet layout. */
struct lpm_v4_key {
    __u32 prefixlen;
    __u8  addr[4];
};

struct lpm_v6_key {
    __u32 prefixlen;
    __u8  addr[16];
};

/* rule_meta — one entry per active rule row. Sized to 32 bytes so the
 * hash table packs well and a lookup stays in one cacheline. */
struct rule_meta {
    __u8  action;
    __u8  protocol;
    __u8  direction;
    __u8  is_active;
    __u16 src_port_from;
    __u16 src_port_to;
    __u16 dst_port_from;
    __u16 dst_port_to;
    __u16 priority;
    __u16 _pad;
    __u32 rate_pps;
    __u32 rate_burst;
    __u32 _pad2;
};

/* rate_tokens — PERCPU_HASH value for rate_limit accounting.
 * tokens_x1000 is a fixed-point scalar (×1000) so sub-packet refill
 * fractions survive integer math. */
struct rate_tokens {
    __u64 tokens_x1000;
    __u64 last_seen_ns;
};

/* rate_key_v4 — PERCPU_HASH key for IPv4 rate buckets. Per-(rule,src)
 * granularity so one rate-limited source can't starve others
 * hitting the same rule. addr is network byte order, matching the
 * on-wire layout and what iphdr->saddr stores. */
struct rate_key_v4 {
    __u32 rule_id;
    __u32 addr;
};

/* log_event — ringbuf payload streamed to userspace for ACTION_LOG hits.
 * Ports/bytes/rule_id are host byte order (emitter ntohs'd ports); the
 * two address slots are network order with IPv4 occupying the first 4
 * bytes and remaining bytes zeroed. family disambiguates the two. */
struct log_event {
    __u64 ts_ns;
    __u32 rule_id;
    __u16 src_port;
    __u16 dst_port;
    __u32 bytes;
    __u8  action;
    __u8  protocol;   /* IPPROTO_* value from the packet, not PROTO_* */
    __u8  family;     /* AF_INET=2, AF_INET6=10 */
    __u8  direction;  /* 0=ingress, 1=egress */
    __u8  src_addr[16];
    __u8  dst_addr[16];
};

/* Upper bounds are compile-time constants; a deploy that outgrows them
 * rebuilds with new values. Unbounded maps are a DoS vector. */
#define MAX_RULES        10000
#define MAX_LPM_V4       10000
#define MAX_LPM_V6       10000
#define MAX_RATE_STATE   65536
#define LOG_RINGBUF_SIZE (1 << 20)
