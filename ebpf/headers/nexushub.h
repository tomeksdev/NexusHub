/* SPDX-License-Identifier: GPL-2.0
 * Shared types between C (eBPF) and Go (userspace). Keep in lockstep
 * with ebpf/userspace/rules.go — the bpf2go code-gen verifies the two
 * agree, but until that runs these are a manual contract.
 *
 * Layout is little-endian-sensitive. All packed fields, no padding
 * tricks: the Go side mirrors each struct with explicit _pad bytes.
 *
 * v2.1 — per-packet iteration. ADR 0005 replaces the LPM-by-source
 * matching of v2.0 with a packed array of full rule records and a
 * bpf_loop driver. struct rule_meta + the four LPM tries are gone;
 * rule_table_v4 / rule_table_v6 now carry every active rule with its
 * src/dst CIDR inlined, so two rules sharing a src can both enforce.
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

/* rule_v4_record — one slot in the per-packet iteration array. The
 * record carries everything the kernel needs to match a packet AND to
 * dispatch the action, so we never have to chase a second map lookup.
 *
 * Address bytes are stored raw on-wire (network byte order, big-endian
 * regardless of host) to match iphdr->saddr/daddr. prefix_len is in
 * bits (0..32).
 *
 * Total size: 44 bytes. Naturally 4-byte-aligned; no compiler padding.
 */
struct rule_v4_record {
    __u8  action;          /* offset 0  : ACTION_* */
    __u8  protocol;        /* offset 1  : PROTO_*  */
    __u8  direction;       /* offset 2  : DIR_*    */
    __u8  is_active;       /* offset 3  : 0/1      */
    __u8  has_src;         /* offset 4  : 1 → gate on src_addr/src_prefix_len */
    __u8  has_dst;         /* offset 5  : 1 → gate on dst_addr/dst_prefix_len */
    __u8  has_protocol;    /* offset 6  : 1 → protocol != PROTO_ANY */
    __u8  src_prefix_len;  /* offset 7  : 0..32 (bits) */
    __u8  dst_prefix_len;  /* offset 8  : 0..32 (bits) */
    __u8  _pad[3];         /* offset 9..11 : align next u32 */
    __u32 rate_pps;        /* offset 12 */
    __u32 rate_burst;      /* offset 16 */
    __u16 src_port_from;   /* offset 20 */
    __u16 src_port_to;     /* offset 22 */
    __u16 dst_port_from;   /* offset 24 */
    __u16 dst_port_to;     /* offset 26 */
    __u16 priority;        /* offset 28 */
    __u16 _pad2;           /* offset 30 */
    __u8  src_addr[4];     /* offset 32 : on-wire (network) byte order */
    __u8  dst_addr[4];     /* offset 36 : on-wire (network) byte order */
    __u32 rule_id;         /* offset 40 : stable id for rule_hits keying */
};

/* rule_v6_record — IPv6 mirror. Same layout up to the address fields,
 * then 16-byte src/dst inline. Total size: 68 bytes. */
struct rule_v6_record {
    __u8  action;
    __u8  protocol;
    __u8  direction;
    __u8  is_active;
    __u8  has_src;
    __u8  has_dst;
    __u8  has_protocol;
    __u8  src_prefix_len;  /* 0..128 */
    __u8  dst_prefix_len;  /* 0..128 */
    __u8  _pad[3];
    __u32 rate_pps;
    __u32 rate_burst;
    __u16 src_port_from;
    __u16 src_port_to;
    __u16 dst_port_from;
    __u16 dst_port_to;
    __u16 priority;
    __u16 _pad2;
    __u8  src_addr[16];
    __u8  dst_addr[16];
    __u32 rule_id;
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

/* rate_key_v6 — v4's counterpart for IPv6 buckets. Same per-(rule,src)
 * granularity. addr holds ip6hdr->saddr bytes verbatim (network order).
 * Total size is 20 bytes; the trailing pad keeps the struct aligned to
 * 4 bytes, which is all the kernel map ABI requires for key layouts. */
struct rate_key_v6 {
    __u32 rule_id;
    __u8  addr[16];
};

/* rule_hits — PERCPU_HASH value for per-rule lossless hit counters.
 * Ticked on every matched rule regardless of action (ALLOW/DENY/
 * RATE_LIMIT/LOG), so operators can answer "how many packets did
 * rule X see this hour" without depending on ringbuf drain cadence
 * or the rule being configured for logging. */
struct rule_hits {
    __u64 packets;
    __u64 bytes;
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

/* Upper bounds are compile-time constants. The v2.1 engine iterates
 * every active rule per packet, so MAX_ACTIVE_RULES_* is a real cap
 * the loader enforces (the syncer rejects an Apply that would push
 * the table over 256). Operators with bigger fleets break the rule
 * set down or wait for the v2.2 partitioned design. */
#define MAX_ACTIVE_RULES_V4  256
#define MAX_ACTIVE_RULES_V6  256
#define MAX_RULES            (MAX_ACTIVE_RULES_V4 + MAX_ACTIVE_RULES_V6)
#define MAX_RATE_STATE       65536
#define LOG_RINGBUF_SIZE     (1 << 20)
