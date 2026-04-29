# ADR 0004 — eBPF rule model & runtime map layout

- **Status:** Accepted
- **Date:** 2026-04-19
- **Deciders:** @tomeksdev

## Context

Phase 5 turns rows in `ebpf_rules` + `ebpf_rule_bindings` (migration
003) into live kernel behaviour. Two decisions need nailing down
before code lands:

1. **Where programs attach** — XDP on `eth0`, TC on `wg0`, or both.
2. **How DB rows become map entries** — so runtime updates are one
   map-write, never a program reload.

CLAUDE.md already commits to the first half: *"XDP does NOT work on
WireGuard interfaces (wg0 is L3, no link-layer headers). Use XDP on
eth0 (pre-tunnel) + TC on wg0 (post-decryption). This is
non-negotiable."* This ADR formalises the map layout that spans
both hooks.

## Decision

### Attach points

| Hook | Interface | Stage | Purpose |
|---|---|---|---|
| XDP | `eth0` (WAN) | pre-tunnel, pre-stack | Drop encrypted-layer attack traffic (blocklists, SYN floods) before it reaches WireGuard. Cheapest possible drop path. |
| TC clsact ingress | `wg0` | post-decryption | Apply per-peer L3/L4 rules using the peer's assigned IP as identity. This is the only place we can see cleartext tunnel traffic. |
| TC clsact egress | `wg0` | pre-encryption | Bandwidth accounting + outbound policy. |

XDP on `eth0` handles rules whose `src_cidr` is a public address;
TC on `wg0` handles rules whose src or dst is a peer's tunnel IP.
The rule's `direction` column picks the hook:

- `ingress` rule with public source → XDP (eth0)
- `ingress` rule with tunnel source → TC ingress (wg0)
- `egress`  rule → TC egress (wg0)
- `both`    rule → program-duplicated to both hooks

### Map layout

Four maps. All pinned at `/sys/fs/bpf/nexushub/<name>`. Sized for
10k rules total — adjust in code constants, not per-deploy tuning.

#### 1. `rule_meta` — HASH, `u32 rule_id → struct rule_meta`

One row per active rule. The LPM/port maps carry only enough
information to pick a rule; the action and counters live here.

```c
struct rule_meta {
    __u8  action;        // 0=allow 1=deny 2=rate_limit 3=log
    __u8  protocol;      // 0=any 1=tcp 2=udp 3=icmp
    __u8  direction;     // 0=ingress 1=egress 2=both
    __u8  _pad;
    __u16 src_port_from; // 0 when wildcard
    __u16 src_port_to;
    __u16 dst_port_from;
    __u16 dst_port_to;
    __u32 rate_pps;      // 0 unless action=rate_limit
    __u32 rate_burst;
    __u16 priority;
    __u8  is_active;
    __u8  _pad2;
};
```

#### 2. `rule_src_v4` — LPM_TRIE, `lpm_key → u32 rule_id`

Longest-prefix match on src CIDR → winning rule id. IPv6 uses a
parallel `rule_src_v6` map (same type, 128-bit key) because
LPM_TRIE keys are fixed-size.

`lpm_key` layout:

```c
struct lpm_v4_key {
    __u32 prefixlen;   // 0..32
    __u8  addr[4];     // network byte order
};
```

LPM_TRIE resolves to the most-specific match, so rule priority is
implicit in prefix length for overlapping CIDRs. Ties are broken by
the `priority` column in `rule_meta` (the BPF program fetches the
meta and compares).

#### 3. `rule_dst_v4` / `rule_dst_v6` — LPM_TRIE

Same shape as `rule_src_*`, keyed on dst address. A rule with both
src and dst CIDRs populates both maps; match requires both to hit.

#### 4. `rate_state` — PERCPU_HASH, `u32 (src_addr|rule_id composite) → struct rate_tokens`

Token-bucket accounting for `action=rate_limit`. Per-CPU to avoid
the global spinlock cost; a small overshoot is acceptable.

```c
struct rate_tokens {
    __u64 tokens_x1000;   // fixed-point; refill = rate_pps * elapsed_ns / 1e6
    __u64 last_seen_ns;
};
```

### Program flow (pseudocode)

```c
SEC("xdp") int xdp_gate(struct xdp_md *ctx) {
    parse_l3_l4();
    rid = lpm_lookup(&rule_src_v4, pkt.saddr);
    if (!rid) return XDP_PASS;
    meta = bpf_map_lookup_elem(&rule_meta, &rid);
    if (!meta || !meta->is_active) return XDP_PASS;
    if (!proto_matches(meta, pkt) || !ports_match(meta, pkt)) return XDP_PASS;

    switch (meta->action) {
    case ACTION_DENY:       return XDP_DROP;
    case ACTION_RATE_LIMIT: return rate_decide(rid, pkt.saddr, meta);
    case ACTION_LOG:        emit_ringbuf(rid, pkt); return XDP_PASS;
    case ACTION_ALLOW:      return XDP_PASS;
    }
}
```

Same structure in the TC programs; the difference is packet parsing
(no ethernet header on `wg0`) and the return verdict constant.

### Userspace sync loop

1. On API startup: `SELECT * FROM ebpf_rules WHERE is_active` →
   write `rule_meta`, populate LPM maps from CIDRs, zero
   `rate_state`.
2. On `ebpf_rules` INSERT/UPDATE/DELETE (triggered from the handler
   after the DB commit): write just the changed key. No program
   reload.
3. Reconciliation sweep every 60s — cheap sanity check that DB
   rows and map entries still match; logs drift rather than
   silently correcting it (for now).

The reconciliation + per-write update pair mirrors the WireGuard
reconciler (Phase 4). Same invariant: **DB is source of truth,
eBPF maps converge.**

### Binding semantics (peer vs. interface)

- `ebpf_rule_bindings.peer_id` set → the rule's src/dst CIDRs get
  augmented with the peer's assigned IP (as a /32 or /128) when
  written to the LPM map. This lets operators write a rule like
  "deny UDP/53 to 8.8.8.8" and bind it to a subset of peers
  without duplicating the rule row.
- `ebpf_rule_bindings.interface_id` set → the rule is installed
  only on the program instance attached to that interface. A
  second interface (e.g. `wg1` added later) gets its own map set.
- Unbound rules — no row in `ebpf_rule_bindings` — apply globally
  (every interface, every peer). Documented as the default for
  "network-wide blocklist" use cases.

## Consequences

- `backend/internal/ebpf/` gets a thin sync layer: `SyncRule(ctx,
  rule)`, `DeleteRule(ctx, ruleID)`, `List()`. Handlers call these
  after their DB write so API responses only succeed when both
  sides are consistent.
- Rule handlers (`POST /api/v1/rules`, `PUT`, `DELETE`, `POST
  /rules/:id/bindings`) can land independently of the kernel code
  — the sync layer is mockable via an interface so integration
  tests don't need a kernel runner.
- Map sizes are compile-time constants; a deploy that needs more
  than 10k rules bumps `MAX_RULES` and rebuilds. This is
  deliberate — unbounded maps are a DoS vector.
- `rate_state` is PERCPU, so reading it for metrics requires
  summing across CPUs. The Prometheus exporter handles that; the
  API does not expose raw per-CPU values.
- Ring-buffer log events (`action=log`) stream to a consumer
  goroutine that writes rows to `connection_logs`. This replaces
  the Phase-6 idea of polling — log is push-based from the kernel.
- Detection logic for kernels that can't run one of these map
  types is out of scope here and tracked under the Phase 5
  "fallback path if kernel lacks BTF" item.

## Rejected alternatives

- **One big map, all fields as key** — unworkable: keys must be
  fixed-size, and an any-CIDR/any-port key would need 40+ bytes
  per entry with most of it wildcards.
- **Cgroup skb attach instead of TC** — cgroup skb can't see
  tunnel decrypt output (runs before `wg0`'s rx path dumps into
  the host stack in a usable way), and attaching per-peer
  cgroups to a single process is awkward.
- **bpf_tail_call for per-action handlers** — premature; single
  programs with switch/case compile fine and are easier to reason
  about. Revisit if any single hook exceeds the verifier's
  instruction budget.
- **Separate program per rule** — BPF program slots are scarce
  and attach cost is non-trivial; the map-driven single-program
  model scales to thousands of rules on unchanged instruction
  count.
