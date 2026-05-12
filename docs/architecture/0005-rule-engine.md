# ADR 0005 — eBPF rule engine v2: per-packet iteration

- Status: proposed (round 10 plan; v2.1 ships the implementation)
- Date: 2026-05-12
- Supersedes the lookup-by-source-LPM behaviour established in ADR 0004
- Driven by bare-metal round-8/9/10 reports: deny rules visible as
  `LOADED` in the UI fail to enforce because two rules sharing a src
  CIDR collide on a single LPM trie slot

## Context

### What v2.0 ships today

ADR 0004 picked an LPM-trie-by-source matching architecture:

```
rule_src_v4 : LPM_TRIE<src_cidr → rule_id>
rule_dst_v4 : LPM_TRIE<dst_cidr → rule_id>   (gating in round 6)
rule_meta   : HASH<rule_id → struct rule_meta>
```

For each packet the kernel program looks up the source IP in
`rule_src_v4`, fetches one rule_id, evaluates that rule's metadata,
and dispatches the action. Round 6 added a destination LPM lookup
gated on `meta->has_dst` so dst-bearing rules stopped silently
degrading to src-only.

### The architectural limitation operators hit

The LPM tries' value is a single `u32 rule_id`. Two active rules
with the same src_cidr can only have one of them in the kernel —
the second `bpf_map_update_elem` overwrites the first. The UI
shows both as "Active: ON, Kernel: LOADED" because the metadata
hash holds them both, but only one wins the LPM slot. Which one
wins is whichever was last applied.

The user discovered this experimentally in round 10:

```
test 1 (one rule)               → ping passes, SSH blocked, hits=10
test 2 (two rules, same src)    → both pass
test 3 (priority swap)          → ping passes, SSH blocked again
test 4 (same priority)          → ping blocked, SSH passes
```

The matching behaviour swaps as the LPM's last-write-wins picks
different rules, confirming the overwrite.

A secondary issue: the rule semantics the UI promises (priority-
ordered evaluation of every matching rule) doesn't map onto a
one-rule-per-prefix lookup. Even when prefixes don't collide,
firewalls usually evaluate multiple rules per packet for the
allow-overrides-deny / deny-overrides-allow patterns.

### What round 10 ships instead of a fix

Round 10 surfaces the limitation rather than fixing it:

- `ruleResponse.shadowed_by_rule_name` flags lower-priority rules
  whose src_cidr is held by a higher-priority active rule
- Rules table renders a "shadowed by X" badge so operators can
  see which rule the kernel is actually enforcing

This is honest stopgap behaviour — the v2.0 engine genuinely can't
do better — and unblocks operators while v2.1 is being built.

## Decision

Replace the LPM-by-source architecture with **per-packet iteration
over a packed rule array**. The kernel program iterates a small
bounded list of active rules (priority-sorted) and applies the
first full match.

### Data structures

```
rule_table_v4 : BPF_MAP_TYPE_ARRAY
    key   : u32 slot     (0 .. MAX_ACTIVE_RULES_V4 - 1)
    value : struct rule_v4_record
rule_count_v4 : BPF_MAP_TYPE_ARRAY[1] of u32
    The number of populated slots in rule_table_v4 (always the
    leading prefix of the array; loader maintains compaction).

rule_table_v6 + rule_count_v6 : symmetric for IPv6
```

The record is wider than `rule_meta` because it carries the
src/dst CIDRs inline (no separate LPM map):

```c
struct rule_v4_record {
    u8  action;
    u8  protocol;
    u8  direction;
    u8  is_active;
    u8  has_src;
    u8  has_dst;
    u8  has_protocol;
    u8  _pad;
    u16 src_port_from;
    u16 src_port_to;
    u16 dst_port_from;
    u16 dst_port_to;
    u16 priority;
    u16 _pad2;
    u32 rate_pps;
    u32 rate_burst;
    u32 src_addr;          /* network byte order */
    u8  src_prefix_len;
    u8  _pad3[3];
    u32 dst_addr;
    u8  dst_prefix_len;
    u8  _pad4[3];
    u32 rule_id;           /* for rule_hits keying */
};
```

`MAX_ACTIVE_RULES_V4` = 256. A 256-entry table at ~56 B/record is
14 KiB per family — fine for a hot map. Operators with more rules
get a clear 400 from the API ("v2.1 supports up to 256 active
rules; disable some or wait for v2.2").

### Per-packet iteration

`decide_v4` becomes:

```c
static __always_inline int
decide_v4(struct iphdr *iph, void *data_end, u8 direction, u32 bytes)
{
    u32 zero = 0;
    u32 *count_ptr = bpf_map_lookup_elem(&rule_count_v4, &zero);
    u32 count = count_ptr ? *count_ptr : 0;
    if (count > MAX_ACTIVE_RULES_V4) count = MAX_ACTIVE_RULES_V4;

    struct match_ctx ctx = { .iph = iph, .data_end = data_end,
                             .direction = direction, .bytes = bytes };
    bpf_loop(count, evaluate_rule_v4, &ctx, 0);
    return ctx.verdict;
}
```

`evaluate_rule_v4` is the per-slot callback the verifier inspects
once. It returns 1 (stop) on the first full match or 0 (continue).
Loader-maintained priority order means "first match" === "highest
priority match".

### What changes in the loader (userspace)

`ebpf/userspace/rules.go` and `ebpfkernel/syncer.go` need a non-
trivial rework:

- `RuleMeta` retires as a separate struct; its fields move into
  `RuleV4Record` / `RuleV6Record`, plus inline addresses
- `KernelSyncer.ids` maps uuid → slot_id (0..N-1) instead of an
  opaque rule_id
- Apply: re-sort the active set by priority and rewrite the array
  positions. Worst case O(N) writes per Apply — fine at N=256
- Delete: same, with a shift-left compaction
- Reconcile: rebuild the entire packed list from scratch in one
  pass

### Tradeoffs

**For:**
- Multiple rules per src CIDR work correctly
- Multiple rules per dst CIDR work correctly
- Priority semantics match what the UI promises
- Per-rule hit counters reflect full matches (round-9 hits)
- The verifier handles `bpf_loop` natively on kernel 5.17+

**Against:**
- O(N) per packet vs O(log N) LPM. At 256 rules and a few hundred
  Mb/s of WG traffic, well under one core
- Min kernel rises to 5.17 (for `bpf_loop`). Acceptable — the
  current set of features already wants 5.11+ for ringbuf
- The 256-rule cap is real. Operators with bigger fleets either
  break it down or wait for v2.2 with a partitioned table

## Implementation plan (v2.1 round 11)

1. **C rewrite** in `ebpf/src/rules.c`:
   - Drop `rule_src_v4` / `rule_dst_v4` / `rule_meta`
   - Add `rule_table_v4` / `rule_count_v4` (+ v6 mirrors)
   - New `evaluate_rule_v4` callback + `bpf_loop` driver
   - Keep `rule_hits` (re-keyed on slot index)
   - Keep `log_events` ringbuf and the rate-state PERCPU maps
2. **Header sync** in `ebpf/headers/nexushub.h` for the new
   record struct
3. **Go mirror** in `ebpf/userspace/rules.go` — Marshal/Unmarshal
   for the new record
4. **Syncer rewrite** in `backend/internal/ebpfkernel/syncer.go`
   to maintain packed sorted arrays
5. **bpf2go regen** + commit the new `.o`s for amd64+arm64
6. **API surface stays stable**: `ruleResponse.kernel_loaded` and
   `rule_hits_packets/bytes` keep working. `shadowed_by_rule_name`
   becomes null for all rules under v2.1 (no shadow can happen)
7. **Migration plan for operators**: on first start with v2.1,
   remove the v2.0 pinned maps (`rm -rf /sys/fs/bpf/nexushub`) and
   let the new program create the v2.1 layout. The DB doesn't
   change

## Test plan

- Unit: `RuleV4Record` Marshal/Unmarshal round-trip
- Userspace: build a fake spec with 4 rules sharing a src CIDR;
  assert all four are programmed and reachable via the iteration
- Kernel-gated: real-kernel test that two rules with the same
  src_cidr but different `dst_cidr` both block their respective
  destinations
- Bare-metal: the round-8 SSH + ping scenarios from the test
  report — both must behave as the UI shows
