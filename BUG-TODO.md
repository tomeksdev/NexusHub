# NexusHub Pre-Release Punch List — Round 9

Source: report after round 8 with extensive `bpftool` / `wg show`
evidence. The big-ticket complaint — eBPF rules show LOADED but
don't block traffic — is hard to fix blind. Maps and programs all
look right from this end. Round 9 prioritises **observability** so
the operator can diagnose on the bare-metal host, plus the live
peer status the user dashboard is missing.

## Reference files (local only, gitignored)

- `Claude - Project Plan.md`
- `example.html`
- `hexagon_logo.png`

---

## Pass N — round-9 fixes

### N1 — Drop the `Co-Authored-By` trailer from commits  📋user-feedback  ✅
The user explicitly wants commit attribution to show only
`tomeksdev`, no "and claude committed" hint on GitHub.

- [ ] Future commits in this repo end without the trailer.
- [ ] Memory note saved so this stays in effect across sessions.

### N2 — Clearer TC-attach logging  🟠high  ✅
The log line `tc_rules_wg0 attached iface=TestLocation` reads as if
the program name is hard-coded to wg0 even when the iface is
something else. That's just a misleading static log string —
replace with one that names the iface, hook, and the actual program
ID so the operator can sanity-check against `bpftool prog show`.

- [ ] `cmd/api/ebpf.go` — log the iface, the eBPF program
      file-descriptor ID, and the hook direction (ingress).
- [ ] Same on detach.

### N3 — Per-rule hit counters in the API + rules table  ⚡high  ✅
The kernel maintains `rule_hits` (packets + bytes per rule_id);
operators have no way to see it without ssh-ing in. Expose it on
the rules list response and render in the table. If a deny rule
shows 0 packets after the operator pinged through it, that's a
clear signal the program isn't seeing the traffic.

- [ ] `userspace.RulesLoader.PeekRuleHits(rid)` already exists.
      `ebpfkernel.KernelSyncer` resolves uuid→rid; expose
      `RuleHits(uuid) (packets, bytes, ok)`.
- [ ] `ebpf.Syncer` grows `Hits(uuid uuid.UUID) (uint64, uint64, bool)`.
      `NoopSyncer` returns `(0, 0, false)`.
- [ ] Rules list response gains `rule_hits_packets` / `rule_hits_bytes`.
- [ ] `RulesPage` adds a Hits column (`N pkts / M KiB`); zero
      means "rule loaded but nothing matched yet" — actionable.

### N4 — `/api/v1/diag/ebpf` for attached-program inventory  📋medium  ✅
`bpftool prog show` only an ssh away, but the Support page should
surface the same picture so the operator can confirm attachment
state from the browser. Lists every attached program with its
iface, hook, and the live `rule_hits` total across rules — a
zero global hit count tells the operator the data plane is silent.

- [ ] New `GET /api/v1/diag/ebpf` returning
      `{programs: [...], rule_hits_total: N}`.
- [ ] `ebpfStack` already tracks `tcLinks` by iface; surface that
      list through a small read interface.
- [ ] Support page renders a "eBPF programs" panel listing each
      attached iface + hook, with the total hits gauge.

### N5 — Live runtime stats on the user dashboard  📋medium  ✅
The `/me/peers` payload already carries `last_handshake`,
`rx_bytes`, `tx_bytes` — `MyConfigPage` just doesn't render them.
Add a clear "Connected / Not connected", a relative-time handshake
("42 seconds ago"), and the byte totals so a user opening their
own dashboard sees whether their tunnel is alive.

- [ ] Status pill based on `last_handshake` recency (<3 min = green
      "Connected", otherwise muted "Not connected").
- [ ] "Last handshake: 42 seconds ago" using `Intl.RelativeTimeFormat`.
- [ ] RX/TX totals shown in human units (existing `formatBytes`
      from PeersPage is the pattern).
- [ ] Auto-refresh every 10 s while the page is visible so the
      operator's WireGuard reconnect shows up without a manual reload.

---

## Out of scope (deferred to round 10+)

The report's biggest concern is **Part 2 — eBPF rules don't enforce**.
The evidence from `bpftool map dump` shows everything I'd expect to
see if enforcement were working. Without a TC counter increment or
a tcpdump on the bare-metal host showing whether packets even reach
the TC program, I can't fix this blind. N3 + N4 give the operator
the visibility to answer "are packets reaching the program?" from
the browser; once we know the answer, the real fix is small.

Also deferred:

- **Part 1 — peer config modal completeness**: the modal already
  shows the operator-supplied side; what's missing is a "server-
  side allowed_ips" line for symmetry. Adding it is straightforward
  but isn't a blocker for diagnosing the enforcement bug.
- **Part 3 — cross-interface route warnings**: bundled with the
  Part 1 redesign.
- **Part 2 fix proper**: depends on what N3+N4 reveal on the host.

## Acceptance — round-9 boxes

- [ ] (R9) Next commit author/committer reads only `tomeksdev`
- [ ] (R9) `journalctl -u nexushub-api` line on tc attach reads
      something like `tc_rules attached iface=TestLocation hook=ingress prog_id=42`
- [ ] (R9) Rules table renders a Hits column; ping the rule's
      src→dst path and refresh — packet count goes up if the
      program is matching
- [ ] (R9) `GET /api/v1/diag/ebpf` returns the attached programs
      list; Support page renders it
- [ ] (R9) User-role MyConfigPage shows "Connected/Not connected",
      relative-time handshake, byte totals; refreshes on its own
