# NexusHub Pre-Release Punch List — Round 10

Source: combined report after round 9 with detailed `wg show` and
`bpftool` evidence. Two distinct themes:

1. **eBPF rule engine** — the LPM-trie matching architecture only
   supports one rule per source CIDR. The user's tests confirm this
   experimentally: adding a second rule with the same src silently
   replaces the first.
2. **Peer .conf / wg show / UI consistency** — three views of the
   peer's networks can disagree because the design intentionally
   separates server-side `allowed_ips` (what the WG kernel module
   accepts) from `client_allowed_ips` (what gets written into the
   exported `.conf`). The operator wants them either unified or
   clearly explained.

## Honest scope for this round

The headline eBPF rewrite (iterate all active rules per packet
instead of LPM-by-source) is **at least a session's worth on its
own** — it touches the C program, the bpf2go bindings, the syncer's
rule-id allocator, and needs verifier-safe iteration via `bpf_loop`.
I'd rather not ship a half-finished kernel program. **Round 10
ships the observability + UX bits; the engine rewrite lands in
round 11 as a coherent piece with its own ADR.**

What ships now:

- A clear API + UI warning when two rules conflict on the same src
  CIDR (so the operator at least knows which rule the kernel is
  actually enforcing).
- UX clarity on the two AllowedIPs fields, plus a one-click "use
  the same routes on the client" helper.
- Forced query invalidation on peer save so the Config modal never
  serves a stale `.conf` after the operator edits a peer.
- An ADR enumerating the round-11 engine rewrite plan.

## Reference files (local only, gitignored)

- `Claude - Project Plan.md`
- `example.html`
- `hexagon_logo.png`

---

## Pass O — round-10 fixes

### O1 — Surface "rule shadows another rule" in the API + table  ⚡high  ✅
The kernel data plane today resolves src CIDR → one rule_id via an
LPM map. Two rules with the same `src_cidr` silently overwrite each
other in that map: only the last-applied wins. The user discovered
this experimentally — adding a higher-priority deny rule changed
which traffic passed.

We can't fix the matching this round without the engine rewrite,
but we CAN surface the conflict so the operator knows what's
happening:

- [ ] Track `shadowed_by_rule_id` per rule. Backend handler walks
      the active rule list, groups by normalised src CIDR, and
      marks all but the highest-priority entry as shadowed.
- [ ] `ruleResponse` grows `shadowed_by_rule_name *string` so the
      UI can show "shadowed by <name>".
- [ ] `RulesPage` renders a "Shadowed" badge in the Kernel column
      when this field is non-null, with a tooltip explaining the
      v2.0 engine limit. Also renders the conflicting rule's name
      inline so the operator can disable the right one.

### O2 — UX clarity on Server-side vs Client-side AllowedIPs  📋medium  ✅
Operators read the two fields as "different shapes of the same
thing" and don't notice that the wg-show change won't make it into
the exported `.conf` without also editing the client side.

- [ ] Rewrite the two field labels + hints in PeerCreateModal +
      PeerEditModal so each one explains what it controls and what
      it does NOT control.
- [ ] New helper button **"Copy server-side routes to client
      AllowedIPs"** in PeerEditModal. One click duplicates the
      server-side CIDRs into the client-side field; the operator
      can then trim before save.
- [ ] Optional **"Sync routes on save"** checkbox that triggers
      the same copy as part of submit. Default off — explicit
      action only.

### O3 — Invalidate peer-config cache on save  ⚡high  ✅
The user reports the Config modal sometimes shows a stale `.conf`
after an edit. The renderer reads live from the DB on every fetch,
but the modal only re-fetches on open. If the operator saves an
edit and then opens Config without closing the page, react-query
serves whatever's in cache.

- [ ] `PeerEditModal` onSave invalidates the same query keys the
      Config modal would use — but we don't cache `.conf` text via
      react-query today (it goes through `apiText`). So the real
      fix is the `peers` invalidation + a one-shot remount of
      PeerConfigModal via a key bump in the parent.
- [ ] In PeersPage + UserDetailPage, track a per-peer "version"
      counter that increments when a peer is edited; pass it as
      the React key to PeerConfigModal so reopening forces a
      fresh fetch.

### O4 — `docs/architecture/0005-rule-engine.md` ADR  📋medium  ✅
Round-11 needs to start from a written plan. Document:
- The current LPM architecture and the overwrite limit
- The new design: per-packet iteration via `bpf_loop` over a
  packed `rule_table_v4` / `rule_table_v6` array of records
  containing inline `src_cidr` + `dst_cidr` + protocol filter
- Migration plan (drop the LPM maps, regenerate bpf2go, syncer
  rewrite, test plan with the bare-metal repro)

---

## Out of scope (round 11)

- **Rule engine rewrite** (the user's "must fix" item). Lands as
  one tight commit in round 11 after the ADR is finalised.
- **Egress TC attach**. Today's TC is ingress-only; rules with
  `direction=egress` are no-ops. Egress hook deferred until the
  engine rewrite ships.
- **IPv6 multi-rule support**: comes with the same rewrite.

## Acceptance — round-10 boxes

- [ ] (R10) Create two active rules with the same `src_cidr`. The
      lower-priority one shows a "shadowed by <name>" badge in the
      Rules table.
- [ ] (R10) Edit modal labels the two AllowedIPs fields clearly
      and the "Copy server-side routes" button works.
- [ ] (R10) Edit a peer, save, immediately open Config — the
      `.conf` reflects the saved change.
- [ ] (R10) `docs/architecture/0005-rule-engine.md` describes the
      v2.0 limitation and the v2.1 rewrite plan.
