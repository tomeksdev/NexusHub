# NexusHub Pre-Release Punch List — Round 5

Source: bare-metal test after round 4. Two issues — one critical
(eBPF rules say active but don't enforce) and one cosmetic loop
(logo asset still has embedded text).

## Reference files (local only, gitignored)

- `Claude - Project Plan.md`
- `example.html`
- `hexagon_logo.png` — kept on disk in case the operator wants to
  swap the inline SVG mark out for a custom asset later.

---

## Pass H — round-5 fixes

### H1 — Runtime TC attach: **the actual eBPF enforcement bug**  🔴critical  ✅
The bare-metal repro: operator creates a new Location after API
start, adds a deny rule, and traffic still flows.

Root cause is in `cmd/api/ebpf.go`. `startEBPF` runs once at boot
and attaches the TC program to every WireGuard interface that
existed at startup. Locations created later via the API land in
the DB and the link is brought up by the rtnetlink path, but
**no TC program ever attaches to the new interface**. The eBPF
maps contain the rule (visible in `bpftool map dump`) but nothing
on the new wgN can see it — packets bypass enforcement entirely.

The KernelSyncer is fine. The map population is fine. The hole
is that the program-attachment stage doesn't follow new links.

- [ ] Define a small `RuntimeAttacher` interface in handler/ with
      `AttachTC(name)` / `DetachTC(name)` shapes.
- [ ] Implement on the eBPF stack in `cmd/api/ebpf.go`. The
      existing `attachTC` / link tracking just needs to be
      re-entrant (de-dupe by interface name) and to expose a
      detach path keyed on name.
- [ ] Wire into `InterfaceHandler.Create` (call `AttachTC` after
      EnsureUp succeeds) and `InterfaceHandler.Delete` (call
      `DetachTC` before the rtnetlink delete).
- [ ] Push every attach/detach failure to the kernel-warnings ring
      so the Support page surfaces it.

### H2 — Kernel-loaded flag per rule  high  ✅
Operator sees "Active: ON" in the rules table even when the rule
was never written to the kernel map (Syncer was Noop, or the Apply
failed silently). The DB enabled state and the kernel enforcement
state are separate concerns; the UI must show both.

- [ ] Add `Has(uuid.UUID) bool` to the `ebpf.Syncer` interface.
      `KernelSyncer.Has` checks the in-memory `ids` table;
      `NoopSyncer.Has` returns false.
- [ ] Rules list handler calls `Has` for each row and includes
      `kernel_loaded` in the response.
- [ ] `RulesPage` grows a "Kernel" column with three states: OK
      (green), OFF (muted — DB-disabled), and ERROR (red — DB
      says enabled but kernel disagrees).

### H3 — Replace logo asset dependency with an inline SVG mark  medium  ✅
The uploaded PNG keeps shipping with embedded text no matter how
small we render it. Path forward: bake a clean hexagon SVG into
the React component and stop reaching for `/logo.png`. Operators
who want custom branding override the SVG component (one file)
instead of editing a binary asset.

- [ ] New `Logo` component renders a hexagon outline + accent
      fill in the product palette. ~28 px in the sidebar, ~36 px
      on the login screen, scales freely.
- [ ] App.tsx + LoginPage.tsx use `<Logo />` instead of
      `<img src="/logo.png">`.
- [ ] Update favicon to the same SVG (vite serves
      `frontend/public/logo.svg`; we keep the existing PNG path
      working as a fallback).
- [ ] `frontend/public/README.md` updated to reflect the SVG-first
      approach.

---

## Working components (don't regress)

All round 1–4 fixes; checklist in `git log` per release.

## Out of scope (still deferred)

- Per-rule "attached on which interface" detail in the UI (out of
  scope for v2.0; the global `kernel_loaded` flag covers the
  operator question "is this rule actually active")
- Egress-direction TC attach (today's setup only attaches
  ingress on each WG iface; the kernel program already supports
  both, but exposing egress hooks is a v2.1 follow-up)

## Acceptance — round-5 boxes

- [ ] (R5) Create a Location via UI ⇒ `bpftool net` shows
      `tc_rules_wg<N>` attached to the new interface within
      seconds of the Create response
- [ ] (R5) Add deny ICMP rule from peer to interface IP ⇒ ping
      from peer fails immediately
- [ ] (R5) Disable rule ⇒ ping works again
- [ ] (R5) Delete rule ⇒ ping works again, rule gone from
      `bpftool map dump`
- [ ] (R5) Rules table renders Kernel column showing OK/OFF/ERROR
- [ ] (R5) Sidebar + login render the inline hexagon SVG; no
      PNG with embedded text in sight
