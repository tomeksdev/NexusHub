# NexusHub Pre-Release Punch List — Round 7

Source: bare-metal report after round 6. Four focused issues, none
architectural — round 6 closed the kernel + peer-edit blockers, this
round is UX hardening.

## Reference files (local only, gitignored)

- `Claude - Project Plan.md`
- `example.html`
- `hexagon_logo.png` — the official mark; the crop in
  `frontend/src/components/Logo.tsx` exposes only the icon portion.

---

## Pass L — round-7 UX

### L1 — Port wildcard shown as `Any` instead of raw `0..0`  ⚡high  ✅
The backend representation `from=0, to=0` for "any port" leaks
through the rule editor as four numeric inputs. An operator
configuring an SSH deny rule has to type `0` in two of them and
guess that means wildcard. The fix is a frontend-only wrapper —
backend stays exactly the same, so existing rules don't need
migration.

- [ ] New `PortField` component with three modes: `Any` (renders
      no inputs), `Single` (one input), `Range` (two inputs,
      `from <= to` enforced).
- [ ] `RuleEditorModal` uses one `PortField` for source and one for
      destination instead of the current `from`/`to` pairs.
- [ ] `RulesPage` cell formatter renders `0..0` as `Any`, `N..N` as
      `N`, `A..B` as `A–B`.
- [ ] Validation: ports outside `1..65535` rejected (except the
      internal `0..0` wildcard, never typed by hand).

### L2 — Sidebar hexagon logo asymmetry  📋medium  ✅
The round-6 SVG-viewBox crop clips the right side of the icon at
sidebar size — the hex looks unbalanced. Bump the crop window so
the entire mark is visible with breathing room on both sides.

- [ ] Widen `CROP_X` / `CROP_W` in `Logo.tsx` so the right side
      of the hexagon stops being clipped.
- [ ] Test at sidebar size (28 px), login (36 px), and 100/125/150 %
      zoom — all should render the full mark without distortion.

### L3 — Peer creation: clearly show the `/32` peer address + config preview  ⚡high  ✅
The CidrList chip editor already supports `/24`, `/32`, etc, but the
"Peer tunnel address" (the `/32` of the peer itself) is buried in
the `Assigned IP` field with no `/32` suffix shown, and operators
have to imagine the resulting `[Peer] AllowedIPs` line. Adding a
small preview makes the relationship explicit.

- [ ] `PeerCreateModal`: rename the visible label from "Assigned IP"
      to "Peer tunnel address (/32)" and append `/32` (or `/128`
      for IPv6) below the input as a hint. The internal value stays
      a plain IP — the suffix is operator-facing only.
- [ ] Config preview block at the bottom of the modal showing how
      the relevant lines of the exported `.conf` will look:
      `[Interface] Address = <ip>/<bits>` and
      `[Peer] AllowedIPs = <inherits from interface OR
      client_allowed_ips list>`.
- [ ] Same preview block in `PeerEditModal` so the operator sees
      the effect of an allowed-networks change before save.

### L4 — Edit peer reachable from the config modal  ⚡high  ✅
Operators reach the peer config modal expecting to be able to
change settings. The round-6 Edit button is on the table row; once
the operator is in the config modal there's no link to Edit —
they have to close, hunt down the row, and click Edit there.

- [ ] `PeerConfigModal` gets an "Edit peer" button alongside
      Copy / Download / Rotate PSK.
- [ ] Clicking it closes the config modal and opens
      `PeerEditModal` for the same peer. The parent (PeersPage,
      UserDetailPage) coordinates the swap so both modals don't
      stack.

---

## Out of scope (defer)

- Multi-peer-per-user batch operations and tags/labels — the
  report mentions them in the "editable fields" wishlist but
  they're a v2.1 feature, not a release blocker.
- Audit-log entries for peer edits — the existing audit
  middleware records the HTTP call; a richer "changed fields"
  diff is its own piece of work.

## Acceptance — round-7 boxes

- [ ] (R7) Rule editor shows `Any` / `Single` / `Range` for port
      fields. Existing rules with `0..0` show `Any` after refresh.
- [ ] (R7) Rules table renders `Any`, `22`, or `1000–2000`
      (no naked `0..0`).
- [ ] (R7) Sidebar hexagon renders fully balanced left↔right
      with no edge clipping at any of 28/36 px and 100/125/150 %.
- [ ] (R7) Peer create modal labels the address field
      "Peer tunnel address (/32)" and the preview block shows
      the lines that will appear in the exported `.conf`.
- [ ] (R7) Peer config modal has an "Edit peer" button that opens
      the edit modal on the same peer.
