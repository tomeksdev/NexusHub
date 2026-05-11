# NexusHub Pre-Release Punch List — Round 8

Source: bare-metal report after round 7. Three critical functional
bugs, two UX gaps. The most important one is the most subtle —
operator types a CIDR into the chip editor, hits Save, and the
network silently doesn't make it to the wire. Stale React state,
not backend, but the symptom looks like backend dropping data.

## Reference files (local only, gitignored)

- `Claude - Project Plan.md`
- `example.html`
- `hexagon_logo.png`

---

## Pass M — round-8 fixes

### M1 — Additional `client_allowed_ips` silently dropped on save  🔴critical  ✅

**Repro:** edit a peer, type `10.10.0.0/24` into Client AllowedIPs,
click Save. The chip editor's draft input never gets committed
because the Save button click fires the form submit before React
flushes the draft → array transition. The submit handler reads
stale state, the PATCH body excludes the field (because the
client array equals the original), and the new network never
reaches the backend.

This isn't a "config generation" bug — the renderer is fine. It's a
React state-timing bug in `CidrList` + the parent submit handlers.

- [ ] `CidrList` exposes an imperative `flush()` via `forwardRef` +
      `useImperativeHandle` that commits any pending draft and
      returns the canonical array.
- [ ] `PeerCreateModal` and `PeerEditModal` hold a ref to each
      `CidrList` and call `flush()` at the top of submit, using the
      returned array (not the stale state) when building the
      request body.
- [ ] Same fix flows through the server-side `allowed_ips` CidrList
      for symmetry — operators can paste-and-save there too.

### M2 — Routed networks not visible in the peer list  🔴critical  ✅

After saving the operator wants to confirm what landed. Today the
table shows Owner / Assigned IP / Status / Last handshake / RX-TX /
Live — no networks. Add a Networks column showing the peer's
`client_allowed_ips` (the routed networks the peer reaches through
the tunnel). For brevity, render up to 2 inline and `+N` for the
rest.

- [ ] PeersPage gets a Networks column. Empty list → "(default)"
      meaning the peer inherits the location CIDR.
- [ ] UserDetailPage's peer table gets the same column.

### M3 — Location + inherited endpoint not shown in PeerEditModal  📋medium  ✅

Edit modal already has a `ConfigPreview` block since round 7, but
the operator wants the location and inherited endpoint surfaced
explicitly at the top — same way the create modal does.

- [ ] Add a read-only summary row at the top of PeerEditModal
      showing `Location: wgN`, `Inherited endpoint: host:port`.
- [ ] Tweak the Endpoint override hint to read
      `Leave blank to use: <inherited endpoint>` so the operator
      knows what they're falling back to.

### M4 — User-role self-service: My Config must show their peers  🔴critical  ✅

Today the My Config page is a stub. The user has no way to view
their own VPN config without an admin handing it to them. The
existing `/peers` and `/peers/:id/config` endpoints are admin-gated
and shouldn't be exposed to all users — instead, add a small
`/me/peers` surface that:

- Lists peers where `owner_user_id` equals the authenticated user
- Serves config + QR for any peer the requester owns

- [ ] Backend: `GET /api/v1/me/peers` lists the requester's peers.
      `GET /api/v1/me/peers/:id/config` and `/config.png` mirror
      the admin endpoints but enforce ownership.
- [ ] Frontend: `MyConfigPage` rewrites from stub to a real list
      using `/me/peers`. Each row offers Show config / Copy /
      Download .conf / Show QR — no admin actions (no Edit, no
      Delete, no Rotate PSK).
- [ ] Rule out the leaks: the user's session token must never let
      them fetch a peer they don't own; tested via `:id` of a
      different user's peer returning 404.

### M5 — Hide Monitoring from the user-role sidebar  🟠high  ✅

Currently `USER_NAV` exposes Monitoring → MetricsPage → which calls
the admin-only `/metrics` endpoint and renders the raw "forbidden"
error. Just remove it from the user nav. Admin keeps it.

- [ ] `App.tsx` USER_NAV drops the `my_monitoring` entry.
- [ ] No backend change — `/metrics` stays admin-gated.

---

## Out of scope (defer)

- Per-peer "primary network" vs. "additional networks" terminology
  separation — server-side `allowed_ips` and client `client_allowed_ips`
  are already two distinct fields with separate UI; the report's
  "additional networks" is the latter, fixed by M1+M2 without a
  schema rework.
- QR for /me/peers — already covered by reusing the admin
  `/config.png` shape behind the new ownership-checked route.

## Acceptance — round-8 boxes

- [ ] (R8) Edit peer, type `10.10.0.0/24` into Client AllowedIPs,
      click Save (no Enter, no + Add) — the network appears in the
      reopened form, in Config preview, and in the downloaded .conf
- [ ] (R8) Peers table renders a Networks column with the routed
      CIDRs visible at a glance
- [ ] (R8) Edit peer modal shows the peer's location and the
      inherited endpoint in a header strip
- [ ] (R8) Log in as `user`-role; My Config lists their peers and
      lets them download the .conf without admin help
- [ ] (R8) `user`-role sidebar has no Monitoring entry; an admin
      browsing `/api/v1/metrics` still works
