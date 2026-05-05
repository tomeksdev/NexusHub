# NexusHub Pre-Release Punch List — Round 4

Source: UI/UX walk-through after rounds 1–3 closed the kernel-link,
data-model, dashboard, and migration gaps. Five focused items, none
architectural.

## Reference files (local only, gitignored)

- `Claude - Project Plan.md`
- `example.html`
- `hexagon_logo.png` — already at `frontend/public/logo.png`. The
  uploaded variant has tiny text baked in; the operator should
  drop a clean icon-only PNG at the same path before tagging.

---

## Pass G — round-4 polish

### G1 — Peer creation: location-driven, not endpoint-driven  ⚡high  ✅
The current modal accepts a free-text endpoint, which lets operators
invent a value that doesn't match the location they picked. Endpoint
already lives on `wg_interfaces.endpoint` — peers should inherit it.

- [ ] Modal pulls the full Locations list and renders a picker with
      `wgN — host:port` labels (replaces the current fixed
      `interfaceID` prop, which still works as the pre-selection
      for the User detail flow).
- [ ] On location change, fetch `GET /api/v1/interfaces/:id/next-ip`
      and pre-fill the Assigned IP field. Operator can still
      override by typing.
- [ ] Endpoint, DNS, MTU, keepalive overrides collapse behind an
      "Advanced options" disclosure (closed by default).
- [ ] Backend: new `GET /api/v1/interfaces/:id/next-ip` returns
      `{"assigned_ip":"10.8.0.5"}` using the existing
      `wg.AllocateIP` allocator + the peer-list query already used
      by Create.

### G2 — Endpoint host + listen-port uniqueness  🔴critical  ✅
Right now we enforce `UNIQUE(listen_port)` blindly. The user's spec:
same port is fine on different endpoint IPs (different binds), but
the same `(endpoint_host, listen_port)` tuple is a conflict.

- [ ] Migration 010: drop the `UNIQUE(listen_port)` constraint
      added in 009. Idempotent — `DROP CONSTRAINT IF EXISTS`.
- [ ] Backend: new helper that normalizes the endpoint to its host
      half (strip port via `net.SplitHostPort`; fall back to the
      raw string when no port). API-layer pre-check rejects
      `(host, listen_port)` collisions with `409
      ENDPOINT_CONFLICT` and a message naming the colliding
      interface ("Endpoint 152.53.64.41:51820 is already used by
      interface wg0").
- [ ] Frontend: surface the message verbatim in the create + edit
      modals.

### G3 — Dashboard owner: username, not email  📋medium  ✅
- [ ] Backend: extend the dashboard `dashboardPeer` payload with
      `owner_username` alongside `owner_email`.
- [ ] Frontend: render `owner_username` first, fall back to email,
      put the email in the row's `title` tooltip so it's still
      reachable on hover but not visible by default.

### G4 — Logo + sidebar header polish  🎨medium  ✅
The provided asset has small embedded text that clashes with the
"NexusHub" wordmark next to it. We can't fix the asset from here,
but we can tighten the layout so the logo is icon-sized and the
text hierarchy is clean.

- [ ] Logo box: `1.75 rem` square (28 px) instead of `2.25 rem`,
      contained so embedded text is at least de-emphasized.
- [ ] Single row: `[logo] NexusHub` on one line, subtitle below in
      smaller muted text.
- [ ] Login-screen logo gets the same sizing.
- [ ] Add a `frontend/public/README.md` note: "Replace `logo.png`
      with an icon-only variant before release; current upload has
      embedded text that hurts readability."

### G5 — Frontend mirror of endpoint conflict + IP validation  small  ✅
Mostly automatic if G1 + G2 land, but worth a checkbox:
- [ ] Modal renders the backend's 409 message inline (not just a
      generic "Failed").
- [ ] `assigned_ip` validation on the client side: must parse,
      must fall inside the selected interface's CIDR, must not be
      the network/broadcast/iface address.

---

## Working components (don't regress)

- ✅ User CRUD + UserDetailPage (round 3)
- ✅ Migration recovery + safe 009 (round 3)
- ✅ Dashboard layout + brand + sparklines (round 3)
- ✅ Kernel-warning ring on Support page (round 3)

---

## Out of scope (still deferred)

- Bind-IP column on `wg_interfaces` (would let the API verify the
  "different IP, same port" claim instead of trusting the operator)
- Display-name field on `users` (G3 falls back to username today)
- Groups + access rules tables, email/SMTP, WebAuthn — same Pass C
  carry-over as round 3

---

## Acceptance — round-4 boxes

- [ ] (R4) Peer create: pick wg0 from a dropdown; endpoint not
      asked; assigned IP auto-suggests next-free
- [ ] (R4) Two locations with same listen port allowed when their
      endpoint hosts differ
- [ ] (R4) Two locations with same listen port + same endpoint
      host blocked with a clear error
- [ ] (R4) Dashboard "Top peers by traffic" shows usernames,
      tooltip carries email
- [ ] (R4) Sidebar header reads as one row with the logo +
      "NexusHub" + a small subtitle below
