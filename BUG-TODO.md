# NexusHub Pre-Release Punch List — Round 3

Source: third bare-metal test of `dev` after rounds 1+2 landed. The UI
direction is now correct; the data model is the gap. Production verdict:
**still NOT READY**.

This file replaces the round-2 list. Round-1 fixes (kernel link, eBPF
lifecycle, frontend crashes) and round-2 fixes (UI redesign, location
edit/delete, port conflict, peer status sync) are in `git log`.

## Reference files (local only, gitignored)

- `Claude - Project Plan.md` — v2.0.0 vision (admin/user menu hierarchy,
  Locations terminology, Users → Peers → Locations relationship).
- `example.html` — design system (colors, layout, status badges).
- `hexagon_logo.png` — **commit this one** under `frontend/public/` so the
  sidebar can render it. Currently sitting unreferenced at the repo root.

---

## Pass D — Migration system reliability  (**operators stuck — start here**)

### D1 — Fix `migrate force`  ✅ (and every other subcommand) accepting `-path` after the cmd
The current parser does `fs.Parse(os.Args[2:])`. Go's `flag` package stops
at the first non-flag arg, so `migrate force 8 -path /opt/...` parses as
positional `["8", "-path", "/opt/..."]` — the `-path` flag never binds, the
runner falls back to `defaultMigrationsPath()` which is "." in production,
and the open fails with `open .: no such file or directory`.

Fix: pre-walk `os.Args[1:]` to extract `-path`/`--path` (with both `space`
and `=` syntaxes) regardless of position, then take the first remaining
positional as the cmd. Document both old and new orderings in `--help`.

- [ ] `backend/cmd/migrate/main.go` — argv pre-walk for `-path`
- [ ] Add a unit test: `extractPathFlag` table cases for the 4 forms
      (`-path X`, `--path X`, `-path=X`, `--path=X`) plus "no flag"

### D2 — Make migration 009  ✅ (UNIQUE listen_port) safe to apply with existing duplicates
Round 2 added the unique constraint blindly. Operators with duplicate ports
(common from earlier testing) hit a constraint violation, the DB enters
dirty state at v9, and there's no recovery path.

Fix: wrap the ALTER in a `DO` block that pre-checks for duplicates and
raises a clear error naming the offending interfaces. The constraint still
errors on operator data, but the message tells them exactly what to fix
instead of a bare `unique violation`.

- [ ] Rewrite `migrations/009_interface_listen_port_unique.up.sql` with a
      `DO $$ ... RAISE EXCEPTION ... $$` pre-flight
- [ ] Make the up migration idempotent (`DROP CONSTRAINT IF EXISTS` first)
      so a re-run after dedupe succeeds without a `force` round-trip

### D3 — Recovery doc  ✅ for dirty-state operators
- [ ] One-page `docs/deployment/migration-recovery.md` with the canonical
      sequence: identify duplicates → reassign/delete → `migrate force 8`
      → `migrate up`. Cross-reference from `docs/deployment/README.md`.

---

## Pass C — Users + Peers + Locations CRUD completion

The schema has supported `wg_peers.owner_user_id` since migration 002, but
nothing in the UI or write API uses it. Operators report:

- "Cannot create / edit / delete users"
- "Cannot create peers under users"
- "Multi-peer per user not working"
- "User → Location → Peer mapping incomplete"

This is the headline gap. The fix is mostly wiring:

### C1 — User CRUD (admin endpoints)  ✅
- [ ] `POST /api/v1/users` — admin creates a user (email, username,
      password, role). Hashes via existing argon2id helper. Returns the
      stored row minus the hash.
- [ ] `PATCH /api/v1/users/:id` — partial update (email, username, role,
      is_active). Never password — that's a separate self-service flow.
- [ ] `POST /api/v1/users/:id/password` — admin reset (sets a new password,
      forces change-on-next-login? — TBD, see open questions).
- [ ] `DELETE /api/v1/users/:id` — soft-delete via `is_active=false` first
      (so audit logs keep their actor reference); hard delete only when
      the operator passes `?force=true`.

### C2 — User CRUD (frontend)  ✅
- [ ] `UserCreateModal` and `UserEditModal` matching the design system
- [ ] "+ New user" button on the Users page top bar
- [ ] Edit + delete (with confirm) buttons in each row
- [ ] Show peer count per user in the table (count over /peers/?owner_user_id=)

### C3 — Peer ownership: assign user to peer at create + multi-peer per user  ✅
- [ ] `PeerCreateModal` gains a User picker (server-fetched, searchable).
      The current `interface_id`-only flow stays — admin can also pick the
      Location. owner_user_id flows through to `wg_peers.owner_user_id`
      (the column is already there, the backend already accepts it).
- [ ] PeersPage table grows an Owner column showing the assigned user's
      email or `—`.
- [ ] On a User detail view (C4), every peer for that user is listed
      regardless of which location it belongs to.

### C4 — User detail view  ✅
- [ ] New `UserDetailPage` reachable by clicking a row in `UsersPage`
- [ ] Sections: profile (read-only summary), peers list (filtered by
      owner_user_id), audit-log entries scoped to actor=user
- [ ] "+ Add peer for this user" — opens `PeerCreateModal` with the user
      pre-selected and only the Location picker active

---

## Pass E — Dashboard + branding + real-time UX

### E1 — Dashboard landing page  ✅
The plan and the design example both call for a dashboard-first UX. Today
admins land on `Locations` which is a list, not a dashboard.

- [ ] New `DashboardPage` becomes the admin default landing route
- [ ] Top stat row: total Locations / total Users / total Peers / Peers
      online (last 3 min)
- [ ] "Top 10 active peers" panel — sorted by RX+TX in the last poll,
      shows owner email + location + sparkline
- [ ] "Active locations" panel — name, listen port, live peer count,
      live state (UP/DOWN with the example.html status-badge)
- [ ] Backend: `GET /api/v1/dashboard` returns the aggregates in a single
      payload so the page doesn't N+1 across /peers/locations/wg-status.
      Reuses the round-2 peer stats poller's data so this is cheap.

### E2 — Brand the sidebar with `hexagon_logo.png`  ✅
- [ ] Move `hexagon_logo.png` → `frontend/public/logo.png`
- [ ] Sidebar brand block uses `<img src="/logo.png">` next to the
      "NexusHub" wordmark
- [ ] Login page also gets the logo above the form
- [ ] Favicon: replace `frontend/public/favicon.svg` with the hexagon
      (either as PNG or convert)

### E3 — Real-time peer indicators  ✅
- [ ] Pulsing green dot in PeersPage rows for peers handshaken in the
      last 60 s (today's "live" classification is 3 min — too coarse for
      "is this peer talking right now")
- [ ] Tiny sparkline column in PeersPage showing the last ~30 RX deltas
      from SSE so the operator sees per-peer traffic without leaving the
      table

---

## Pass F — Validation + error surfacing

### F1 — API-layer port pre-validation  ✅
The DB constraint catches duplicates but the message is opaque. Add a
`SELECT 1 FROM wg_interfaces WHERE listen_port=$1` pre-flight in the
Create handler that returns a `LISTEN_PORT_CONFLICT` 409 before the
INSERT. Same for Update.

- [ ] Pre-flight check in `InterfaceHandler.Create`
- [ ] Pre-flight check in `InterfaceHandler.Update`

### F2 — User-peer-location consistency  ✅
- [ ] When a peer is created with an `owner_user_id`, the user must be
      `is_active=true` (today nothing prevents assigning peers to a
      disabled user)
- [ ] When a user is soft-deleted, optionally cascade-disable their
      peers via a flag on the DELETE endpoint

### F3 — Surface backend errors more loudly  ✅
- [ ] `slog.Warn(...)` calls in handler kernel-apply paths today are
      invisible to the operator. Add a simple in-memory ring of the last
      50 kernel-apply warnings, exposed at `GET /api/v1/diag/kernel-warnings`,
      so the Support page can render them. Alerts on warnings older than
      a few minutes get auto-cleared.

---

## Working components (don't regress)

- ✅ Interface (Location) creation, edit, delete (round 2)
- ✅ WireGuard kernel link create + UP + addr (round 1)
- ✅ eBPF map pinning + startup rule reconcile (round 1)
- ✅ Frontend design system + sidebar restructure (round 2)
- ✅ TOTP 2FA flow

---

## Out of scope (still deferred)

- Groups + access rules tables, CRUD, UI (plan §6)
- Email/SMTP infra: invitations, password reset, verification
- `users.first_name` / `users.last_name`
- Global config table + Global Config admin page
- WebAuthn (TOTP is in)
- `connection_logs` write-back from the WG stats poller (today only the
  eBPF logger writes there)

These stay flagged for v2.1.

---

## Acceptance — what "ready to ship" looks like

Each box must pass on a real bare-metal host before tagging v2.0.0.

- [ ] (R3) `migrate force 9 -path /opt/NexusHub/migrations` works
- [ ] (R3) Re-running `migrate up` after deduping ports succeeds without
      a manual force step
- [ ] (R3) Admin can create / edit / delete a user from the UI
- [ ] (R3) Admin can create a peer for a specific user, choosing the
      Location from a dropdown
- [ ] (R3) A user with three peers across two locations shows all three
      on their detail view
- [ ] (R3) Dashboard renders top-10 peers, active locations, peers
      online
- [ ] (R3) Hexagon logo renders in the sidebar + login screen
- [ ] (R3) Two locations cannot share a port — UI rejects with a clear
      message before the DB rejects
- [ ] (carry) Interface created via UI ⇒ `ip link show <name>` UP with
      the configured address
- [ ] (carry) eBPF maps survive restart at `/sys/fs/bpf/nexushub`
- [ ] (carry) Adding a deny rule blocks traffic ≤1 s and `rule_hits`
      increments

---

## Open questions before I start coding

1. **Admin password reset UX (C1)** — `POST /users/:id/password` sets a
   new password. Does the user need to change it on next login, or is
   the new password just live? My read is "live" today (we don't have a
   `must_change_password` flag on `users`); document the trade-off and
   move on.
2. **Soft-delete semantics (C1)** — `DELETE /users/:id` flips
   `is_active=false`; their peers stay active. Hard delete (`?force=true`)
   cascades via the existing FK. Sound right?
3. **Dashboard route as default landing (E1)** — admin currently lands on
   Locations. Should the redirect happen now (recommended) or stay
   stable until the dashboard page is fully populated? My read is
   redirect now even with sparse data.

Send a one-liner per question and I'll start at D1.
