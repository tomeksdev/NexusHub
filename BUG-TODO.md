# NexusHub Pre-Release Punch List — Round 2

Source: second bare-metal test of `dev` branch + the original v2.0.0 project
plan I was supposed to be following from the start. Production verdict: **NOT
READY**.

This file replaces the old triage list. The previous round closed the
kernel-link and frontend-crash blockers, but the *design* and *menu structure*
that landed do not match the v2.0.0 plan, and a second wave of bugs surfaced
once the basic flow worked.

## Reference files (local only, gitignored)

These two are kept in the working tree to inform the redesign and are NOT
pushed to GitHub (see `.gitignore`):

- `Claude - Project Plan.md` — the full v2.0.0 vision (menu hierarchy,
  Locations terminology, RBAC plan).
- `example.html` — the target design system (sidebar `#1e1e1e`, body
  `#1a1a1a`, accent `#FF4C4C`, card-based layout, status badges).

---

## Pass A — UI redesign + menu restructure

The current Tailwind/slate UI is generic. Operators expect the dashboard
described in the project plan and prototyped in `example.html`.

### A1 — Apply the `example.html` design system  ✅
- [x] Body `#1a1a1a`, sidebar `#1e1e1e`, cards `#2a2a2a`, accent `#FF4C4C`
- [ ] Sidebar fixed 280 px, single accent color for active/hover, no slate
- [ ] Top bar with page title + actions + clock badge (rounded card, 1.5 rem
      padding)
- [ ] Stat cards with colored left border (`primary` indigo / `success` green
      / `warning` amber / `danger` red)
- [ ] Status badges: `ok` / `warning` / `critical` with pulsing dot
- [ ] Tables in dark cards with hover row tint
- [ ] Custom-tab pill row for in-page section switches
- [ ] Replace existing `slate-*` Tailwind utilities throughout with the
      new palette (or migrate to a small CSS-variable theme so we stop
      hand-editing class strings every time the palette shifts)

### A2 — Restructure sidebar to match the project plan  ✅
Admin menu (current is flat — needs sections):
```
Main
├── Locations         (CRUD WG endpoints + status indicators + peer counts)
├── Users             (mgmt, role, 2FA status, invite)
└── Monitoring        (real-time charts, connection logs, per-peer stats)

Configuration
├── Global Config     (app name, default DNS, SMTP, feature toggles)
├── Groups            (CRUD groups, assign users + locations)
└── Access Rules      (per-group/location/user allow/deny w/ priority)

Security
└── eBPF Rules        (CRUD eBPF, apply/unapply, compilation status)

Profile
├── My Profile        (name, email, password, 2FA TOTP+WebAuthn)
└── Support           (docs, system info, version, health)
```

User menu:
```
Main
├── My Config         (own peers, .conf, QR, enable/disable)
└── Monitoring        (own stats for allowed locations only)

Profile
├── My Profile        (name, email, password, 2FA, recovery codes)
└── Support           (docs, contact admin)
```

- [ ] Render sidebar with section headers (`Main`, `Configuration`,
      `Security`, `Profile`) instead of one flat list
- [ ] Branch the sidebar items by role (`super_admin`/`admin` vs `user`)
- [ ] Active route highlight with `#FF4C4C` left border + background

### A3 — Rename "Interfaces" → "Locations" in the UI  ✅
The DB table stays `wg_interfaces` — that's the kernel-level primitive — but
the operator concept per the plan is "Locations" (a server endpoint with a
public host + listen port + peers). Pure label rename in the frontend.

- [ ] All UI strings: `Interfaces` → `Locations`
- [ ] Routes: `/interfaces` → `/locations` (with redirect from old path so
      bookmarks don't 404)
- [ ] No DB / API rename in this pass — the v1 endpoint stays
      `/api/v1/interfaces`. Adding a `/locations` alias is a follow-up if
      the SDK ever needs it.

### A4 — Remove i18n  ✅
The plan doesn't include multi-language. The current `react-i18next` setup
adds bundle weight, indirection, and forces every label through a
`t()` lookup with no real benefit.

- [ ] Strip `react-i18next` + `i18next` + `i18next-browser-languagedetector`
      from `package.json`
- [ ] Replace `t("foo")` calls with literal English strings
- [ ] Delete `src/lib/i18n.ts`, `src/lib/locales/`, the `LanguageSwitcher`
      component
- [ ] Remove the `i18n` import side-effect from `main.tsx`

### A5 — Profile + Support pages  ✅
Currently nothing under `/profile`. Plan calls for these as the role-anchor
pages.

- [ ] `My Profile` page: read-only name/email + change password + 2FA setup
      (already exists as `SecurityPage` — fold it in here)
- [ ] `Support` page: docs links, system info, version (read from
      `/api/v1/health` build info), DB pool / WG mode read-outs

### A6 — Dashboard landing page  (deferred)
Per `example.html`, the landing should be a dashboard with KPI stat cards +
charts, not a peer list. Even if the v2.0.0 plan doesn't strictly require a
Dashboard route, this is what the design example shows; the user has flagged
"current looks generic" as a blocker.

- [ ] Add `/` Dashboard route with stat cards (peers online, locations up,
      eBPF rule hits/min, traffic last 24h) + a 24-h traffic chart
- [ ] Sidebar `Main` section starts with `Dashboard` for admin

---

## Pass B — Critical bug fixes

### B1 — Interface edit + delete  ✅
- [ ] Backend: add `PATCH /api/v1/interfaces/:id` (port, address, dns, mtu,
      endpoint, post_up, post_down — never the keys)
- [ ] Backend: confirm `DELETE /api/v1/interfaces/:id` actually works on
      bare metal. Last report said "cannot delete" — verify the netlink
      `DeleteLink` path runs and reports the failure if it doesn't
- [ ] Frontend: `LocationEditModal` (form mirroring create, name + keys
      read-only)
- [ ] Frontend: delete button in the table with confirm dialog

### B2 — Port handling: kernel ↔ DB ↔ UI  ✅
Bug report says "Wrong port assigned" + "UI shows incorrect port vs kernel".
Two suspect paths:
- Create flow may be passing the DB-stored port back without confirming the
  kernel accepted it. If kernel rejected and silently picked a different one,
  the UI lies.
- Reconciler doesn't re-read the live `Device.ListenPort` after applying.

- [ ] Have `InterfaceHandler.Create` re-fetch the kernel device after
      `ConfigureDevice` and surface a 500 if `live.ListenPort != requested`
- [ ] Wire a `wg/status` poll into the Locations table so the live port is
      visible alongside the configured port; show a drift badge if they
      differ
- [ ] Add a backend test that asserts `live.ListenPort == iface.ListenPort`
      after Create against `wg.FakeClient`

### B3 — Port conflict validation  ✅
- [ ] DB: unique constraint on `wg_interfaces.listen_port` (migration 009)
- [ ] Backend: 409 with `LISTEN_PORT_CONFLICT` code when the constraint
      violates, surfaced as a user-readable error in the modal

### B4 — Peer status / handshake / RX-TX desync  ✅
Bug report: "No handshake shown, RX/TX = 0, but actually active in backend".
Root candidates: peer-events SSE never wires up the live counters into the
DB peer row; the table renders the DB peer as the source of truth and the
SSE merge is partial. Need to investigate.

- [ ] Repro: create peer, complete handshake, watch what the SSE actually
      emits (`event: peer` payloads should carry `last_handshake` /
      `rx_bytes` / `tx_bytes`)
- [ ] Confirm `PeersPage` merges live state on top of the DB row (it does
      today via the `live` map keyed by public key — verify it's keyed on
      the right field after the recent `null`-filtering fix)
- [ ] Backfill: periodic job that polls every device and writes the
      cumulative counters back to `wg_peers` so a fresh page load shows
      non-zero values without waiting for an SSE tick
- [ ] If the SSE works fine and the issue is page-load latency, surface a
      "live data loading…" indicator instead of zeros

### B5 — AllowedIPs validation  ✅
Already partially fixed in round 1 (`parsePrefixesStrict`). The new report
calls out "Wrong config generated" — likely the asymmetric `[Peer]
AllowedIPs` issue we addressed in round 1 wasn't enough.

- [ ] Confirm the round-1 `client_allowed_ips` column makes it into the
      exported `.conf` correctly on bare metal
- [ ] Add a server-side check that rejects creates where `assigned_ip` is
      outside every `allowed_ips` entry (today nothing prevents the
      operator from setting `allowed_ips=10.0.0.0/24` and `assigned_ip=
      192.168.5.1`)

---

## Pass C — Deferred (NOT in this batch)

The project plan describes a much bigger v2.0.0 surface than what got built.
Calling these out so the gap is visible — none of these ship as part of
addressing this report:

- `users.first_name` / `users.last_name` columns + invite-via-email flow
- `email_tokens` table + SMTP config + verification / reset / invite emails
- `groups` + `group_users` + `group_locations` model + CRUD + UI
- `access_rules` table + priority-ordered evaluation engine + UI
- `global_config` table + Global Config admin page
- `locations.description` / `locations.max_peers` (stay on
  `wg_interfaces` for now)
- WebAuthn (TOTP is in; WebAuthn is in the plan but not implemented)
- Connection-event streaming into `connection_logs` from the WG poller
  (only eBPF logs land there today)

These are tracked for a follow-up phase; please confirm prioritization
once Passes A + B are green.

---

## Acceptance — what "ready to ship" looks like

A v2.0.0 tag cannot land until every box passes on a real bare-metal host.
Round-1 boxes that still need verification stay on the list; new criteria
mark `(R2)`.

- [ ] (R2) Sidebar matches `example.html` palette + section headers
- [ ] (R2) Admin sees `Locations / Users / Monitoring / Global Config /
      Groups / Access Rules / eBPF Rules / My Profile / Support`
- [ ] (R2) User sees only `My Config / Monitoring / My Profile / Support`
- [ ] (R2) i18n stripped; bundle smaller; no `t()` calls remain
- [ ] (R2) Edit + delete work for a Location end-to-end
- [ ] (R2) Two locations cannot share a listen port (UI surfaces the
      conflict)
- [ ] (R2) Configured port matches `wg show <iface>` listen port in every
      case
- [ ] (R2) Peer table shows non-zero handshake + RX/TX within ≤30 s of an
      active peer connecting
- [ ] Interface created via UI ⇒ `ip link show wg0` reports the link, UP,
      with the configured address (round-1 carry-over)
- [ ] eBPF maps visible at `/sys/fs/bpf/nexushub/` and survive API restart
      (round-1 carry-over)
- [ ] Adding a deny rule blocks matching traffic ≤1 s and `rule_hits`
      increments (round-1 carry-over)

---

## Decisions needed before I start coding

1. **Dashboard route** (A6) — add it now or skip and let `Locations` be the
   landing page? The plan doesn't strictly require it; the design example
   does.
2. **Drop i18n today** (A4) or keep the scaffolding silent for a future
   re-add? My read is full removal — re-adding later is cheap.
3. **`wg_interfaces` → `locations` DB rename** — do later (separate
   migration phase) or never (stay technical-name in DB, "Locations" in
   UI)? My read is later/never — the rename has zero functional value and
   risks breaking integrations.

Send a one-line answer to each and I'll start at A1.
