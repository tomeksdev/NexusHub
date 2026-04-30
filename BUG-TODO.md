# NexusHub Pre-Release Bug Triage & Fix Plan

Source: bare-metal test of `dev` branch. Production-readiness verdict: **NOT READY**.

This file is the working punch list. Tick items as they land on `dev`.

---

## Root-cause summary

Three things are actually broken under the hood. Everything in the test report
collapses into one of them.

### 1. Kernel-side WireGuard creation does not work

`wgctrl.ConfigureDevice` only configures **existing** WG devices — it does not
create them. The current code in `backend/internal/handler/interfaces.go:117-130`
and `backend/internal/wg/reconcile.go:74-81` has comments asserting that
"ConfigureDevice creates the device implicitly". That is wrong on every
mainline backend.

To actually bring `wg0` up you need three steps the code never performs:

1. `ip link add wg0 type wireguard` (rtnetlink, `RTM_NEWLINK` with
   `IFLA_INFO_KIND="wireguard"`).
2. `ip address add <iface.address> dev wg0` (rtnetlink, `RTM_NEWADDR`).
3. `ip link set wg0 up` (rtnetlink, `RTM_SETLINK` with `IFF_UP`).

`wgctrl` only steps in **after** step 1 to push private key + listen port +
peers. That is why `wg show wg0 public-key` returned `(none)` in the report —
the device never existed; the netlink call to read it returned ENODEV; the
DB row is just metadata.

### 2. eBPF maps are anonymous and unpinned

CLAUDE.md says programs and maps must be pinned at `/sys/fs/bpf/nexushub/`.
There are zero references to bpffs anywhere in the codebase. Every API restart
loads fresh, anonymous maps; every out-of-band `bpftool` invocation creates a
different set. That explains the "duplicate maps" finding and the lack of
enforcement persistence.

### 3. Frontend has three small but loud bugs

Null pointer on the SSE payload, uncaught refresh-token rejection, and
`navigator.clipboard` undefined on HTTP. None of them are architectural.

---

## Pass 1 — Frontend + config-generation fixes

Tractable without system-level testing. After this pass the UI is usable and
exported `.conf` files are correct.

- [x] **#1 — Fix PeersPage SSE null-pointer crash** (`frontend/src/pages/PeersPage.tsx:105`).
  Guard against payload entries missing `public_key`. Catch the SSE auth-refresh
  rejection so a reused refresh token doesn't crash the page.
- [x] **#2 — Handle refresh-token failure cleanly.** When `refresh()` throws
  `refresh token reused` / `invalid refresh token`, the UI must clear tokens
  and redirect to `/login`. Currently `getAccessTokenForStream` lets the
  rejection escape into the SSE init.
- [x] **#3 — Clipboard fallback for insecure (HTTP) contexts**
  (`frontend/src/pages/PeerConfigModal.tsx:68`). `navigator.clipboard` is
  `undefined` on `http://`. Fall back to a hidden `<textarea>` + `execCommand("copy")`.
- [x] **#4 — Add "Create Interface" UI.** `InterfacesPage` has no creation
  affordance. Add `InterfaceCreateModal` (`name`, `listen_port`, `address` CIDR,
  `dns`, `mtu`, `endpoint`, `post_up`, `post_down`) hitting `POST /api/v1/interfaces`.
- [x] **#5 — Fix wg-quick config generation.** Two sub-bugs in
  `backend/internal/handler/peers.go:507-557`:
  - `wg.EncodePublicKey(raw)` is reused to base64-encode a peer's *private* key.
    Semantically harmless (both halves are 32 bytes → 44-char b64), but the
    function name lies. Rename to `wg.EncodeKey` or split.
  - `[Peer] AllowedIPs` in the **client's** `.conf` is currently populated
    from the server-side `allowed_ips` (which means "what source IPs the
    server accepts from this peer"). On the client that field means
    "destinations to route through the tunnel" — they are not the same thing.
    Default split-tunnel = interface CIDR; full-tunnel = `0.0.0.0/0,::/0`.
    Add a `client_allowed_ips` column so operators control this per peer
    (`@confirm` — needs migration).
- [x] **#6 — Validate peer-create payload.** `parsePrefixes` silently drops
  invalid CIDRs in `allowed_ips`. Reject the request instead. Validate
  `endpoint` is `host:port`, `persistent_keepalive ∈ [0, 65535]`, explicit
  `assigned_ip` is not the network/broadcast/interface address.

---

## Pass 2 — Kernel datapath (the actual release blockers)

Needs validation on a real Linux host with the WireGuard kernel module loaded.
The Go test harness can run unit tests but cannot exercise rtnetlink against
a live kernel.

- [x] **#7 — Create kernel WireGuard link via netlink.** Add an `ensureLink()`
  step to the WG client that:
  1. Looks up the link by name; if absent, creates it with
     `IFLA_INFO_KIND="wireguard"`.
  2. Adds the interface address from the DB row if missing.
  3. Sets `IFF_UP` if down.

  Wire it into `InterfaceHandler.Create` (before the existing
  `ConfigureDevice` call) and into the startup reconciler. Also handle
  delete: `RTM_DELLINK` after the DB row is gone.

  **Open question — netlink dep choice** (`@confirm`):
  - `github.com/vishvananda/netlink` — heavyweight, covers every type of
    link, well-known.
  - `github.com/mdlayher/wireguardctrl` style + `mdlayher/rtnetlink` —
    leaner, single-purpose, matches the style of `wgctrl-go`.

- [x] **#8 — Pin eBPF maps to `/sys/fs/bpf/nexushub`.** Set
  `MapOptions.PinPath` when loading the spec. Mkdir the directory at
  startup with `0700`. Programs already attach via `link.AttachXDP` /
  `link.AttachTCX` — those handles persist for the process lifetime, but
  pinning the **maps** is what gives external `bpftool` a stable view.

  Document the lifecycle in `docs/deployment/`: maps survive API restart;
  `nexushub uninstall` is responsible for `rm -rf /sys/fs/bpf/nexushub`.

- [x] **#9 — Reconcile DB → kernel eBPF rules at startup.** `KernelSyncer`
  handles incremental updates from API calls but no code walks the
  `ebpf_rules` + `ebpf_rule_bindings` tables at startup and seeds the
  kernel maps. Add an `InitialSync(ctx)` called after `RulesLoader` is up
  and before the HTTP listener accepts traffic.

- [x] **#10 — Auto-attach eBPF programs.** Today XDP/TC attach is gated on
  `NEXUSHUB_XDP_IFACE` / `NEXUSHUB_TC_IFACE`. Default behaviour should be:
  - **TC** auto-attached to every WG interface listed in the DB after
    reconcile (we know they exist by the time we get here).
  - **XDP** stays opt-in via env (`@confirm` — auto-detecting the
    default-route NIC is a foot-gun for hosts with multiple uplinks).

---

## Working components (don't regress these)

- Backend builds + unit tests pass
- API auth + JWT refresh (when not crashing the UI)
- Peer creation in DB
- eBPF program load (just not attach/persist)
- eBPF map populate (just not pinned)
- WireGuard handshake (after manual `ip link add` / `ip addr add` / `ip link set up`)

---

## Pre-release acceptance tests

A v2.0.0 tag cannot ship until every box below is checked on a real bare-metal
host (not in CI, not in compose).

- [ ] Interface created via UI ⇒ `ip link show wg0` reports the link, UP, with
      the configured address.
- [ ] `wg show wg0 public-key` returns the interface's public key.
- [ ] Peer created via UI ⇒ visible in `wg show wg0` immediately, no manual
      `wg-quick` step.
- [ ] eBPF programs visible in `bpftool net` after API start.
- [ ] eBPF maps visible at `/sys/fs/bpf/nexushub/` and survive API restart.
- [ ] Adding a deny rule in the UI blocks matching traffic within ≤1 second
      and `rule_hits` for that rule increments.
- [ ] Reboot ⇒ systemd brings API up ⇒ DB rules re-applied to kernel maps ⇒
      enforcement still works without manual intervention.
- [ ] PeersPage opens cleanly on a stale refresh token (redirects to login,
      no console crash).
- [ ] Copy `.conf` button works on `http://` (insecure context).
- [ ] Exported `.conf` `[Peer] AllowedIPs` matches operator intent
      (split-tunnel / full-tunnel) — not the server-side `allowed_ips`.

---

## Decisions (locked in 2026-04-29)

- **#5** — `client_allowed_ips` peer column will be added (migration 008).
- **#7** — Netlink dep is `github.com/vishvananda/netlink`.
- **#10** — TC auto-attached to every DB-listed WG interface after reconcile;
  XDP stays opt-in via `NEXUSHUB_XDP_IFACE` (no default-route auto-detect).
