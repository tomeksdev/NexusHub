# ADR 0003 — eBPF loader & toolchain

- **Status:** Accepted
- **Date:** 2026-04-19
- **Deciders:** @tomeksdev

## Context

Phase 5 introduces eBPF programs for per-peer security rules: an XDP
blocklist on `eth0` (pre-tunnel) and a TC classifier on `wg0`
(post-decryption), with map-based runtime updates so policy changes
never reload the program. CLAUDE.md lists the loader decision as
"`cilium/ebpf` (Go) vs. libbpf + CO-RE". We need:

- A single binary that loads, attaches, and manages maps — no runtime
  C toolchain on the operator's host.
- CO-RE-style portability across kernels ≥ 5.8 (BTF-equipped).
- Native Go bindings so the loader lives alongside `backend/` and
  `cli/` under the same `go build` path.
- A code-gen step from `.c` → Go so map keys/values are type-checked
  at compile time, not at runtime.
- A clean story for pinning to bpffs so eBPF state survives the API
  process restarting.

## Decision

**`github.com/cilium/ebpf`** plus **`cmd/bpf2go`** for code generation.

### Why cilium/ebpf over libbpf + CO-RE

| Concern | cilium/ebpf + bpf2go | libbpf + CO-RE |
|---|---|---|
| Language match | Go (matches backend, cli, Go-based test harness) | C userspace, cgo bridge needed |
| Toolchain on host | `clang` only at **build** time; nothing at runtime | `clang` + `libbpf` runtime required, or static link |
| Code-gen | `bpf2go` generates typed Go structs from C definitions | No equivalent — map keys by untyped `unsafe.Pointer` |
| CO-RE | Supported natively (BTF relocations in loader) | Canonical implementation, but we inherit complexity |
| Map type coverage | All production map types (LPM_TRIE, HASH, PERCPU_*, RINGBUF) | Same |
| Attach helpers | `link.AttachXDP`, `link.AttachTCX`, `link.AttachCgroup` etc. | Manual `bpf_prog_attach`/netlink |
| Pinning | `coll.Maps[...].Pin(path)` | `bpf_obj_pin(fd, path)` |
| Ecosystem | Used by Cilium, tetragon, parca, inspektor-gadget | Upstream kernel tree's reference |
| Testing | Maps usable in unit tests without attaching; program-run tests via `BPF_PROG_TEST_RUN` | Same capability, more boilerplate |
| cgo | None | Required |

The cgo-free property is the tipping point. Everything else in the
repo is cgo-free; introducing it for eBPF alone would bifurcate the
build matrix (especially for the CLI's `goreleaser` cross-compile).

### Build pipeline

```
ebpf/src/*.c  ──clang -target bpf──► ebpf/userspace/*_bpfel.o
                                    └── bpf2go ──► ebpf/userspace/*_bpfel.go
```

- `go generate ./ebpf/...` drives `bpf2go`; output files are checked
  into git so downstream packages compile without `clang` installed.
- bpf2go emits little-endian and big-endian variants (`_bpfel.go`,
  `_bpfeb.go`) gated by build tags; only the host-arch one compiles
  in any given build.
- `clang` is pinned to ≥ 14; verified in CI via a dedicated eBPF
  build step.

### Kernel floor

- **Required:** Linux ≥ 5.8 (BTF, `bpf_link` API, `skb_output`).
- **Preferred:** Linux ≥ 5.15 (BPF_MAP_TYPE_RINGBUF GA, TCX attach).

Operators on older kernels fall back to a degraded mode where the
API still works but eBPF programs are not loaded (Phase 5 has a
"fallback path if kernel lacks BTF" item; this ADR defers the
detection logic to that work, not its policy).

## Consequences

- `go.mod` in `ebpf/` adds `github.com/cilium/ebpf`.
- `ebpf/userspace/` contains both hand-written loader code and
  generated `*_bpfel.go` files; the generated files are in git.
- Build CI gets a new step: install `clang`, run `go generate
  ./ebpf/...`, assert no diff (catches stale generated code).
- Backend integrates the loader through a thin interface
  (`internal/ebpf/Loader`) so `cmd/api` can be built without eBPF
  for tests.
- Unit tests against maps run anywhere; program-attach tests are
  gated behind `-tags=kernel` and need a kernel-ready runner
  (Phase 9 item).
- Pin path convention: `/sys/fs/bpf/nexushub/<program>/<object>`;
  directory must be pre-created with `0755 root:root`.

## Rejected alternatives

- **libbpf + CO-RE via cgo** — mature and canonical, but cgo
  poisons the backend/cli build and buys us nothing `cilium/ebpf`
  doesn't already expose.
- **BCC (bpfcc)** — runtime clang dependency is a non-starter
  for production deployments.
- **aya (Rust)** — compelling, but adds a third language to the
  repo. Reconsider only if Go's eBPF story regresses.
- **`ebpf-go` standalone** (`ebpf.LoadCollectionSpec` without
  `bpf2go`) — works, but loses the typed code-gen. Reserve for
  programs where C source is externally generated.
