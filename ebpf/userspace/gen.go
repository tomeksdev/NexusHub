// Package userspace is the Go-side loader for NexusHub's eBPF programs.
//
// The //go:generate directive below drives cilium/ebpf's bpf2go tool:
// given a C source file, it emits a typed Go wrapper (maps + program
// handles) plus an embedded .o blob for the target architecture. The
// generated files land in this directory with names like
// rules_bpfel.go and rules_bpfel.o; they are checked into git so
// downstream packages compile without clang installed.
//
// Regenerate after touching any file under ebpf/src/ or ebpf/headers/:
//
//	cd ebpf && go generate ./...
//
// Requires clang ≥ 14.
package userspace

// On Debian-derived hosts (Ubuntu, Mint, the GH-Actions ubuntu-latest
// runner) the kernel arch headers live under /usr/include/<triplet>/asm/
// rather than /usr/include/asm/. We add both x86_64 and aarch64
// triplet paths so the same generate works on either host arch — clang
// silently ignores -I paths that don't exist.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target amd64,arm64 -cflags "-O2 -g -Wall -Werror" Rules ../src/rules.c -- -I../headers -I/usr/include/x86_64-linux-gnu -I/usr/include/aarch64-linux-gnu
