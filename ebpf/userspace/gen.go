// Package userspace is the Go-side loader for NexusHub's eBPF programs.
//
// The //go:generate directive below drives cilium/ebpf's bpf2go tool:
// given a C source file, it emits a typed Go wrapper (maps + program
// handles) plus an embedded .o blob for the target architecture. The
// generated files land in this directory with names like
// blocklist_bpfel.go and blocklist_bpfel.o; they are checked into git
// so downstream packages compile without clang installed.
//
// Regenerate after touching any file under ebpf/src/ or ebpf/headers/:
//
//	cd ebpf && go generate ./...
//
// Requires clang ≥ 14.
package userspace

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target amd64,arm64 -cflags "-O2 -g -Wall -Werror" Blocklist ../src/blocklist.c -- -I../headers
