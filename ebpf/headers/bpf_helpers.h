/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Minimal subset of libbpf's bpf_helpers.h.
 *
 * Vendored rather than #included from /usr/include/bpf so the BPF build
 * is reproducible on hosts that have clang but not libbpf. Matches the
 * helper numbering in include/uapi/linux/bpf.h (stable kernel ABI).
 *
 * Add new helpers here on demand; don't copy the full upstream file.
 */
#pragma once

#include <linux/bpf.h>

#define SEC(name) __attribute__((section(name), used))

/* The always-inline attribute is load-bearing on the BPF target.
 * The BPF backend can't lower stack-argument calls; helpers that
 * take more than 5 parameters MUST be fully inlined or codegen
 * fails with "stack arguments are not supported".
 *
 * linux/stddef.h (transitively included via linux/bpf.h) defines
 * __always_inline as a bare `__inline__` — just a hint. We #undef
 * + redefine so the BPF target gets the load-bearing attribute. */
#undef __always_inline
#define __always_inline inline __attribute__((always_inline))

/* Map-definition macros as used in the modern libbpf ".maps" ELF section.
 * A map looks like:
 *
 *     struct {
 *         __uint(type, BPF_MAP_TYPE_HASH);
 *         __type(key, __u32);
 *         __type(value, struct my_val);
 *         __uint(max_entries, 1024);
 *     } my_map SEC(".maps");
 */
#define __uint(name, val)  int (*name)[val]
#define __type(name, val)  typeof(val) *name
#define __array(name, val) typeof(val) *name[]

/* BPF helper declarations. The (void *)N cast is how pre-libbpf programs
 * referenced helpers; the BPF loader rewrites these to real BPF_CALL insns
 * at load time. IDs come from enum bpf_func_id in linux/bpf.h. */
static void *(*bpf_map_lookup_elem)(void *map, const void *key) =
    (void *) BPF_FUNC_map_lookup_elem;

static long (*bpf_map_update_elem)(void *map, const void *key,
                                   const void *value, __u64 flags) =
    (void *) BPF_FUNC_map_update_elem;

static long (*bpf_map_delete_elem)(void *map, const void *key) =
    (void *) BPF_FUNC_map_delete_elem;

static __u64 (*bpf_ktime_get_ns)(void) =
    (void *) BPF_FUNC_ktime_get_ns;

static long (*bpf_trace_printk)(const char *fmt, __u32 fmt_size, ...) =
    (void *) BPF_FUNC_trace_printk;

/* Ring buffer helpers (kernel 5.8+). reserve() returns NULL when the
 * buffer is full; the program must check before writing. submit()
 * publishes the reserved record to userspace consumers. */
static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size, __u64 flags) =
    (void *) BPF_FUNC_ringbuf_reserve;

static void (*bpf_ringbuf_submit)(void *data, __u64 flags) =
    (void *) BPF_FUNC_ringbuf_submit;

static void (*bpf_ringbuf_discard)(void *data, __u64 flags) =
    (void *) BPF_FUNC_ringbuf_discard;

/* Endian-swap builtins. On the BPF target, clang always emits the correct
 * code regardless of host endianness. */
#define bpf_ntohs(x) __builtin_bswap16(x)
#define bpf_ntohl(x) __builtin_bswap32(x)
#define bpf_htons(x) __builtin_bswap16(x)
#define bpf_htonl(x) __builtin_bswap32(x)
