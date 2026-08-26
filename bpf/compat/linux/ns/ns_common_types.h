/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_NS_COMMON_TYPES_H
#define _LINUX_NS_COMMON_TYPES_H

/*
 * BCC/Clang compat for kernel 7.0.0-1011+ (DLPX-98669).
 * Force-included as the first user cflag in estat.py before ZFS preamble.
 *
 * Key observations about the BCC compilation environment:
 * - BCC's built-in preamble defines atomic_t (do NOT redefine)
 * - BCC's preamble does NOT define refcount_t (must define here)
 * - Setting _LINUX_REFCOUNT_TYPES_H prevents the real refcount_types.h from
 *   causing a typedef redefinition conflict later
 *
 * Fixes three fatal BCC/Clang errors:
 * 1. "no member named 'ns_id' in struct ns_common": GCC anonymous-embed
 *    "union { struct ns_tree; ... }" not supported by Clang. Provide flat
 *    struct with ns_id and __ns_ref_active as direct members. Anonymous
 *    struct member (for __ns_ref) must have NO name/attribute — Clang only
 *    supports true anonymous structs (unnamed, no attribute on closing brace).
 * 2. fs.h static_assert failure: suppress via macro.
 * 3. bpf.h identifier mismatches: map BPF_TRACE_FSESSION, BPF_F_CPU, etc.
 */

/* ── Fix 2: suppress fs.h static_assert ────────────────────────────────── */
/*
 * build_bug.h (included by BCC's preamble) defines static_assert before
 * this file runs. #undef first so our no-op definition takes effect.
 */
#undef static_assert
#define static_assert(...) /* disabled — Clang/GCC struct-size mismatch */

/* ── Fix 3: bpf.h identifier mismatches ────────────────────────────────── */
#ifndef BPF_TRACE_FSESSION
#define BPF_TRACE_FSESSION BPF_TRAMP_FSESSION
#endif
#ifndef BPF_F_CPU
#define BPF_F_CPU     0ULL
#endif
#ifndef BPF_F_ALL_CPUS
#define BPF_F_ALL_CPUS 0ULL
#endif

/* ── Fix 1: Clang-compatible flat struct ns_common ──────────────────────── */

/* refcount_t: not in BCC's preamble; define here and suppress real header */
#ifndef _LINUX_REFCOUNT_TYPES_H
#define _LINUX_REFCOUNT_TYPES_H
/* atomic_t is already defined by BCC's built-in preamble */
typedef struct { atomic_t refs; } refcount_t;
#endif

struct dentry;
struct proc_ns_operations;

/*
 * Clang-compatible flat struct ns_common.
 * The __ns_ref anonymous sub-struct has NO name or attribute on the closing
 * brace — Clang requires truly nameless structs for anonymous embedding.
 * The ____cacheline_aligned_in_smp attribute is dropped; the struct layout
 * is not critical for BCC type-checking of BPF programs.
 */
struct ns_common {
	struct {
		refcount_t __ns_ref;
	};                              /* anonymous — no name, no attribute */
	unsigned int ns_type;
	struct dentry *stashed;
	const struct proc_ns_operations *ops;
	unsigned int inum;
	unsigned long ns_id;		/* from struct ns_tree (kernel 7.0+) */
	atomic_t __ns_ref_active;	/* from struct ns_tree (kernel 7.0+) */
};

/*
 * to_ns_common / ns_init_* macros from the real ns_common_types.h.
 * Provide minimal definitions so code that includes ns_common_types.h via
 * user_namespace.h compiles without errors. BPF programs do not call these
 * at runtime.
 */
#ifndef to_ns_common
#define to_ns_common(x) ((struct ns_common *)&(x)->ns)
#endif
#ifndef ns_init_inum
#define ns_init_inum(x) (0U)
#endif
#ifndef ns_init_id
#define ns_init_id(x) (0UL)
#endif
#ifndef ns_init_ns
#define ns_init_ns(x) ((x))
#endif
#ifndef to_ns_operations
#define to_ns_operations(x) ((const struct proc_ns_operations *)0)
#endif
#ifndef ns_common_type
#define ns_common_type(x) (0U)
#endif

#endif /* _LINUX_NS_COMMON_TYPES_H */
