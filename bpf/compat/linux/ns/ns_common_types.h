/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_NS_COMMON_TYPES_H
#define _LINUX_NS_COMMON_TYPES_H

/*
 * BCC/Clang compat header, force-included before the ZFS SPL preamble in
 * estat.py.  Fixes three compilation errors that arise when BCC compiles
 * BPF programs with the ZFS preamble on kernel 7.0+.
 */

/* fs.h contains a static_assert that fails under BCC/Clang due to a
 * GCC/Clang difference in anonymous-struct sizing.  #undef first because
 * build_bug.h in BCC's preamble has already defined static_assert. */
#undef static_assert
#define static_assert(...)

/* kernel 7.0+ added these bpf.h identifiers; BCC's bundled bpf.h lacks them */
#ifndef BPF_TRACE_FSESSION
#define BPF_TRACE_FSESSION BPF_TRAMP_FSESSION
#endif
#ifndef BPF_F_CPU
#define BPF_F_CPU     0ULL
#endif
#ifndef BPF_F_ALL_CPUS
#define BPF_F_ALL_CPUS 0ULL
#endif

/*
 * kernel 7.0+ ns_common_types.h uses "union { struct ns_tree; ... }" to
 * embed ns_id and __ns_ref_active into struct ns_common.  Clang treats
 * "struct ns_tree;" as a forward declaration, not an anonymous embed, so
 * those fields are invisible and ns_common.h inline functions fail to
 * compile.  Provide a Clang-compatible flat definition.
 *
 * Gated on __has_include: on kernels < 7.0, struct ns_common is defined
 * directly in ns_common.h (no separate types file), so setting this guard
 * and defining the struct here would cause a redefinition error.
 */
#if __has_include(<linux/ns/ns_common_types.h>)

/* refcount_t is not provided by BCC's built-in preamble; suppress the real
 * refcount_types.h to avoid a typedef redefinition conflict.
 * atomic_t IS in BCC's preamble — do not redefine it. */
#ifndef _LINUX_REFCOUNT_TYPES_H
#define _LINUX_REFCOUNT_TYPES_H
typedef struct { atomic_t refs; } refcount_t;
#endif

struct dentry;
struct proc_ns_operations;

struct ns_common {
	struct {
		refcount_t __ns_ref;
	};			/* nameless — Clang requires no name/attr for anonymous embedding */
	unsigned int ns_type;
	struct dentry *stashed;
	const struct proc_ns_operations *ops;
	unsigned int inum;
	unsigned long ns_id;		/* promoted from struct ns_tree */
	atomic_t __ns_ref_active;	/* promoted from struct ns_tree */
};

/* Stubs for _Generic macros defined in the real ns_common_types.h.
 * Referenced by user_namespace.h headers; never called at BPF runtime. */
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

#endif /* __has_include(<linux/ns/ns_common_types.h>) */

#endif /* _LINUX_NS_COMMON_TYPES_H */
