/*
 *  arch/arm/include/asm/domain.h
 *
 *  Copyright (C) 1999 Russell King.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#ifndef __ASM_PROC_DOMAIN_H
#define __ASM_PROC_DOMAIN_H

#ifndef __ASSEMBLY__
#include <asm/barrier.h>
#endif

/*
 * Domain numbers
 *
 *  DOMAIN_IO     - domain 2 includes all IO only
 *  DOMAIN_USER   - domain 1 includes all user memory only
 *  DOMAIN_KERNEL - domain 0 includes all kernel memory only
 *
 * The domain numbering depends on whether we support 36 physical
 * address for I/O or not.  Addresses above the 32 bit boundary can
 * only be mapped using supersections and supersections can only
 * be set for domain 0.  We could just default to DOMAIN_IO as zero,
 * but there may be systems with supersection support and no 36-bit
 * addressing.  In such cases, we want to map system memory with
 * supersections to reduce TLB misses and footprint.
 *
 * 36-bit addressing and supersections are only available on
 * CPUs based on ARMv6+ or the Intel XSC3 core.
 */
#ifndef CONFIG_IO_36
#define DOMAIN_KERNEL	0
#define DOMAIN_TABLE	0
#define DOMAIN_USER	1
#define DOMAIN_IO	2
#else
#define DOMAIN_KERNEL	2
#define DOMAIN_TABLE	2
#define DOMAIN_USER	1
#define DOMAIN_IO	0
#endif

/*
 * Domain types
 */
#define DOMAIN_NOACCESS	0
/*
 * PaX: Removed so we can be certain we replaced all uses of
 * DOMAIN_CLIENT in the kernel
 */
//#define DOMAIN_CLIENT	1

#ifdef CONFIG_CPU_USE_DOMAINS
#define DOMAIN_USERCLIENT	1 /* perm-honoring access allowed */
#define DOMAIN_KERNELCLIENT	1 /* perm-honoring access allowed */
/*
 * PaX: Upstream's CPU_USE_DOMAINS use results in userland memory
 * accesses using instruction variants that act as if the access
 * is being performed by userland code itself.  Since the same
 * copy_*_user code is used in both KERNEL_DS mode and USER_DS mode
 * this results in these "userland" variants being used for kernel
 * to kernel copies.  This of course won't work with permission-honoring
 * domain access values, so they use a mode where any page table permissions
 * are ignored.  This causes a side effect of kernel to kernel copies
 * being allowed to modify read-only kernel memory, something we don't
 * want to allow in PaX.  Therefore, we force CONFIG_CPU_USE_DOMAINS
 * to be disabled but make use of some of the infrastructure it provides.
 */
#define DOMAIN_MANAGER		3 /* perm-ignoring access allowed */
#else

#define DOMAIN_MANAGER		1 /* perm-honoring access allowed */

#ifdef CONFIG_PAX_KERNEXEC
/*
 * PaX: The below value is used to allow temporary write access to
 * read-only data for the current CPU between pax_open/close_kernel
 * calls
 */
#define DOMAIN_KERNEXEC		3 /* perm-ignoring access allowed */
#endif

#ifdef CONFIG_PAX_MEMORY_UDEREF
/* PaX: Domain Access Values */
/* Under UDEREF the default access for userland memory is no access */
#define DOMAIN_USERCLIENT	0 /* no access */
/*
 * Between pax_open/close_userland calls, this access to userland will
 * be provided
 */
#define DOMAIN_UDEREF		1 /* perm-honoring access allowed */
/*
 * PaX: We won't map the vectors into userland when
 * PAX_OLD_ARM_USERLAND is disabled
 * Unlike the above, this is DACR index rather than a value
 * for a particular DACR index
 */
#define DOMAIN_VECTORS		DOMAIN_KERNEL
#else
/* PaX: Default access for userland memory */
#define DOMAIN_USERCLIENT	1 /* perm-honoring access allowed */
#define DOMAIN_VECTORS		DOMAIN_USER
#endif

/* PaX: Default access for kernel memory */
#define DOMAIN_KERNELCLIENT	1 /* perm-honoring access allowed */

#endif

#define domain_val(dom,type)	((type) << (2*(dom)))

#ifndef __ASSEMBLY__

#if defined(CONFIG_CPU_USE_DOMAINS) || defined(CONFIG_PAX_MEMORY_UDEREF) || \
    defined(CONFIG_PAX_KERNEXEC)
static inline void set_domain(unsigned val)
{
	asm volatile(
	"mcr	p15, 0, %0, c3, c0	@ set domain"
	  : : "r" (val));
	isb();
}

extern void modify_domain(unsigned int dom, unsigned int type);
#else
static inline void set_domain(unsigned val) { }
static inline void modify_domain(unsigned dom, unsigned type)	{ }
#endif

/*
 * Generate the T (user) versions of the LDR/STR and related
 * instructions (inline assembly)
 */
#ifdef CONFIG_CPU_USE_DOMAINS
#define TUSER(instr)	#instr "t"
#else
#define TUSER(instr)	#instr
#endif

#else /* __ASSEMBLY__ */

/*
 * Generate the T (user) versions of the LDR/STR and related
 * instructions
 */
#ifdef CONFIG_CPU_USE_DOMAINS
#define TUSER(instr)	instr ## t
#else
#define TUSER(instr)	instr
#endif

#endif /* __ASSEMBLY__ */

#endif /* !__ASM_PROC_DOMAIN_H */
