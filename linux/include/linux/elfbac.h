#ifndef __LINUX_ELFBAC_H
#define __LINUX_ELFBAC_H

#include <linux/elf.h>
#include <linux/list.h>
#include <linux/spinlock.h>

#include <asm/mmu.h>

/* Define an upper bound on policy size to prevent exhausting kernel resources,
 * can re-examine this later. */
#define ELFBAC_POLICY_SIZE_MAX (PAGE_SIZE * 10)

#define PT_ELFBAC_POLICY (PT_LOOS + 0xfe7fbac)

#define UNDEFINED_STATE_ID (ULONG_MAX)

struct elfbac_state {
	unsigned long id;
	unsigned long stack_id;
	unsigned long return_state_id;
	struct list_head list;
	struct list_head sections_list;
	pgd_t *pgd;
	mm_context_t context;
};

struct elfbac_section {
	struct list_head list;
	unsigned long base;
	unsigned long size;
	unsigned long flags;
};

struct elfbac_data_transition {
	struct list_head list;
	unsigned long from;
	unsigned long to;
	unsigned long base;
	unsigned long size;
	unsigned long flags;
};

struct elfbac_call_transition {
	struct list_head list;
	unsigned long from;
	unsigned long to;
	unsigned long addr;
	unsigned long param_size;
	unsigned long return_size;
};

struct elfbac_policy {
	struct list_head states_list;
	struct list_head data_transitions_list;
	struct list_head call_transitions_list;
	spinlock_t lock;
	unsigned long num_stacks;
	struct elfbac_state *current_state;
};

int elfbac_parse_policy(struct mm_struct *mm, unsigned char *buf, size_t size,
		struct elfbac_policy *policy);
void elfbac_policy_destroy(struct mm_struct *mm, struct elfbac_policy *policy);
int elfbac_policy_clone(struct mm_struct *mm, struct elfbac_policy *orig,
		struct elfbac_policy *new);
int elfbac_mm_is_present(struct mm_struct *mm, unsigned long addr);
unsigned long elfbac_get_flags(struct elfbac_policy *policy,
			       unsigned long addr);
bool elfbac_access_ok(struct elfbac_policy *policy, unsigned long addr,
		unsigned int mask, struct elfbac_state **next_state);
int elfbac_copy_mapping(struct elfbac_policy *policy, struct mm_struct *mm,
		struct vm_area_struct *vma, unsigned long addr,
		unsigned long flags);

#endif /* ! __LINUX_ELFBAC_H */

