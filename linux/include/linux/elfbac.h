#ifndef __LINUX_ELFBAC_H
#define __LINUX_ELFBAC_H

#include <linux/elf.h>
#include <linux/list.h>

#include <asm/mmu.h>

/* Define an upper bound on policy size to prevent exhausting kernel resources,
 * can re-examine this later. */
#define ELFBAC_POLICY_SIZE_MAX (PAGE_SIZE * 10)

#define PT_ELFBAC_POLICY (PT_LOOS + 0xfe7fbac)

struct elfbac_state {
	unsigned long id;
	unsigned long stack_id;
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
	unsigned long to;
	unsigned long from;
	unsigned long base;
	unsigned long size;
	unsigned long flags;
};

struct elfbac_call_transition {
	struct list_head list;
	unsigned long to;
	unsigned long from;
	unsigned long addr;
	unsigned long param_size;
	unsigned long return_size;
};

struct elfbac_policy {
	struct list_head states_list;
	struct list_head data_transitions_list;
	struct list_head call_transitions_list;
	unsigned long num_stacks;
	struct elfbac_state *current_state;
};

int elfbac_parse_policy(unsigned char *buf, size_t size,
		struct elfbac_policy *policy);
void elfbac_policy_destroy(struct elfbac_policy *policy);
int elfbac_policy_clone(struct elfbac_policy *orig, struct elfbac_policy *new);
bool elfbac_access_ok(struct elfbac_policy *policy, unsigned long addr,
		      unsigned int mask, struct elfbac_state **next_state);
int elfbac_copy_mapping(struct elfbac_policy *policy, struct mm_struct *mm,
			struct vm_area_struct *vma, unsigned long addr);

#endif /* ! __LINUX_ELFBAC_H */

