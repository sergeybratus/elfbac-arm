#ifndef __LINUX_ELFBAC_H
#define __LINUX_ELFBAC_H

#include <linux/elf.h>
#include <linux/list.h>
#include <linux/mmu_notifier.h>
#include <linux/spinlock.h>

#include <asm/mmu.h>

/* Define an upper bound on policy size to prevent exhausting kernel resources,
 * can re-examine this later. */
#define ELFBAC_POLICY_SIZE_MAX (PAGE_SIZE)
#define ELFBAC_NUM_STATES_MAX (0x100)
#define ELFBAC_UNDEFINED_STATE_ID (ULONG_MAX)
#define PT_ELFBAC_POLICY (PT_LOOS + 0xfe7fbac)

struct elfbac_state {
	struct list_head list;
	unsigned long id;
	unsigned long stack_id;
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
	spinlock_t lock;
	struct mmu_notifier mmu_notifier;
	struct list_head states_list;
	struct list_head data_transitions_list;
	struct list_head call_transitions_list;
	unsigned long num_stacks;
	pgd_t **stacks;
};

struct elfbac_return_info {
	struct list_head list;
	unsigned long return_addr;
	unsigned long return_size;
	unsigned long return_state_id;
};

struct elfbac_task {
	struct elfbac_policy *policy;
	struct elfbac_state *state;
	struct elfbac_return_info *return_info;
	struct list_head return_info_list;
};

int elfbac_copy_mapping(struct mm_struct *mm, pgd_t *dst_pgd, pgd_t *src_pgd,
		struct vm_area_struct *vma, unsigned long addr,
		unsigned long flags);

int elfbac_policy_parse(struct mm_struct *mm, unsigned char *buf, size_t size,
		struct elfbac_policy *policy);
void elfbac_policy_destroy(struct mm_struct *mm, struct elfbac_policy *policy);
int elfbac_policy_clone(struct mm_struct *mm, struct elfbac_policy *orig,
		struct elfbac_policy *new);

int elfbac_task_init(struct elfbac_policy *policy, struct elfbac_task *task);
void elfbac_task_destroy(struct elfbac_task *task);
int elfbac_task_clone(struct elfbac_policy *new_policy, struct elfbac_task *orig,
	      struct elfbac_task *new);

bool elfbac_access_ok(struct elfbac_policy *policy, unsigned long addr,
		unsigned int mask, unsigned long lr,
		struct elfbac_state **next_state, unsigned long *flags,
		unsigned long *copy_size);

#endif /* ! __LINUX_ELFBAC_H */

