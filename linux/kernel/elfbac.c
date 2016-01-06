#include <asm/mmu_context.h>
#include <asm/pgalloc.h>
#include <asm/pgtable.h>
#include <asm/tlb.h>

#include <linux/list.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/resource.h>
#include <linux/rmap.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/uaccess.h>

#include <linux/elfbac.h>

/* Modified routines from mm/memory.c
 * TODO: Potentially factor out common code to reduce duplication
 * TODO: Hugepages support
 */
static inline unsigned long elfbac_copy_one_pte(struct mm_struct *mm,
		pte_t *dst_pte, pte_t *src_pte, struct vm_area_struct *vma,
		unsigned long addr, unsigned long flags)
{
	pte_t pte = *src_pte;
	struct page *page;

	/* pte contains position in file, so copy. */
	if (unlikely(!pte_present(pte))) {
		swp_entry_t entry = pte_to_swp_entry(pte);

		if (likely(!non_swap_entry(entry))) {
			if (swap_duplicate(entry) < 0)
				return entry.val;
		} else if (is_migration_entry(entry)) {
			page = migration_entry_to_page(entry);
		}
		goto out_set_pte;
	}

	page = vm_normal_page(vma, addr, pte);
	if (page) {
		get_page(page);
		page_dup_rmap(page);
	}

out_set_pte:
	if (!(flags & VM_WRITE))
		pte = pte_wrprotect(pte);

	if (!(flags & VM_EXEC))
		pte = pte_mknexec(pte);

	if (!flags)
		pte = pte_modify(pte, PAGE_NONE);

	set_pte_at(mm, addr, dst_pte, pte);
	return 0;
}

static int elfbac_copy_pte_range(struct mm_struct *mm, pmd_t *dst_pmd,
		pmd_t *src_pmd, struct vm_area_struct *vma, unsigned long addr,
		unsigned long end, unsigned long flags)
{
	pte_t *orig_src_pte, *orig_dst_pte;
	pte_t *src_pte, *dst_pte;
	spinlock_t *dst_ptl;
	int progress = 0;
	swp_entry_t entry = (swp_entry_t){0};

again:
	dst_pte = pte_alloc_map_lock(mm, dst_pmd, addr, &dst_ptl);
	if (!dst_pte)
		return -ENOMEM;
	src_pte = pte_offset_map(src_pmd, addr);
	orig_src_pte = src_pte;
	orig_dst_pte = dst_pte;
	arch_enter_lazy_mmu_mode();

	do {
		if (pte_none(*src_pte)) {
			progress++;
			continue;
		}
		entry.val = elfbac_copy_one_pte(mm, dst_pte, src_pte, vma,
						addr, flags);
		if (entry.val)
			break;
		progress += 8;
	} while (dst_pte++, src_pte++, addr += PAGE_SIZE, addr != end);

	arch_leave_lazy_mmu_mode();
	pte_unmap(orig_src_pte);
	pte_unmap_unlock(orig_dst_pte, dst_ptl);
	cond_resched();

	if (entry.val) {
		if (add_swap_count_continuation(entry, GFP_KERNEL) < 0)
			return -ENOMEM;
		progress = 0;
	}

	if (addr != end)
		goto again;
	return 0;
}

static inline int elfbac_copy_pmd_range(struct mm_struct *mm, pud_t *dst_pud,
		pud_t *src_pud, struct vm_area_struct *vma, unsigned long addr,
		unsigned long end, unsigned long flags)
{
	pmd_t *src_pmd, *dst_pmd;
	unsigned long next;

	dst_pmd = pmd_alloc(mm, dst_pud, addr);
	if (!dst_pmd)
		return -ENOMEM;
	src_pmd = pmd_offset(src_pud, addr);
	do {
		next = pmd_addr_end(addr, end);
//		if (pmd_trans_huge(*src_pmd)) {
//			int err;
//			VM_BUG_ON(next-addr != HPAGE_PMD_SIZE);
//			err = copy_huge_pmd(mm, src_mm,
//					    dst_pmd, src_pmd, addr, vma);
//			if (err == -ENOMEM)
//				return -ENOMEM;
//			if (!err)
//				continue;
//			/* fall through */
//		}
		if (pmd_none_or_clear_bad(src_pmd))
			continue;
		if (elfbac_copy_pte_range(mm, dst_pmd, src_pmd, vma,
						addr, next, flags))
			return -ENOMEM;
	} while (dst_pmd++, src_pmd++, addr = next, addr != end);
	return 0;
}

static inline int elfbac_copy_pud_range(struct mm_struct *mm, pgd_t *dst_pgd, pgd_t *src_pgd,
					struct vm_area_struct *vma, unsigned long addr,
					unsigned long end, unsigned long flags)
{
	pud_t *src_pud, *dst_pud;
	unsigned long next;

	dst_pud = pud_alloc(mm, dst_pgd, addr);
	if (!dst_pud)
		return -ENOMEM;
	src_pud = pud_offset(src_pgd, addr);
	do {
		next = pud_addr_end(addr, end);
		if (pud_none_or_clear_bad(src_pud))
			continue;
		if (elfbac_copy_pmd_range(mm, dst_pud, src_pud, vma,
					  addr, next, flags))
			return -ENOMEM;
	} while (dst_pud++, src_pud++, addr = next, addr != end);
	return 0;
}

static int elfbac_copy_page_range(struct mm_struct *mm, pgd_t *dst_pgd, pgd_t *src_pgd,
				  struct vm_area_struct *vma, unsigned long addr,
				  unsigned long end, unsigned long flags)
{
	unsigned long next;
	int ret;

	if (vma->vm_start > addr || end > vma->vm_end)
		return -EINVAL;

//	if (is_vm_hugetlb_page(vma))
//		return copy_hugetlb_page_range(mm, src_mm, vma);

	if (unlikely(vma->vm_flags & VM_PFNMAP)) {
		/*
		 * We do not free on error cases below as remove_vma
		 * gets called on error from higher level routine
		 */
		ret = track_pfn_copy(vma);
		if (ret)
			return ret;
	}

	ret = 0;
	dst_pgd += pgd_index(addr);
	src_pgd += pgd_index(addr);
	do {
		next = pgd_addr_end(addr, end);
		if (pgd_none_or_clear_bad(src_pgd))
			continue;
		if (unlikely(elfbac_copy_pud_range(mm, dst_pgd, src_pgd,
					    vma, addr, next, flags))) {
			ret = -ENOMEM;
			break;
		}
	} while (dst_pgd++, src_pgd++, addr = next, addr != end);

	return ret;
}

int elfbac_copy_mapping(struct mm_struct *mm, pgd_t *dst_pgd, pgd_t *src_pgd,
			struct vm_area_struct *vma, unsigned long addr,
			unsigned long flags)
{
	unsigned long start, end;

	start = rounddown(addr, PAGE_SIZE);
	end = roundup(addr, PAGE_SIZE);

	if (start == end)
		end += PAGE_SIZE;

	return elfbac_copy_page_range(mm, dst_pgd, src_pgd, vma, start, end, flags);
}

/*
 * Note: this doesn't free the actual pages themselves. That
 * has been handled earlier when unmapping all the memory regions.
 */
static void elfbac_free_pte_range(struct mmu_gather *tlb, pmd_t *pmd,
			   unsigned long addr)
{
	pgtable_t token = pmd_pgtable(*pmd);
	pmd_clear(pmd);
	pte_free_tlb(tlb, token, addr);
	atomic_long_dec(&tlb->mm->nr_ptes);
}

static inline void elfbac_free_pmd_range(struct mmu_gather *tlb, pud_t *pud,
				unsigned long addr, unsigned long end,
				unsigned long floor, unsigned long ceiling)
{
	pmd_t *pmd;
	unsigned long next;
	unsigned long start;

	start = addr;
	pmd = pmd_offset(pud, addr);
	do {
		next = pmd_addr_end(addr, end);
		if (pmd_none_or_clear_bad(pmd))
			continue;
		elfbac_free_pte_range(tlb, pmd, addr);
	} while (pmd++, addr = next, addr != end);

	start &= PUD_MASK;
	if (start < floor)
		return;
	if (ceiling) {
		ceiling &= PUD_MASK;
		if (!ceiling)
			return;
	}
	if (end - 1 > ceiling - 1)
		return;

	pmd = pmd_offset(pud, start);
	pud_clear(pud);
	pmd_free_tlb(tlb, pmd, start);
	mm_dec_nr_pmds(tlb->mm);
}

static inline void elfbac_free_pud_range(struct mmu_gather *tlb, pgd_t *pgd,
				unsigned long addr, unsigned long end,
				unsigned long floor, unsigned long ceiling)
{
	pud_t *pud;
	unsigned long next;
	unsigned long start;

	start = addr;
	pud = pud_offset(pgd, addr);
	do {
		next = pud_addr_end(addr, end);
		if (pud_none_or_clear_bad(pud))
			continue;
		elfbac_free_pmd_range(tlb, pud, addr, next, floor, ceiling);
	} while (pud++, addr = next, addr != end);

	start &= PGDIR_MASK;
	if (start < floor)
		return;
	if (ceiling) {
		ceiling &= PGDIR_MASK;
		if (!ceiling)
			return;
	}
	if (end - 1 > ceiling - 1)
		return;

	pud = pud_offset(pgd, start);
	pgd_clear(pgd);
	pud_free_tlb(tlb, pud, start);
}

/*
 * This function frees user-level page tables of a process.
 */
static void elfbac_free_pgd_range(struct mmu_gather *tlb, pgd_t *pgd,
			unsigned long addr, unsigned long end,
			unsigned long floor, unsigned long ceiling)
{
	unsigned long next;

	/*
	 * The next few lines have given us lots of grief...
	 *
	 * Why are we testing PMD* at this top level?  Because often
	 * there will be no work to do at all, and we'd prefer not to
	 * go all the way down to the bottom just to discover that.
	 *
	 * Why all these "- 1"s?  Because 0 represents both the bottom
	 * of the address space and the top of it (using -1 for the
	 * top wouldn't help much: the masks would do the wrong thing).
	 * The rule is that addr 0 and floor 0 refer to the bottom of
	 * the address space, but end 0 and ceiling 0 refer to the top
	 * Comparisons need to use "end - 1" and "ceiling - 1" (though
	 * that end 0 case should be mythical).
	 *
	 * Wherever addr is brought up or ceiling brought down, we must
	 * be careful to reject "the opposite 0" before it confuses the
	 * subsequent tests.  But what about where end is brought down
	 * by PMD_SIZE below? no, end can't go down to 0 there.
	 *
	 * Whereas we round start (addr) and ceiling down, by different
	 * masks at different levels, in order to test whether a table
	 * now has no other vmas using it, so can be freed, we don't
	 * bother to round floor or end up - the tests don't need that.
	 */

	addr &= PMD_MASK;
	if (addr < floor) {
		addr += PMD_SIZE;
		if (!addr)
			return;
	}
	if (ceiling) {
		ceiling &= PMD_MASK;
		if (!ceiling)
			return;
	}
	if (end - 1 > ceiling - 1)
		end -= PMD_SIZE;
	if (addr > end - 1)
		return;

	pgd += pgd_index(addr);
	do {
		next = pgd_addr_end(addr, end);
		if (pgd_none_or_clear_bad(pgd))
			continue;
		elfbac_free_pud_range(tlb, pgd, addr, next, floor, ceiling);
	} while (pgd++, addr = next, addr != end);
}

static void elfbac_free_pgtables(struct mmu_gather *tlb, pgd_t *pgd,
				 struct vm_area_struct *vma,
				 unsigned long floor, unsigned long ceiling)
{
	while (vma) {
		struct vm_area_struct *next = vma->vm_next;
		unsigned long addr = vma->vm_start;

		/*
		 * Optimization: gather nearby vmas into one call down
		 */
		while (next && next->vm_start <= vma->vm_end + PMD_SIZE
		       && !is_vm_hugetlb_page(next)) {
			vma = next;
			next = vma->vm_next;
		}
		elfbac_free_pgd_range(tlb, pgd, addr, vma->vm_end,
			floor, next? next->vm_start: ceiling);
		vma = next;
	}
}

static int parse_ulong(unsigned char **buf, size_t *size, unsigned long *out)
{
	if (*size >= sizeof(unsigned long)) {
		*out = *(unsigned long *)(*buf);
		*buf += sizeof(unsigned long);
		*size -= sizeof(unsigned long);
		return 0;
	}

	return -1;
}

static int elfbac_parse_state(unsigned char **buf, size_t *size,
			      struct elfbac_state *state)
{
	if (parse_ulong(buf, size, &state->stack_id) != 0)
		return -EINVAL;

	return 0;
}

static int elfbac_parse_section(unsigned char **buf, size_t *size,
				struct elfbac_section *section)
{
	if (parse_ulong(buf, size, &section->base) != 0)
		return -EINVAL;
	if (parse_ulong(buf, size, &section->size) != 0)
		return -EINVAL;
	if (parse_ulong(buf, size, &section->flags) != 0)
		return -EINVAL;

	return 0;
}

static int elfbac_parse_data_transition(unsigned char **buf, size_t *size,
					struct elfbac_data_transition *data_transition)
{
	if (parse_ulong(buf, size, &data_transition->from) != 0)
		return -EINVAL;
	if (parse_ulong(buf, size, &data_transition->to) != 0)
		return -EINVAL;
	if (parse_ulong(buf, size, &data_transition->base) != 0)
		return -EINVAL;
	if (parse_ulong(buf, size, &data_transition->size) != 0)
		return -EINVAL;
	if (parse_ulong(buf, size, &data_transition->flags) != 0)
		return -EINVAL;

	return 0;
}

static int elfbac_parse_call_transition(unsigned char **buf, size_t *size,
					struct elfbac_call_transition *call_transition)
{
	if (parse_ulong(buf, size, &call_transition->from) != 0)
		return -EINVAL;
	if (parse_ulong(buf, size, &call_transition->to) != 0)
		return -EINVAL;
	if (parse_ulong(buf, size, &call_transition->addr) != 0)
		return -EINVAL;
	if (parse_ulong(buf, size, &call_transition->param_size) != 0)
		return -EINVAL;
	if (parse_ulong(buf, size, &call_transition->return_size) != 0)
		return -EINVAL;

	return 0;
}

static int elfbac_validate_policy(struct elfbac_policy *policy)
{
	unsigned long num_states = 0;
	struct elfbac_state *state;
	struct elfbac_section *section;
	struct elfbac_data_transition *data_transition;
	struct elfbac_call_transition *call_transition;

	list_for_each_entry(state, &policy->states_list, list) {
		if (state->stack_id >= policy->num_stacks)
			return -EINVAL;

		num_states++;

		list_for_each_entry(section, &state->sections_list, list) {
			if (section->base + section->size < section->base)
				return -EINVAL;
		}

	}

	if (num_states == 0)
		return -EINVAL;

	if (policy->num_stacks < 1 || policy->num_stacks > num_states)
		return -EINVAL;

	list_for_each_entry(data_transition, &policy->data_transitions_list, list) {
		if (data_transition->from > num_states ||
		    data_transition->to > num_states)
			return -EINVAL;

		if (data_transition->base + data_transition->size < data_transition->base)
			return -EINVAL;
	}

	list_for_each_entry(call_transition, &policy->call_transitions_list, list) {
		if (call_transition->from > num_states ||
		    call_transition->to > num_states)
			return -EINVAL;

		if (call_transition->param_size > PAGE_SIZE ||
		    call_transition->return_size > PAGE_SIZE)
			return -EINVAL;
	}

	return 0;
}

int elfbac_parse_policy(struct mm_struct *mm, unsigned char *buf, size_t size,
			struct elfbac_policy *out)
{
	enum {
		STATE = 1,
		SECTION,
		DATA_TRANSITION,
		CALL_TRANSITION
	} type;

	int i, retval;
	unsigned long flags;
	unsigned long cur_state_id = 0;

	struct elfbac_state *state;
	struct elfbac_section *section;
	struct elfbac_data_transition *data_transition;
	struct elfbac_call_transition *call_transition;

	spin_lock_init(&out->lock);
	spin_lock_irqsave(&out->lock, flags);

	INIT_LIST_HEAD(&out->states_list);
	INIT_LIST_HEAD(&out->data_transitions_list);
	INIT_LIST_HEAD(&out->call_transitions_list);
	out->stacks = NULL;

	retval = -EINVAL;
	if (parse_ulong(&buf, &size, &out->num_stacks) != 0)
		goto err;

	while (size) {
		retval = -EINVAL;
		if (parse_ulong(&buf, &size, (unsigned long *)&type) != 0)
			goto err;

		switch (type) {
		case STATE:
			if (cur_state_id >= ELFBAC_NUM_STATES_MAX)
				goto err;

			retval = -ENOMEM;
			state = kmalloc(sizeof(struct elfbac_state),
					GFP_KERNEL);
			if (!state)
				goto err;

			state->pgd = pgd_alloc(mm);
			if (!state->pgd) {
				kfree(state);
				goto err;
			}

			retval = elfbac_parse_state(&buf, &size, state);
			if (retval != 0) {
				pgd_free(mm, state->pgd);
				kfree(state);
				goto err;
			}

			state->id = cur_state_id++;
			state->return_addr = 0;
			state->return_size = 0;
			state->return_state_id = ELFBAC_UNDEFINED_STATE_ID;

			memset(&state->context, 0, sizeof(mm_context_t));
			INIT_LIST_HEAD(&state->sections_list);

			list_add_tail(&state->list, &out->states_list);
			break;
		case SECTION:
			if (list_empty(&out->states_list))
				goto err;

			state = list_last_entry(&out->states_list,
						struct elfbac_state,
						list);

			retval = -ENOMEM;
			section = kmalloc(sizeof(struct elfbac_section),
					  GFP_KERNEL);
			if (!section)
				goto err;

			retval = elfbac_parse_section(&buf, &size, section);
			if (retval != 0) {
				kfree(section);
				goto err;
			}

			list_add_tail(&section->list, &state->sections_list);
			break;
		case DATA_TRANSITION:
			retval = -ENOMEM;
			data_transition = kmalloc(sizeof(struct elfbac_data_transition),
						  GFP_KERNEL);
			if (!data_transition)
				goto err;

			retval = elfbac_parse_data_transition(&buf, &size,
							      data_transition);
			if (retval != 0) {
				kfree(data_transition);
				goto err;
			}

			list_add_tail(&data_transition->list, &out->data_transitions_list);
			break;
		case CALL_TRANSITION:
			retval = -ENOMEM;
			call_transition = kmalloc(sizeof(struct elfbac_call_transition),
						  GFP_KERNEL);
			if (!call_transition)
				goto err;

			retval = elfbac_parse_call_transition(&buf, &size,
							      call_transition);
			if (retval != 0) {
				kfree(call_transition);
				goto err;
			}

			list_add_tail(&call_transition->list, &out->call_transitions_list);
			break;
		default:
			goto err;
		}
	}

	retval = -EINVAL;
	if (elfbac_validate_policy(out) != 0)
		goto err;

	retval = -EINVAL;
	if (out->num_stacks < 1 || out->num_stacks >= ELFBAC_NUM_STATES_MAX)
		goto err;

	retval = -ENOMEM;
	out->stacks = kmalloc(sizeof(pgd_t *) * out->num_stacks, GFP_KERNEL);
	if (!out->stacks)
		goto err;
	out->stacks[0] = mm->pgd;
	for (i = 1; i < out->num_stacks; i++)
		out->stacks[i] = pgd_alloc(mm);

	out->current_state = list_entry(out->states_list.next, struct elfbac_state, list);
	spin_unlock_irqrestore(&out->lock, flags);
	return 0;

err:
	spin_unlock_irqrestore(&out->lock, flags);
	elfbac_policy_destroy(mm, out);

	return retval;
}

void elfbac_policy_destroy(struct mm_struct *mm, struct elfbac_policy *policy)
{
	int i;
	unsigned long flags;
	struct elfbac_state *state, *nstate;
	struct elfbac_section *section, *nsection;
	struct elfbac_data_transition *data_transition, *ndata_transition;
	struct elfbac_call_transition *call_transition, *ncall_transition;
	struct mmu_gather tlb;
	pgd_t *orig_pgd;

	spin_lock_irqsave(&policy->lock, flags);

	list_for_each_entry_safe(state, nstate, &policy->states_list, list) {
		list_for_each_entry_safe(section, nsection, &state->sections_list, list)
			kfree(section);

		tlb_gather_mmu(&tlb, mm, 0, -1);
		elfbac_free_pgtables(&tlb, state->pgd, mm->mmap,
				     FIRST_USER_ADDRESS, USER_PGTABLES_CEILING);
		tlb_finish_mmu(&tlb, 0, -1);

		pgd_free(mm, state->pgd);
		kfree(state);
	}

	if (policy->stacks) {
		orig_pgd = mm->pgd;
		for (i = 1; i < policy->num_stacks; i++) {
			mm->pgd = policy->stacks[i];
			tlb_gather_mmu(&tlb, mm, 0, -1);
			unmap_vmas(&tlb, mm->mmap, 0, -1);
			elfbac_free_pgtables(&tlb, mm->pgd, mm->mmap,
					     FIRST_USER_ADDRESS, USER_PGTABLES_CEILING);
			tlb_finish_mmu(&tlb, 0, -1);
			pgd_free(mm, policy->stacks[i]);
		}
		mm->pgd = orig_pgd;
		kfree(policy->stacks);
	}


	list_for_each_entry_safe(data_transition, ndata_transition, &policy->data_transitions_list, list)
		kfree(data_transition);

	list_for_each_entry_safe(call_transition, ncall_transition, &policy->call_transitions_list, list)
		kfree(call_transition);

	spin_unlock_irqrestore(&policy->lock, flags);
}

int elfbac_policy_clone(struct mm_struct *mm, struct elfbac_policy *orig, struct elfbac_policy *new)
{
	int retval;

	unsigned long flags;
	struct elfbac_state *state, *new_state = NULL;
	struct elfbac_section *section, *new_section = NULL;
	struct elfbac_data_transition *data_transition, *new_data_transition = NULL;
	struct elfbac_call_transition *call_transition, *new_call_transition = NULL;

	spin_lock_irqsave(&orig->lock, flags);

	spin_lock_init(&new->lock);
	spin_lock(&new->lock);

	INIT_LIST_HEAD(&new->states_list);
	INIT_LIST_HEAD(&new->data_transitions_list);
	INIT_LIST_HEAD(&new->call_transitions_list);
	new->stacks = NULL;

	new->num_stacks = orig->num_stacks;

	list_for_each_entry(state, &orig->states_list, list) {
		retval = -ENOMEM;
		new_state = kmalloc(sizeof(struct elfbac_state), GFP_KERNEL);

		if (!new_state)
			goto err;

		memset(new_state, '\0', sizeof(struct elfbac_state));

		new_state->id = state->id;
		new_state->return_state_id = state->return_state_id;
		INIT_LIST_HEAD(&new_state->list);
		INIT_LIST_HEAD(&new_state->sections_list);
		list_add_tail(&state->list, &new->states_list);

		if (new_state->id == orig->current_state->id)
			new->current_state = new_state;

		list_for_each_entry(section, &state->sections_list, list) {
			retval = -ENOMEM;
			new_section = kmalloc(sizeof(struct elfbac_section),
					    GFP_KERNEL);

			if (!new_section)
				goto err;

			memcpy(new_section, section,
			       sizeof(struct elfbac_section));

			INIT_LIST_HEAD(&new_section->list);
			list_add_tail(&section->list, &new_state->sections_list);

			new_section = NULL;
		}

		new_state = NULL;

	}

	list_for_each_entry(data_transition, &orig->data_transitions_list, list) {
		retval = -ENOMEM;
		new_data_transition = kmalloc(sizeof(struct elfbac_data_transition),
				    GFP_KERNEL);

		if (!new_data_transition)
			goto err;

		memcpy(new_data_transition, data_transition,
		       sizeof(struct elfbac_data_transition));

		INIT_LIST_HEAD(&new_data_transition->list);
		list_add_tail(&new_data_transition->list,
			      &new->data_transitions_list);

		new_data_transition = NULL;
	}

	list_for_each_entry(call_transition, &orig->call_transitions_list, list) {
		retval = -ENOMEM;
		new_call_transition = kmalloc(sizeof(struct elfbac_call_transition),
				    GFP_KERNEL);

		if (!new_call_transition)
			goto err;

		memcpy(new_call_transition, call_transition,
		       sizeof(struct elfbac_call_transition));

		INIT_LIST_HEAD(&new_call_transition->list);
		list_add_tail(&new_call_transition->list,
			      &new->call_transitions_list);

		new_call_transition = NULL;
	}

	retval = -EINVAL;
	if (new->num_stacks < 1 || new->num_stacks >= ELFBAC_NUM_STATES_MAX)
		goto err;

	retval = -ENOMEM;
	new->stacks = kmalloc(sizeof(pgd_t *) * new->num_stacks, GFP_KERNEL);
	if (!new->stacks)
		goto err;
	memset(&new->stacks, '\0', sizeof(pgd_t *) * new->num_stacks);

	spin_unlock(&new->lock);
	spin_unlock_irqrestore(&orig->lock, flags);

	return 0;

err:
	elfbac_policy_destroy(mm, new);
	kfree(new_state);
	kfree(new_section);
	kfree(new_data_transition);
	kfree(new_call_transition);
	spin_unlock(&new->lock);
	spin_unlock_irqrestore(&orig->lock, flags);

	return retval;
}

static struct elfbac_state *get_state_by_id(struct elfbac_policy *policy, unsigned long id)
{
	struct elfbac_state *state;

	list_for_each_entry(state, &policy->states_list, list)
		if (id-- == 0)
			return state;

	return NULL;
}

bool elfbac_access_ok(struct elfbac_policy *policy, unsigned long addr,
		      unsigned int mask, unsigned long lr,
		      struct elfbac_state **next_state, unsigned long *flags,
		      unsigned long *copy_size)
{
	unsigned long start, end;
	struct elfbac_state *state;
	struct elfbac_section *section;
	struct elfbac_data_transition *data_transition;
	struct elfbac_call_transition *call_transition;

	*next_state = NULL;
	*flags = 0;
	*copy_size = 0;

	// Check for return from a call transition
	// TODO: Need 1 return_state_id per state per task for shared policies
	if ((mask & VM_EXEC) && addr == (policy->current_state->return_addr & ~1) &&
	    policy->current_state->return_state_id != ELFBAC_UNDEFINED_STATE_ID) {
		state = get_state_by_id(policy, policy->current_state->return_state_id);
		if (state) {
			*copy_size = policy->current_state->return_size;
			*next_state = state;
			policy->current_state->return_addr = 0;
			policy->current_state->return_size = 0;
			policy->current_state->return_state_id = ELFBAC_UNDEFINED_STATE_ID;
			goto good_transition;
		}
	}

	// Common case, addr is allowed in current state
	list_for_each_entry(section, &policy->current_state->sections_list, list) {
		start = section->base;
		end = start + section->size;

		if ((section->flags & mask) && addr >= start && addr <= end) {
			*flags = section->flags;
			return true;
		}
	}

	// Check for normal state transitions (call and data)
	if (mask & VM_EXEC) {
		list_for_each_entry(call_transition, &policy->call_transitions_list, list) {
			if (call_transition->from == policy->current_state->id) {
				state = get_state_by_id(policy, call_transition->to);

				if (!state)
					continue;

				// Don't allow calling back into a previous
				// state, need to maintain internal per-state
				// stack if this is wanted
				if ((call_transition->addr & ~1) == addr && state->return_addr == 0) {
					*next_state = state;
					*copy_size = call_transition->param_size;
					state->return_addr = lr & ~1;
					state->return_size = call_transition->return_size;
					state->return_state_id = policy->current_state->id;
					goto good_transition;
				}
			}
		}
	} else {
		list_for_each_entry(data_transition, &policy->data_transitions_list, list) {
			if (data_transition->from == policy->current_state->id) {
				start = data_transition->base;
				end = start + data_transition->size;

				state = get_state_by_id(policy, data_transition->to);

				if (!state)
					continue;

				if ((data_transition->flags & mask) && addr >= start && addr <= end) {
					*next_state = state;
					goto good_transition;
				}
			}
		}
	}

	return false;

good_transition:
	list_for_each_entry(section, &(*next_state)->sections_list, list) {
		start = section->base;
		end = start + section->size;

		if ((section->flags & mask) && addr >= start && addr <= end) {
			*flags = section->flags;
			return true;
		}
	}

	return false;
}

