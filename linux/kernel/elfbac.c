#include <asm/mmu_context.h>
#include <asm/pgalloc.h>

#include <linux/list.h>
#include <linux/mm.h>
#include <linux/resource.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include <linux/elfbac.h>

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

	state->pgd = NULL;
	memset(&state->context, 0, sizeof(mm_context_t));

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
	if (parse_ulong(buf, size, &data_transition->to) != 0)
		return -EINVAL;
	if (parse_ulong(buf, size, &data_transition->from) != 0)
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
	if (parse_ulong(buf, size, &call_transition->to) != 0)
		return -EINVAL;
	if (parse_ulong(buf, size, &call_transition->from) != 0)
		return -EINVAL;
	if (parse_ulong(buf, size, &call_transition->address) != 0)
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
	struct elfbac_state *state = NULL;
	struct elfbac_section *section = NULL;
	struct elfbac_data_transition *data_transition = NULL;
	struct elfbac_call_transition *call_transition = NULL;

	list_for_each_entry(state, &policy->states_list, list) {
		if (state->stack_id >= policy->num_stacks)
			return -EINVAL;

		num_states++;

		list_for_each_entry(section, &state->sections_list, list) {
			if (section->flags & VM_WRITE && !access_ok(VERIFY_WRITE,
								      (void *)section->base,
								      section->size))
				return -EINVAL;
			else if (!access_ok(VERIFY_READ, (void *)section->base,
					    section->size))
				return -EINVAL;
		}

	}

	if (num_states == 0)
		return -EINVAL;

	if (policy->num_stacks > num_states)
		return -EINVAL;

	list_for_each_entry(data_transition, &policy->data_transitions_list, list) {
		if (data_transition->from > num_states ||
		    data_transition->to > num_states)
			return -EINVAL;

		if (data_transition->flags & VM_WRITE && !access_ok(VERIFY_WRITE,
								      (void *)data_transition->base,
								      data_transition->size))
			return -EINVAL;
		else if (!access_ok(VERIFY_READ, (void *)data_transition->base,
				    data_transition->size))
			return -EINVAL;
	}

	list_for_each_entry(call_transition, &policy->call_transitions_list, list) {
		if (call_transition->from > num_states ||
		    call_transition->to > num_states)
			return -EINVAL;

		if (!access_ok(VERIFY_READ, (void *)call_transition->address,
			       sizeof(unsigned long)))
			return -EINVAL;
	}

	return 0;
}

int elfbac_parse_policy(unsigned char *buf, size_t size,
			struct elfbac_policy *out)
{
	enum {
		STATE = 1,
		SECTION,
		DATA_TRANSITION,
		CALL_TRANSITION
	} type;

	int retval;
	unsigned long cur_state_id = 0;

	struct elfbac_policy policy;
	struct elfbac_state *state = NULL;
	struct elfbac_section *section = NULL;
	struct elfbac_data_transition *data_transition = NULL;
	struct elfbac_call_transition *call_transition = NULL;

	INIT_LIST_HEAD(&policy.states_list);
	INIT_LIST_HEAD(&policy.data_transitions_list);
	INIT_LIST_HEAD(&policy.call_transitions_list);

	retval = -EINVAL;
	if (parse_ulong(&buf, &size, &policy.num_stacks) != 0)
		goto out;

	while (size) {
		retval = -EINVAL;
		if (parse_ulong(&buf, &size, (unsigned long *)&type) != 0)
			goto out;

		switch (type) {
		case STATE:
			retval = -ENOMEM;
			state = kmalloc(sizeof(struct elfbac_state),
					GFP_KERNEL);
			if (!state)
				goto out;

			retval = elfbac_parse_state(&buf, &size, state);
			if (retval != 0)
				goto out;

			state->id = cur_state_id++;
			state->pgd = NULL;
			INIT_LIST_HEAD(&state->sections_list);
			list_add_tail(&state->list, &policy.states_list);
			state = NULL;
			break;
		case SECTION:
			if (list_empty(&policy.states_list))
				goto out;
			state = list_last_entry(&policy.states_list,
						struct elfbac_state,
						list);

			retval = -ENOMEM;
			section = kmalloc(sizeof(struct elfbac_section),
					  GFP_KERNEL);
			if (!section)
				goto out;

			retval = elfbac_parse_section(&buf, &size, section);
			if (retval != 0)
				goto out;

			list_add_tail(&section->list, &state->sections_list);
			state = NULL;
			section = NULL;
			break;
		case DATA_TRANSITION:
			retval = -ENOMEM;
			data_transition = kmalloc(
						  sizeof(struct elfbac_data_transition),
						  GFP_KERNEL);
			if (!data_transition)
				goto out;

			retval = elfbac_parse_data_transition(&buf, &size,
							      data_transition);
			if (retval != 0)
				goto out;

			list_add_tail(&data_transition->list, &policy.data_transitions_list);
			data_transition = NULL;
			break;
		case CALL_TRANSITION:
			retval = -ENOMEM;
			call_transition = kmalloc(
						  sizeof(struct elfbac_call_transition),
						  GFP_KERNEL);
			if (!call_transition)
				goto out;

			retval = elfbac_parse_call_transition(&buf, &size,
							      call_transition);
			if (retval != 0)
				goto out;

			list_add_tail(&call_transition->list, &policy.call_transitions_list);
			call_transition = NULL;
			break;
		default:
			goto out;
		}
	}

	retval = -EINVAL;
	if (elfbac_validate_policy(&policy) != 0)
		goto out;

	// TODO: Figure out stacks

	policy.current_state = list_entry(policy.states_list.next,
					  struct elfbac_state, list);
	*out = policy;
	retval = 0;

out:
	elfbac_policy_destroy(&policy);
	kfree(state);
	kfree(section);
	kfree(data_transition);
	kfree(call_transition);
	return retval;
}

void elfbac_policy_destroy(struct elfbac_policy *policy)
{

}

int elfbac_policy_clone(struct elfbac_policy *orig, struct elfbac_policy *new)
{
	return 0;
}

bool elfbac_access_ok(struct elfbac_policy *policy, unsigned long address,
		      unsigned int mask, struct elfbac_state **next_state)
{

	// For now, don't deny any requests
	*next_state = NULL;
	return true;
}

int elfbac_copy_mapping(struct elfbac_policy *policy, struct mm_struct *mm,
			struct vm_area_struct *vma, pte_t pte,
			unsigned long address)
{
	// Very similar to __handle_mm_fault from mm/memory.c
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *ptep;

	pgd = policy->current_state->pgd;
	pud = pud_alloc(mm, pgd, address);
	if (!pud)
		return VM_FAULT_OOM;
	pmd = pmd_alloc(mm, pud, address);
	if (!pmd)
		return VM_FAULT_OOM;

	// TODO: Figure out the hugepages stuff which may need to happen
	ptep = pte_alloc_map(mm, vma, pmd, address);
	set_pte_at(mm, address, ptep, pte);

	return 0;
}

