#include <linux/list.h>
#include <linux/mman.h>
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
	}

	if (policy->num_stacks > num_states)
		return -EINVAL;

	list_for_each_entry(section, &policy->sections_list, list) {
		if (section->flags & PROT_WRITE && !access_ok(VERIFY_WRITE,
					(void *)section->base, section->size))
			return -EINVAL;
		else if (!access_ok(VERIFY_READ, (void *)section->base,
					section->size))
			return -EINVAL;
	}

	list_for_each_entry(data_transition, &policy->data_transitions_list, list) {
		if (data_transition->from > num_states ||
				data_transition->to > num_states)
			return -EINVAL;

		if (section->flags & PROT_WRITE && !access_ok(VERIFY_WRITE,
					(void *)section->base, section->size))
			return -EINVAL;
		else if (!access_ok(VERIFY_READ, (void *)section->base,
					section->size))
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

	struct elfbac_policy policy;
	struct elfbac_state *state = NULL;
	struct elfbac_section *section = NULL;
	struct elfbac_data_transition *data_transition = NULL;
	struct elfbac_call_transition *call_transition = NULL;

	INIT_LIST_HEAD(&policy.states_list);
	INIT_LIST_HEAD(&policy.sections_list);
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

			list_add_tail(&policy.states_list, &state->list);
			state = NULL;
			break;
		case SECTION:
			retval = -ENOMEM;
			section = kmalloc(sizeof(struct elfbac_section),
					GFP_KERNEL);
			if (!section)
				goto out;

			retval = elfbac_parse_section(&buf, &size, section);
			if (retval != 0)
				goto out;

			list_add_tail(&policy.sections_list, &section->list);
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

			list_add_tail(&policy.data_transitions_list,
					&data_transition->list);
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

			list_add_tail(&policy.call_transitions_list,
					&call_transition->list);
			call_transition = NULL;
			break;
		default:
			goto out;
		}
	}

	retval = -EINVAL;
	if (elfbac_validate_policy(&policy) != 0)
		goto out;

	// TODO: Allocate stacks

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
