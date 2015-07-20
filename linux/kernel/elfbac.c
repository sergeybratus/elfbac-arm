#include <linux/elfbac.h>

struct elfbac_state { };
struct elfbac_section { };
struct elfbac_transition { };

static int parse_elfbac_state(unsigned char *buf, size_t *size,
		struct elfbac_state *state)
{

	return 0;
}

static int parse_elfbac_section(unsigned char *buf, size_t *size,
		struct elfbac_section *section)
{

	return 0;
}

static int parse_elfbac_transition(unsigned char *buf, size_t *size,
		struct elfbac_transition *transition)
{
	return 0;
}

int parse_elfbac_policy(unsigned char *policy, size_t size)
{

	return 0;
}

