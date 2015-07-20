#ifndef __LINUX_ELFBAC_H
#define __LINUX_ELFBAC_H

#include <linux/elf.h>

/* Define an upper bound on policy size to prevent exhausting kernel resources,
 * can re-examine this later. */
#define ELFBAC_POLICY_SIZE_MAX (PAGE_SIZE * 10)

#define PT_ELFBAC_POLICY (PT_LOOS + 0xfe7fbac)

int parse_elfbac_policy(unsigned char *policy, size_t size);

#endif /* ! __LINUX_ELFBAC_H */

