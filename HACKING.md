# Hacking on ELFbac

Need to make some bookkeeping data not per-mm\_struct but per-task\_struct to be
support multithreaded programs properly, each thread can / most likely will be
running in their own ELFbac states most of the time, so need a per-task copy of
e.g. current\_state, return\_state, etc. Essentially need to separate out the
policy data from the execution state data, keeping the policy shared between all
tasks sharing the same address space but allowing the current execution state to
be per-task.

Need to support labeling newly-mmapped pages with ELFbac permissions, this is
tricky as it introduces the idea of a program modifying its own ELFbac policy.
Need to ensure that all pages are label-once to prevent malicious relabeling at
a minimum, which leads to questions of how to safely unmap pages and then remap
them from e.g. userspace malloc. Need to ensure that, if we don't introduce a
new, ELFbac aware mmap/munmap which takes a label immediately that we don't
introduce race conditions where a thread can relabel memory acquired from
another thread out from under it. Also would make sense to limit which ELFbac
states are allowed to invoke mmap/munmap/mprotect etc, which can likely be
accomplished with per-state seccomp filters or a similar mechanism.

ELFbac-aware versions of the dynamic loader / malloc in userspace are also
needed, the implementation of which should be relatively straightforward once
ELFbac-aware mmap exists.
