#include "libc.h"
#include "sum.h"

void
_start(void)
{
    int i, ret = 0;
    for (i = 0; i < 0xffff; i++)
        ret += sum(i);
    _exit(ret);
}

