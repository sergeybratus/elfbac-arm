#include "libc.h"
#include "sum.h"

void
_start(void)
{
    _exit(sum((unsigned int)-1));
}

