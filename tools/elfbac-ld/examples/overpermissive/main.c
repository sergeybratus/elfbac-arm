#include "libc.h"

__attribute__((section(".data.buf")))
char buf[256];

void
_start(void)
{
    read(0, buf, sizeof(buf));
    write(1, buf, foo(sizeof(buf), 0));
    *((unsigned int *)foo) = 0xdeadbeef;
    _exit(0);
}

__attribute__((section(".text.jit")))
int
foo(int a, int b)
{
    return a + b;
}
