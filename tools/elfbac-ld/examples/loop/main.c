#include "libc.h"

__attribute__((section(".data.buf")))
char buf[256];

void
_start(void)
{
    while (1) {
        read(0, buf, sizeof(buf));
        write(1, buf, sizeof(buf));
    }
    _exit(0);
}

