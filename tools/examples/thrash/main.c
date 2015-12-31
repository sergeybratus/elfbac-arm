#include <stdio.h>

#include "libc.h"

__attribute__((section(".data.buf")))
char buf[256];

void
_start(void)
{
    int i;
    for (i = 0; i < 5; i++) {
        if (read(0, buf, sizeof(buf)) < 0)
            _exit(-1);
        if (write(1, buf, sizeof(buf)) < 0)
            _exit(-1);
    }
    _exit(0);
}

