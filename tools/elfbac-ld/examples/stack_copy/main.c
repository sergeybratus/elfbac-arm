#include "foo.h"
#include "libc.h"

__attribute__((section(".data.buf")))
char buf[256];

__attribute__((section(".data.stack_chk_guard")))
unsigned long __stack_chk_guard;

__attribute__((section(".data.xxx")))
char xxx[] = "xxx!\n";

__attribute__((section(".data.yyy")))
char yyy[] = "yyy!\n";

void
_start(void)
{
    struct foo baz;

    read(0, buf, sizeof(buf));
    write(1, buf, sizeof(buf));

    baz = bar(0, 1, 2, 3, 4, 5);

    if (baz.f == 10)
        write(1, xxx, sizeof(xxx));
    else
        write(1, yyy, sizeof(yyy));

    _exit(0);
}

