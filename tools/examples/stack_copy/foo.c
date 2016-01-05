#include "foo.h"

extern unsigned long __stack_chk_guard;

struct foo bar(unsigned long a, unsigned long b, unsigned long c,
        unsigned long d, unsigned long e, unsigned long f) {
    struct foo ret;

    ret.a = a * 2;
    ret.b = b * 2;
    ret.c = c * 2;
    ret.d = d * 2;
    ret.e = e * 2;
    ret.f = f * 2;

    return ret;
}

