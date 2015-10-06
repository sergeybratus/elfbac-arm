#include <stdio.h>

#include "parser.h"

__attribute__((section(".data.parse_result")))
int parse_result;

int
main(void)
{
    do_parse(&parse_result);
    printf("%d\n", parse_result);
    return 0;
}

