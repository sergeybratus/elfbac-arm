/* Syscall wrappers from bionic */

#include <asm/unistd.h> /* For system call numbers. */

#define __bionic_asm_align 0

#undef __bionic_asm_custom_entry
#undef __bionic_asm_custom_end
#define __bionic_asm_custom_entry(f) .fnstart
#define __bionic_asm_custom_end(f) .fnend

#undef __bionic_asm_function_type
#define __bionic_asm_function_type #function

#define ENTRY_NO_DWARF(f) \
    .text; \
    .globl f; \
    .align __bionic_asm_align; \
    .type f, __bionic_asm_function_type; \
    f: \
    __bionic_asm_custom_entry(f); \

#define ENTRY(f) \
    ENTRY_NO_DWARF(f) \
    .cfi_startproc \

#define END_NO_DWARF(f) \
    .size f, .-f; \
    __bionic_asm_custom_end(f) \

#define END(f) \
    .cfi_endproc; \
    END_NO_DWARF(f) \

ENTRY(read)
    mov     ip, r7
    ldr     r7, =__NR_read
    swi     #0
    mov     r7, ip
    bx      lr
END(read)

ENTRY(write)
    mov     ip, r7
    ldr     r7, =__NR_write
    swi     #0
    mov     r7, ip
    bx      lr
END(write)

ENTRY(_exit)
    mov     ip, r7
    ldr     r7, =__NR_exit_group
    swi     #0
    mov     r7, ip
    bx      lr
END(_exit)

ENTRY(__aeabi_unwind_cpp_pr0)
END(__aeabi_unwind_cpp_pr0)

