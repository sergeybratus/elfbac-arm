CC := arm-linux-gnueabihf-gcc
CFLAGS := -O0 -marm
OBJS := foo.o libc.o main.o
LIBS :=

all: stack_copy_pol stack_copy_nopol

stack_copy_pol: $(OBJS) policy.json
	../../elfbac-ld.py -v -c -l $(CC) -p policy.json -- -nostdlib -static $(OBJS) $(LIBS) -o stack_copy_pol

stack_copy_nopol: $(OBJS)
	$(CC) -nostdlib -static $(OBJS) $(LIBS) -o stack_copy_nopol

-include $(OBJS:.o=.d)

%.o: %.c
	$(CC) -c $(CFLAGS) $*.c -o $*.o
	$(CC) -MM $(CFLAGS) $*.c > $*.d

%.o: %.S
	$(CC) -c $(CFLAGS) $*.S -o $*.o
	$(CC) -MM $(CFLAGS) $*.S > $*.d

clean:
	@-rm -rf stack_copy_pol stack_copy_nopol *.o *.d

.PHONY: all clean
