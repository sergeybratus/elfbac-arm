CC := arm-linux-gnueabihf-gcc
CFLAGS := -O0 -marm
OBJS := libc.o exit.o main.o sum.o
LIBS := 

all: sum_pol sum_nopol

sum_pol: $(OBJS) policy.json
	../../elfbac-ld.py -v -c -l $(CC) -p policy.json -- -nostdlib -static $(OBJS) $(LIBS) -o sum_pol

sum_nopol: $(OBJS)
	$(CC) -nostdlib -static $(OBJS) $(LIBS) -o sum_nopol

-include $(OBJS:.o=.d)

%.o: %.c
	$(CC) -c $(CFLAGS) $*.c -o $*.o
	$(CC) -MM $(CFLAGS) $*.c > $*.d

%.o: %.S
	$(CC) -c $(CFLAGS) $*.S -o $*.o
	$(CC) -MM $(CFLAGS) $*.S > $*.d

clean:
	@-rm -rf sum_pol sum_nopol *.o *.d

.PHONY: all clean
