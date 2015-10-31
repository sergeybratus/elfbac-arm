CC := arm-linux-gnueabihf-gcc
CFLAGS := -O0 -marm
OBJS := libc.o read.o write.o exit.o main.o
LIBS := 

all: thrash_pol thrash_nopol

thrash_pol: $(OBJS) policy.json
	../../elfbac-ld.py -v -c -l $(CC) -p policy.json -- -nostdlib -static $(OBJS) $(LIBS) -o thrash_pol

thrash_nopol: $(OBJS)
	$(CC) -nostdlib -static $(OBJS) $(LIBS) -o thrash_nopol

-include $(OBJS:.o=.d)

%.o: %.c
	$(CC) -c $(CFLAGS) $*.c -o $*.o
	$(CC) -MM $(CFLAGS) $*.c > $*.d

%.o: %.S
	$(CC) -c $(CFLAGS) $*.S -o $*.o
	$(CC) -MM $(CFLAGS) $*.S > $*.d

clean:
	@-rm -rf thrash_pol thrash_nopol *.o *.d

.PHONY: all clean
