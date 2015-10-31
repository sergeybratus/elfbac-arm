CC := arm-linux-gnueabihf-gcc
CFLAGS := -O0 -marm
OBJS := libc.o main.o
LIBS := 

all: loop_pol loop_nopol

loop_pol: $(OBJS) policy.json
	../../elfbac-ld.py -c -l $(CC) -p policy.json -- -nostdlib -static $(OBJS) $(LIBS) -o loop_pol

loop_nopol: $(OBJS)
	$(CC) -nostdlib -static $(OBJS) $(LIBS) -o loop_nopol

-include $(OBJS:.o=.d)

%.o: %.c
	$(CC) -c $(CFLAGS) $*.c -o $*.o
	$(CC) -MM $(CFLAGS) $*.c > $*.d

%.o: %.S
	$(CC) -c $(CFLAGS) $*.S -o $*.o
	$(CC) -MM $(CFLAGS) $*.S > $*.d

clean:
	@-rm -rf loop_pol loop_nopol *.o *.d

.PHONY: all clean
