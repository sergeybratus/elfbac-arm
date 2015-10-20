CC := arm-linux-gnueabihf-gcc
CFLAGS := -O0
OBJS := libc.o main.o
LIBS := 

all: simple_pol simple_nopol

simple_pol: $(OBJS) policy.json
	../../elfbac-ld.py -v -c -l $(CC) -p policy.json -- -nostdlib -static $(OBJS) $(LIBS) -o simple_pol

simple_nopol: $(OBJS)
	$(CC) -nostdlib -static $(OBJS) $(LIBS) -o simple_nopol -Wl,-verbose

-include $(OBJS:.o=.d)

%.o: %.c
	$(CC) -c $(CFLAGS) $*.c -o $*.o
	$(CC) -MM $(CFLAGS) $*.c > $*.d

%.o: %.S
	$(CC) -c $(CFLAGS) $*.S -o $*.o
	$(CC) -MM $(CFLAGS) $*.S > $*.d

clean:
	@-rm -rf simple_pol simple_nopol *.o *.d

.PHONY: all clean
