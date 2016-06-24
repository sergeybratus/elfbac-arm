CC := arm-linux-gnueabihf-gcc
CFLAGS := -O0 -marm
OBJS := libc.o main.o
LIBS := 

all: overpermissive_pol overpermissive_nopol

overpermissive_pol: $(OBJS) policy.json
	../../elfbac-ld.py -v -c -l $(CC) -p policy.json -- -nostdlib -static $(OBJS) $(LIBS) -o overpermissive_pol

overpermissive_nopol: $(OBJS)
	$(CC) -nostdlib -static $(OBJS) $(LIBS) -o overpermissive_nopol

-include $(OBJS:.o=.d)

%.o: %.c
	$(CC) -c $(CFLAGS) $*.c -o $*.o
	$(CC) -MM $(CFLAGS) $*.c > $*.d

%.o: %.S
	$(CC) -c $(CFLAGS) $*.S -o $*.o
	$(CC) -MM $(CFLAGS) $*.S > $*.d

clean:
	@-rm -rf overpermissive_pol overpermissive_nopol *.o *.d

.PHONY: all clean
