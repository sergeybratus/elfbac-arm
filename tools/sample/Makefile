CC := arm-linux-gnueabihf-gcc
CFLAGS := -O0
OBJS := parser.o main.o

test: $(OBJS)
	../elfbac-ld.py -c -l $(CC) -p policy.json -- -static $(OBJS) -o sample

-include $(OBJS:.o=.d)

%.o: %.c
	$(CC) -c $(CFLAGS) $*.c -o $*.o
	$(CC) -MM $(CFLAGS) $*.c > $*.d

clean:
	@-rm -rf sample *.o *.d

