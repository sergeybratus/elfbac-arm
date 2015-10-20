CC := arm-linux-gnueabihf-gcc
CFLAGS := -O0
OBJS := parser.o main.o

all: parser_pol parser_nopol

parser_pol: $(OBJS) policy.json
	../../elfbac-ld.py -v -c -l $(CC) -p policy.json -- -static $(OBJS) -o parser_pol

parser_nopol: $(OBJS)
	$(CC) -static $(OBJS) $(LIBS) -o parser_nopol

-include $(OBJS:.o=.d)

%.o: %.c
	$(CC) -c $(CFLAGS) $*.c -o $*.o
	$(CC) -MM $(CFLAGS) $*.c > $*.d

clean:
	@-rm -rf parser_pol parser_nopol *.o *.d

.PHONY: all clean
