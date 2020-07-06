
CFLAGS = -Wno-error=unused-function -O1 -g -std=c89 -Wall -Wextra -Werror -Wstrict-prototypes -Wold-style-definition -Wmissing-prototypes -Wmissing-declarations -Wdeclaration-after-statement

OBJS = io.o parse.o cursor.o describe.o serve.o client.o

protoverse: protoverse.c $(OBJS)
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@

libprotoverse.a: $(OBJS)
	ar rcs $@ $^

clean:
	rm -f protoverse *.o

TAGS: fake
	etags *.c *.h > $@


.PHONY: fake
