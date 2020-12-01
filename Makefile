
CFLAGS = -Wno-error=unused-function -Ofast -std=gnu90 -Wall -Wextra -Werror -Wstrict-prototypes -Wold-style-definition -Wmissing-prototypes -Wmissing-declarations -Wdeclaration-after-statement

OBJS = src/io.o \
       src/parse.o \
       src/describe.o \
       src/serve.o \
       src/client.o \
       src/net.o \
       src/varint.o \
       src/parser.o \
       src/wasm.o

WASMS = wasm/hello-c.wasm \
	wasm/hello.wasm

all: protoverse libprotoverse.a

wasm: $(WASMS)

%.o: %.c %.h
	@echo "cc $<"
	@$(CC) -c -o $@ $(CPPFLAGS) $(CFLAGS) $<

%.wasm: %.wat
	wat2wasm $^ -o $@

wasm/hello-c.wasm: wasm/hello-c.c
	emcc $< -s WASM=1 -o $@

protoverse: src/protoverse.c $(OBJS)
	@echo "ld $@"
	@$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@

libprotoverse.a: $(OBJS)
	ar rcs $@ $^

clean:
	rm -f protoverse test $(OBJS) libprotoverse.a $(WASMS)

test: src/test.c $(OBJS)
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@

check: test
	@./test

tags: fake
	ctags src/*.c src/*.h > $@

TAGS: fake
	etags src/*.c src/*.h > $@


.PHONY: fake
