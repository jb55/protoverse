
CFLAGS = -Wno-error=unused-function -O2 -g -std=gnu90 -Wall -Wextra -Werror \
	 -Wstrict-prototypes -Wold-style-definition -Wmissing-prototypes \
	 -Wmissing-declarations -Wdeclaration-after-statement -fno-stack-protector

OBJS = src/io.o \
       src/parse.o \
       src/describe.o \
       src/serve.o \
       src/client.o \
       src/net.o \
       src/varint.o \
       src/parser.o \
       src/error.o \
       src/wasm.o

SRCS=$(OBJS:.o=.c)

WASMS = wasm/hello-c.wasm \
	wasm/hello.wasm

all: protoverse bench test libprotoverse.a

noinline: CFLAGS += -DNOINLINE
noinline: all

debug: CFLAGS += -DDEBUG
debug: all

wasm: $(WASMS)

%.o: %.c %.h
	@echo "cc $<"
	@$(CC) -c -o $@ $(CPPFLAGS) $(CFLAGS) $<

%.wasm: %.wat
	wat2wasm $^ -o $@

%.c.wasm: %.wasm.c
	emcc -g $< -s WASM=1 -o $@

wasm/hello-c.wasm: wasm/hello-c.c
	emcc -g $< -s WASM=1 -o $@

protoverse.wasm: src/protoverse.c $(SRCS)
	emcc -g $^ -s WASM=1 -o $@

protoverse: src/protoverse.c $(OBJS)
	@echo "ld $@"
	@$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@

libprotoverse.a: $(OBJS)
	ar rcs $@ $^

bench: src/bench.c $(OBJS)
	@echo "ld $@"
	@$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@

clean:
	rm -f protoverse test $(OBJS) libprotoverse.a

test: src/test.c $(OBJS)
	@echo "ld $@"
	@$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@

check: test
	@./test

tags: fake
	ctags src/*.c src/*.h > $@

TAGS: fake
	etags src/*.c src/*.h > $@


.PHONY: fake
