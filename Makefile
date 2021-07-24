
CFLAGS = -O2 -g -std=gnu90 -Wall -Wextra -Werror \
	 -Wold-style-definition -Wmissing-prototypes \
	 -Wmissing-declarations -Wdeclaration-after-statement \
	 -Wno-strict-prototypes -Wno-old-style-definition \
	 -Wno-unused-function \
	 $(shell pkg-config --cflags sdl2)

LDFLAGS = $(shell pkg-config --libs sdl2) -lm -ldl

OBJS = src/io.o \
       src/parse.o \
       src/describe.o \
       src/gl.o \
       src/serve.o \
       src/client.o \
       src/net.o \
       src/varint.o \
       src/error.o \
       src/wasm.o

HEADS = src/wasm_gfx.h

SRCS=$(OBJS:.o=.c)

WASMS = wasm/hello-c.wasm \
	wasm/hello.wasm

all: protoverse bench test examples

noinline: CFLAGS += -DNOINLINE
noinline: all

debug: CFLAGS += -DDEBUG
debug: all

examples: examples/server

wasm: $(WASMS)

src/wasm.o: src/wasm.c src/wasm_gfx.h
	@echo "cc $<"
	@$(CC) -c -o $@ $(CPPFLAGS) $(CFLAGS) $<

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
	emcc -g $^ -s WASM=1 -s ERROR_ON_UNDEFINED_SYMBOLS=0 -o $@

protoverse: src/protoverse.c $(OBJS) $(HEADS)
	@echo "ld $@"
	@$(CC) $(CFLAGS) src/protoverse.c $(OBJS) $(LDFLAGS) -o $@

examples/server: examples/server.c libprotoverse.a
	$(CC) -Isrc $(CFLAGS) $^ -o $@

libprotoverse.a: $(OBJS)
	ar rcs $@ $^

bench: src/bench.c $(OBJS)
	@echo "ld $@"
	@$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@

clean:
	rm -f protoverse test $(OBJS) libprotoverse.a

test: src/test.c $(OBJS) $(HEADS)
	@echo "ld $@"
	@$(CC) $(CFLAGS) src/test.c $(OBJS) $(LDFLAGS) -o $@

check: test protoverse
	@./test
	./runtests

tags: fake
	ctags src/*.c src/*.h > $@

TAGS: fake
	etags src/*.c src/*.h > $@


.PHONY: fake
