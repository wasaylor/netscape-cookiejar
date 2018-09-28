CC ?= clang
CFLAGS ?= -Wall -std=c11 -O2 -march=native

all: clean netscape-cookiejar

netscape-cookiejar: src/main.c src/cookiejar.c src/SetCookie.c
	$(CC) $(CFLAGS) -DCOOKIEJAR_FAST_BOOLS -o$@ $^

clean:
	rm -f netscape-cookiejar
