all: dop payload

.PHONY: clean

CC = clang-4.0
CFLAGS = -static
#CFLAGS = -fsanitize=safe-stack

dop: dop.c
	$(CC) $(CFLAGS) -o $@ $<

payload: payload.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f dop payload *.o
