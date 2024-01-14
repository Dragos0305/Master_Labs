.PHONY: all clean

all: open.bin

open.bin: open.asm
	nasm -o $@ $^

print: open.bin
	@hexdump -v -e '"\\" 1/1 "x%02x"' $^ ; echo

clean:
	-rm -f open.bin *~
