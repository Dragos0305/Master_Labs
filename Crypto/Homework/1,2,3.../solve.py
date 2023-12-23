from pwn import *

IP = "141.85.224.119"
PORT = 9776

ciphertexts = []
remote_process = remote(IP, PORT)
remote_process.recv()

payload = 64 * b'A'

for i in range(64):
    remote_process.sendline(b"2")
    remote_process.recv().decode()
    remote_process.sendline(payload)
    ciphertexts.append(remote_process.recvline().decode().split(" ")[2])
    print(i, remote_process.recv().decode())


remote_process.sendline(b"1")
flag = remote_process.recv().decode().split(":")[1].split("\n")[0]
flag = bytes.fromhex(flag)

ciphertext = bytes.fromhex(ciphertexts[0][:76])
first_xor = xor(flag, ciphertext)
second_xor = xor(first_xor, payload[:38])
print(second_xor.decode())


