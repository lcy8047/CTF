from pwn import *

'''
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
'''

context(arch='amd64', os='linux')

# 소스코드를 분석해보면 srand와 time을 사용해 random값을 만들었다
# 문제서버가 같은 한국시간대를 사용했을거라 추측하고 
# 내 로컬 시간대를 맞추고 똑같이 random값을 생성하는 프로그램을 만들었다
# 같은 시간에 생성한 랜덤값은 같으므로 
# 받아온 값을 입력했다.

r = remote("ctf.j0n9hyun.xyz", 3014)
rand = process("./makeRand")

rand_value = rand.recvline()

r.send(rand_value)

r.interactive()