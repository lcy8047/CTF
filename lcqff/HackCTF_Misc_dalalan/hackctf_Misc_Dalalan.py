#Hack-ctf misk 달라란 침공


from pwn import *
r = remote("ctf.j0n9hyun.xyz",9003)
d = r.recv()
print(d.decode('utf-8')) #우리 악당들이 모여 달라란을 차지하자!
d = r.recv()
print(d.decode('utf-8')) # 문제 1) ,2), 3)
r.sendline(b'\x31') #'1' 입력

for i in range(20):
    d = r.recvuntil(b'\n') #뭐였는지 기억안남
    print(d.decode('utf-8'))


    d = r.recvline() #공식받아오기
    formula = d.decode('utf-8');
    answer = eval(formula);
    r.sendline(str(answer)); #string으로 보내주기


    d = r.recvuntil(b'\n') #침공 결과
    print('\n'+d.decode('utf-8'))



#2)

d = r.recvuntil('input )')
print(d.decode('utf-8'))
r.sendline('2')

for i in range(30):
    d = r.recvuntil(b'\n') #:까지
    print(d.decode('utf-8'))

    d = r.recvline() #공식
    formula = d.decode('utf-8');
    answer = eval(formula);
    r.sendline(str(int(answer))); #string으로 보내주기

    d = r.recvuntil(b'\n') #침공 결과
    print('\n'+d.decode('utf-8'))


#3)
d = r.recvuntil('input )')
print(d.decode('utf-8'))
r.sendline('3') #그냥 '1'보내도 됨

for i in range(40):
    d = r.recvuntil(b'\n') #:까지
    print(d.decode('utf-8'))

    d = r.recvline() #공식
    formula = d.decode('utf-8');
    answer = eval(formula);
    r.sendline(str(int(answer))); #string으로 보내주기

    d = r.recvuntil(b'\n') #침공 결과
    print('\n'+d.decode('utf-8'))

d = r.recvuntil(b'\n') #침공 결과
print('\n'+d.decode('utf-8'))
r.interactive()
