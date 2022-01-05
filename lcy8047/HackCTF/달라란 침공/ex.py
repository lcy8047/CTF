from pwn import *

r = remote("ctf.j0n9hyun.xyz", 9003)

def recvline_str():
    print(str(r.recvline(), "utf-8"))


def recv_str():
    print(str(r.recv(), "utf-8"))


def recvuntil_str(s):
    print(str(r.recvuntil(s), "utf-8"))

def recvline():
    return r.recvline()

# 받은 식을 계산해서 결과를 리턴함
# 나눗셈은 몫을 구하는 연산으로 해야하기 때문에
# eval대신 직접 몫 연산으로 수행함
def calc_expr(s):
    s = s.strip()
    s = str(s,"utf-8")
    
    l = s.split(" ")

    if(l[1] == "/"):
        result = int(l[0]) // int(l[2])
    else:
        result = eval(s)
    
    return result

def send_res(n):
    r.sendline(bytes(str(n), "utf-8"))

# 총 3개의 라운드가 있음

for t in range(1,4):
    recvuntil_str("input )")
    recv_str()
    # 먼저 1,2,3 라운드의 각 번호를 input으로 줌
    send_res(t)

    # 라운드마다 반복적인 사칙연산을 수행
    # 1라운드 - 20번, 2라운드 - 30번, 3라운드 - 40번
    for i in range(10*(t+1)):
        recvline_str()
        s = recvline()
        print("expr : ",s)
        result = calc_expr(s)
        print("result : ", result)
        recv_str()
        send_res(result)
        recvline_str()

r.interactive()
