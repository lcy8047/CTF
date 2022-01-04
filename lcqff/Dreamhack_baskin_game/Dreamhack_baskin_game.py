from pwn import *
r = remote("host1.dreamhack.games", 12349)
x = 0
N = 0
C = 0

d = r.recvuntil('Good luck~')
print(d.decode('utf-8')) #goodluck까지 출력

def main():
    d = r.recvuntil('N = ')
    print(d.decode('utf-8'),end = '')

    d = r.recvline() #(숫자1), count = (숫자2)'가 저장됐다.
    print(d.decode('utf-8'))
    num = d.decode('utf-8')
    N = int(num.split(', count = ')[0])
    C = int(num.split(', count = ')[1])
    check_NC ='Check!: N = ' + str(N) + ' count =' + str(C)
    print(check_NC) #위의 d를 출력한 뒤에 출력해야만 출력이 됨;

    r.recvuntil('input your name ->')
    r.sendline('12') #이름으로 12를 보냈다. #이름이 짝수면 user first

    r.recvline() #hi (user)

    last_num = 0

    d = r.recvline() #computer first | user first, 항상 user first여야 한다.


    s = ""
    for i in range(1, (N-1)%(C+1)+1): #필승전법! 제일 처음 시작할때 (n-1)%(C+1)까지의 수를 부른다
        s += str(i)
        s += " "
    print("유저 먼저: user number-> ", end ="")
    print(s)
    r.sendline(s)

    last_num = (N-1)%(C+1)

    x = (N-1)%(C+1) #N-1을 C+1로 나눈 나머지
    print('나머지 = ', x)#확인용

    while last_num <= N-2 :
        last_num = computersTurn(last_num)
        last_num = usersTurn(last_num, x,C) #x는 전역변수로 저장된다. C는 왜 전역에서 못가져 오는지 모르겠음
        if not (last_num <= N-2):
            #while문에서 알아서 탈출을 안함...
            break


    print("끝!")
    print()


def computersTurn(last_num):
    print('users last num = ',str(last_num))

    r.recvuntil('computer say -> ')
    d = r.recvline()
    #print('Check!: computer say ->', d.decode('utf-8'))
    last_num = int(d.split()[-1]) #제일 마지막 수 가져오기
    return last_num

def usersTurn(last_num, x,C):
    print('cumputers last num = ',str(last_num))
    #print('x = ',str(x))
    #print('C = ',str(C))
    d = r.recvuntil('input your number -> ') #input your number
    #print(d.decode('utf-8'))

    while x <= last_num:
        x += (C+1) #첫 시작만 잘했다면 그 이후로는 계속(N-1)%(C+1) + (C+1)*t로 끝내면 된다

    s = ""
    for i in range(last_num+1, x+1):
        s += str(i)
        s += " "

    #print("check!: user number->",s)
    r.sendline(s)

    last_num = x

    return last_num

i = 0
for i in range(31):
    #i += 1
    main()
    print('몇번째?:',i)
r.interactive()

