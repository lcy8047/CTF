f = open("hoooo.txt", "r")

string = f.read().split()

flag=""

for s in string:
    flag += chr(int('0b'+s, 2))

print(flag)