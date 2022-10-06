import hashlib
from Crypto.Util.number import *
from math import gcd

p = pow(2, 1024) + 643

with open("my-signature", "rb") as f:
    sig = f.read()

g0 = bytes_to_long(sig[256*0:256*1])
r0 = bytes_to_long(sig[256*1:256*2])
s0 = bytes_to_long(sig[256*2:256*3])
# get the hash by running the challenge
h0 = 73364709830763917388310523356926131622285580104266471737308980031746716844740

g1 = bytes_to_long(sig[256*3:256*4])
r1 = bytes_to_long(sig[256*4:256*5])
s1 = bytes_to_long(sig[256*5:256*6])
h1 = 58689353063978552222534415081160953701655523813434362867556819824364338369170

zaehler = (s1 * h0 - s0 * h1) % (p - 1)
nenner = (s1 * r0 - s0 * r1) % (p - 1) 

ggt = gcd(zaehler, p-1)
ggt = gcd(nenner, p-1)

zaehler = zaehler // ggt
nenner = nenner // ggt
p_1 = (p-1) // ggt

ans = (zaehler * pow(nenner, -1, p_1)) % (p_1)
# print(f'{ans=}')

for t in range(ggt):
    x = ans + t * (p_1)
    x_l = long_to_bytes(x)
    flag = x_l[-32:]
    if flag.startswith(b'EPFL'):
        flag = flag.decode()
        print(f'{t=}, {flag=}')

# t=186, flag='EPFL{PzuUw&ILdy7@5II1vTQX3DcL3f<'
# t=469, flag='EPFL{PzuUw&ILdy7@5II1vTQX3DcL3g}'
