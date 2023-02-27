from pwn import *
from sage.all import crt

t = remote('lac.tf', 31111)
p = t.recvline().strip()
q = t.recvline().strip()
t.sendlineafter(b'>> ', b'1')
t.sendlineafter(b'Type your modulus here: ', p)
target_p = t.recvline().strip()

t.sendlineafter(b'>> ', b'1')
t.sendlineafter(b'Type your modulus here: ', q)
target_q = t.recvline().strip()

t.sendlineafter(b'>> ', b'2')
for target_m in range(30):
    target = int(crt([int(target_p), int(target_q), target_m], [int(p), int(q), 30]))
    print(f'target={int(target)}')
    t.sendlineafter(b'Type your guess here: ', str(target).encode())
    flag_nope = t.recvline().strip().decode()
    if 'lactf' in flag_nope:
        print(f'flag={flag_nope}')
        exit(0)

# flag=lactf{n0t_$o_l@a@AzY_aNYm0Re}
