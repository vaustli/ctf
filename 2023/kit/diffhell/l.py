from sage.all import GF, Matrix, vector
from pwn import *
import json
import sys
import hashlib
context.log_level = 'error'

def recv_matrix_row(io):
	g = io.recvline().decode().strip()[1:-1].split(' ')
	# print(g)
	r = []
	for _ in g:
		if _ == '':
			continue
		r.append(int(_))
	return r

if sys.argv[1] == 'l':
	io = process(['sage', 'o-challenge.sage'])
else:
	io = remote('diffhell-0.chals.kitctf.de', 1337, ssl = True)

io.recvline()
p = int(io.recvline().decode())
print(f'{p=}')
if sys.argv[1] == 'l':
	r1 = recv_matrix_row(io)
	r2 = recv_matrix_row(io)
	A = Matrix(GF(p), 2, [r1, r2])
	print(f'{A=}')
	r1 = recv_matrix_row(io)
	r2 = recv_matrix_row(io)
	B = Matrix(GF(p), 2, [r1, r2])
	print(f'{B=}')

for _ in range(3):
	io.recvline()

r1 = recv_matrix_row(io)
r2 = recv_matrix_row(io)
G = Matrix(GF(p), 2, [r1, r2])
print(f'{G=}')

io.recvline()
r1 = recv_matrix_row(io)
r2 = recv_matrix_row(io)
gA = Matrix(GF(p), 2, [r1, r2])
print(f'{gA=}')

io.recvline()
r1 = recv_matrix_row(io)
r2 = recv_matrix_row(io)
gB = Matrix(GF(p), 2, [r1, r2])
print(f'{gB=}')

io.recvline()
encMsg = json.loads(io.recvline().decode())
print(f'{encMsg=}')
io.close()

mtrxA = Matrix(GF(p), 4,
	[
		[gA[0][0] - G[0][0], gA[1][0], -G[0][1], 0],
		[gA[0][1], gA[1][1] - G[0][0], 0, -G[0][1]],
		[-G[1][0], 0, gA[0][0] - G[1][1], gA[1][0]],
		[0, -G[1][0], gA[0][1], gA[1][1] - G[1][1]]
	]
)
# print(mtrxA)

mtrxB = Matrix(GF(p), 4,
	[
		[gB[0][0] - G[0][0], gB[1][0], -G[0][1], 0],
		[gB[0][1], gB[1][1] - G[0][0], 0, -G[0][1]],
		[-G[1][0], 0, gB[0][0] - G[1][1], gB[1][0]],
		[0, -G[1][0], gB[0][1], gB[1][1] - G[1][1]]
	]
)
# print(mtrxB)

if sys.argv[1] == 'l':
	print(f'{mtrxA * vector(A) =}')
	print(f'{mtrxB * vector(B) =}')
	print(f'{(A**-1 * G * A) =}')
	print(f'{gA =}')
# print(f'{mtrxA.right_kernel()}')
# print(f'{mtrxB.right_kernel()}')
lam1 = mtrxA.right_kernel_matrix()[0][2]
lam2 = mtrxA.right_kernel_matrix()[1][2]
lam3 = mtrxA.right_kernel_matrix()[0][3]
lam4 = mtrxA.right_kernel_matrix()[1][3]

miu1 = mtrxB.right_kernel_matrix()[0][2]
miu2 = mtrxB.right_kernel_matrix()[1][2]
miu3 = mtrxB.right_kernel_matrix()[0][3]
miu4 = mtrxB.right_kernel_matrix()[1][3]

mtrxC = Matrix(GF(p), 3,
	[
		[lam1, -miu1, lam2 - miu2],
		[lam3 - 1, 1 - miu3, lam4 - miu4],
		[lam3 * miu2 - miu2 - lam1 * miu4, lam2 + lam4 * miu1 - lam2 * miu3, lam4 * miu2 - lam2 * miu4]
	]
)

ua = 1
rel = mtrxC.solve_right(vector([0, 0, -(lam1 + lam3 * miu1 - miu1 - lam1 * miu3)]))
# print(f'{rel = }')
if sys.argv[1] == 'l':
	assert (A[0][0] * B[0][0] * rel[0] - A[0][0] * B[0][1]) % p == 0
	assert (A[0][0] * B[0][0] * rel[1] - A[0][1] * B[0][0]) % p == 0
	assert (A[0][0] * B[0][0] * rel[2] - A[0][1] * B[0][1]) % p == 0
	print('so far so good')

rel0, rel1, rel2 = rel
mtrxD = Matrix(GF(p), 2,
	[
		[1 + miu1 * rel1 + miu2 * rel2, rel0 + miu3 * rel1 + miu4 * rel2],
		[
			lam1 + lam2 * rel1 + lam3 * miu1 + lam3 * miu2 * rel0 + lam4 * miu1 * rel1 + lam4 * miu2 * rel2,
			lam1 * rel0 + lam2 * rel2 + lam3 * miu3 + lam3 * miu4 * rel0 + lam4 * miu3 * rel1 + lam4 * miu4 * rel2
		]
	]
)

# print(f'{mtrxD=}')
super_secret_key = mtrxD**-1 * G * mtrxD
if sys.argv[1] == 'l':
	print(f'{super_secret_key=}')
	print(f'{B**-1 * gA * B=}')

m = hashlib.sha256()
m.update(f"{super_secret_key[0][1]}{super_secret_key[1][0]}{super_secret_key[1][1]}{super_secret_key[0][0]}".encode())
otp = m.digest()
flag = [em ^ ot for em, ot in zip(encMsg, otp)]
flag = ''.join([chr(_) for _ in flag])
print(flag)
# GPNCTF{Dr.M3t4F0rTh3W1n!?0x1337}
