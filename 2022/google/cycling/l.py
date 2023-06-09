from math import prod
from tqdm import tqdm
from Crypto.Util.number import isPrime

"""
pow(ct, e^cyc * e, n) == ct
e^(cyc+1) == 1 % l, where l | lamda(n), lamda is Carmichael function
assume that l is lamda(n) rather than a divisor of it, then
(cyc+1) is some divisor r, r | lamda(lamda(n))

since n = p * q, lamda(n) = lcm(p-1, q-1) = 2*s1*s2*s3 ..., and
lamda(lamda(n)) = lamda(2*s1*s2*s3) = lcm(s1-1, s2-1, s3-1, ...)

further assume that (cyc+1) = lamda(lamda(n))
then, si-1 | (cyc+1)

let's try out this idea. first step factorize cyc+1
"""

def div_from_fact(factors):
	div = {1}
	for f in factors:
		div |= set(x * f for x in div)
	return sorted(div)

e = 65537
n = 0x99efa9177387907eb3f74dc09a4d7a93abf6ceb7ee102c689ecd0998975cede29f3ca951feb5adfb9282879cc666e22dcafc07d7f89d762b9ad5532042c79060cdb022703d790421a7f6a76a50cceb635ad1b5d78510adf8c6ff9645a1b179e965358e10fe3dd5f82744773360270b6fa62d972d196a810e152f1285e0b8b26f5d54991d0539a13e655d752bd71963f822affc7a03e946cea2c4ef65bf94706f20b79d672e64e8faac45172c4130bfeca9bef71ed8c0c9e2aa0a1d6d47239960f90ef25b337255bac9c452cb019a44115b0437726a9adef10a028f1e1263c97c14a1d7cd58a8994832e764ffbfcc05ec8ed3269bb0569278eea0550548b552b1
ct = 0x339be515121dab503106cd190897382149e032a76a1ca0eec74f2c8c74560b00dffc0ad65ee4df4f47b2c9810d93e8579517692268c821c6724946438a9744a2a95510d529f0e0195a2660abd057d3f6a59df3a1c9a116f76d53900e2a715dfe5525228e832c02fd07b8dac0d488cca269e0dbb74047cf7a5e64a06a443f7d580ee28c5d41d5ede3604825eba31985e96575df2bcc2fefd0c77f2033c04008be9746a0935338434c16d5a68d1338eabdcf0170ac19a27ec832bf0a353934570abd48b1fe31bc9a4bb99428d1fbab726b284aec27522efb9527ddce1106ba6a480c65f9332c5b2a3c727a2cca6d6951b09c7c28ed0474fdc6a945076524877680

cyc = 2**1025 - 3
cyc_1 = cyc + 1
# factors of cyc_1
factors = [
	2, 3, 5, 17, 257, 641, 65537, 274177, 6700417, 67280421310721,
	1238926361552897, 59649589127497217, 5704689200685129054721,
	93461639715357977769163558199606896584051237541638188580280321, 2424833,
	7455602825647884208337395736200454918783366342657,
	741640062627530801524787141901937474059940781097519023905821316144415759504705008092818711693940737
]
assert prod(factors) == cyc_1
# print(f'{len(factors)=}')
divisors = div_from_fact(factors)

# {si} must be subset of divisors+1
divisors = [d + 1 for d in divisors]
# print(f'{len(divisors)=}')
# print(f'{divisors[-4:]=}')

# prune some for primes, otherwise proding all divisors are too slow
cands = []
for d in tqdm(divisors):
	if isPrime(d):
		cands.append(d)
# print(f'{len(cands)=}')
# no need to identify the lamda(n), we just prod all candidates and
# hope there is that d, where e * d = 1 % this prod
phi_lifted = prod(cands)
d = pow(e, -1, phi_lifted)
pt = pow(ct, d, n)
print(pt.to_bytes((pt.bit_length()+7)//8, 'big').decode())
# CTF{Recycling_Is_Great}