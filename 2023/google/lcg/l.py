from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes, isPrime
from math import prod

# multiplier, increment and modulus are cracked by LCGHack
class LCG:
	# using the given six states, the lcghack can recover m, c and n
	# python3 main.py -k state1 state2 ... state6
	# https://raw.githubusercontent.com/TomasGlgg/LCGHack/master/main.py
	lcg_m = 99470802153294399618017402366955844921383026244330401927153381788409087864090915476376417542092444282980114205684938728578475547514901286372129860608477
	lcg_c = 3910539794193409979886870049869456815685040868312878537393070815966881265118275755165613835833103526090552456472867019296386475520134783987251699999776365
	lcg_n = 8311271273016946265169120092240227882013893131681882078655426814178920681968884651437107918874328518499850252591810409558783335118823692585959490215446923

	def __init__(self, lcg_s):
		self.state = lcg_s

	def next(self):
		self.state = (self.state * self.lcg_m + self.lcg_c) % self.lcg_n
		return self.state

class Config:
	def __init__(self, it, bits):
		self.it = it
		self.bits = bits

with open ("public.pem", "r") as pub_file:
	pubkey = RSA.import_key(pub_file.read())

with open('dump.txt', 'r') as dump_file:
	dump_lcg = [int(line.strip()) for line in dump_file]

# seed is given in the challenge
seed = 211286818345627549183608678726370412218029639873054513839005340650674982169404937862395980568550063504804783328450267566224937880641772833325018028629959635
lcg = LCG(seed)
for _ in dump_lcg:
	assert lcg.next() == _

primes_arr = []
items = 0
primes_n = 1
config = Config(8, 512)

while True:
	for i in range(config.it):
		while True:
			prime_candidate = lcg.next()
			if not isPrime(prime_candidate):
				continue
			elif prime_candidate.bit_length() != config.bits:
				continue
			else:
				primes_n *= prime_candidate
				primes_arr.append(prime_candidate)
				break

	# check bit length
	if primes_n.bit_length() > 4096:
		print("bit length", primes_n.bit_length())
		primes_arr.clear()
		primes_n = 1
		continue
	else:
		break

# create public key 'n' (multi-prime RSA)
n = prod(primes_arr)
assert n == pubkey.n
phi = prod([(p-1) for p in primes_arr])

# calculate private key 'd'
d = pow(pubkey.e, -1, phi)

with open ("flag.txt", "rb") as flag_file:
	enc_flag = int.from_bytes(flag_file.read(), 'little')

# decrypt flag
flag = long_to_bytes(pow(enc_flag, d, n)).decode()
print(f'{flag=}')
# CTF{C0nGr@tz_RiV35t_5h4MiR_nD_Ad13MaN_W0ulD_b_h@pPy}
