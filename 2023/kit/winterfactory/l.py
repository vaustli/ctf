from pwn import *
from binascii import unhexlify
from signatures import WOTS, openssl_sha256
context.log_level = 'error'

def verdict_on_sign(msg0, msg1, msg2):
	assert len(msg0) == len(msg1) == len(msg2)
	for (m0, m1) in zip(msg0, msg1):
		if (m0 > m1):
			if m0 == 14:
				print(f'{m0=},{m1=}')
				continue
			return False
	if msg1[-2] > msg2[-2]:
		print(f'{msg1[-2]=}, {msg2[-2]=}')
		return True
	return False

w = 2**16
if sys.argv[1] == 'l':
	io = process(['python3', 'o-winterfactory.py'])
else:
	io = remote('winterfactory-0.chals.kitctf.de', 1337, ssl=True)

for _ in range(2):
	io.recvline()
bigsig = io.recvline().decode().strip().split('|')
bigsig_bytes = [bytes.fromhex(x) for x in bigsig]
# print(f'{bigsig}')
# print(f'{bigsig_bytes}')

init_message = bytes("surely no secret here"+str(831347528), "utf-8")
init_msg_to_sign=[18678, 15145, 5129, 7711, 123, 3102, 14094, 90, 10894, 11278, 14561, 755, 3157, 5962, 7673, 7901, 14, 4803]

wots = WOTS(w, digestsize=256, hashfunction=openssl_sha256)
msg_to_sign = None

while True:
	# get message 1
	io.recvuntil(b'|')
	msg1 = io.recvuntil(b'|').decode()[:-1].strip()
	print(f'{msg1=}')
	msg1 = bytes.fromhex(msg1)
	msg1hash = wots.hashfunction(msg1)
	msg1_to_sign = wots._getSignatureBaseMessage(msg1hash)
	print(f'{msg1_to_sign=}')
	# get message 2
	io.recvline()
	io.recvuntil(b'|')
	msg2 = io.recvuntil(b'|').decode()[:-1].strip()
	print(f'{msg2=}')
	msg2 = bytes.fromhex(msg2)
	msg2hash = wots.hashfunction(msg2)
	msg2_to_sign = wots._getSignatureBaseMessage(msg2hash)
	print(f'{msg2_to_sign=}')
	# verdict
	jn = verdict_on_sign(init_msg_to_sign, msg1_to_sign, msg2_to_sign)
	if jn:
		print('found a candidate!!!')
		msg_to_sign = msg1_to_sign
		break
	io.sendlineafter(b'>> ', b'no')

io.sendline(b'yes')
io.recvuntil(b'buy? >> ')
io.sendline(b'0')
io.recvline()
sig_extra = bytes.fromhex(io.recvline().decode().strip())
#signature = sign(msg_to_sign)
assert len(init_msg_to_sign) == len(msg_to_sign)
signature = []
bigsig_bytes[-2] = sig_extra
init_msg_to_sign[-2] = msg2_to_sign[-2]
# print(f'{init_msg_to_sign=}')
# print(f'{msg_to_sign=}')
for (v, s, e) in zip(bigsig_bytes, init_msg_to_sign, msg_to_sign):
	signature.append(wots._chain(v, s, e))
# print(f'{signature=}')
s = "".join([a.hex()+"|" for a in signature])[:-1]

io.sendlineafter(b'your order >> ', s.encode())
flag = io.recvline().decode().strip()
print(f'{flag=}')
io.close()
# GPNCTF{1t_is_a_0n4_T1me_S1gnature_01856312904836215}
