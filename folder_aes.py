# pip install pycryptodomex
# conda install -c anaconda pycryptodomex

import struct, hashlib, sys
import binascii
import os, glob, codecs
from Crypto.Cipher import AES

# 암호화
def encrypt_file(key, in_filename, out_filename=None, chunksize=65536):
    if not out_filename:
        out_filename = in_filename + '.enc'
    iv = 'initialvector123'
    encryptor = AES.new(key, AES.MODE_CBC, iv.encode("utf8"))
    filesize = os.path.getsize(in_filename)
    with open(in_filename, 'rb') as infile:
        with open(out_filename, 'wb') as outfile:
            outfile.write(struct.pack('<Q', filesize))
            outfile.write(iv.encode())
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += b' ' * (16 - len(chunk) % 16)
                outfile.write(encryptor.encrypt(chunk))

# 복호화
def decrypt_file(key, in_filename, out_filename, chunksize=24 * 1024):
    with open(in_filename, 'rb') as infile:
        origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
        iv = infile.read(16)
        decryptor = AES.new(key, AES.MODE_CBC, iv)
        with open(out_filename, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                outfile.write(decryptor.decrypt(chunk))
            outfile.truncate(origsize)

def get_key(password):
    key = hashlib.sha256(password.encode('utf-8')).digest()
    return key

def common_work(x, extension, dest):
    if x.split(".")[-1] not in extension:
        return False
    print(x)
    destination = os.path.join(dest, x)
    os.makedirs(os.path.dirname(destination), exist_ok=True)
    return destination

if __name__ == "__main__":
    mode = sys.argv[1] # mode ( 1 or 2 )
    root = sys.argv[2] # encrypt, decrypt root
    dest = sys.argv[3] # destination root
    password = sys.argv[4] # password

    if mode == '1':
        # 암호화
        key = get_key(password)
        for x in glob.iglob('**', recursive=True):
            destination = common_work(x, ["jpg", "png"], dest)
            if not destination: continue
            encrypt_file(key, x, destination[:-4] + '.win')
    elif mode == '2':
        # 복호화
        key = get_key(password)
        os.chdir(root)
        for x in glob.iglob('**', recursive=True):
            destination = common_work(x, ["win"], dest)
            if not destination: continue
            decrypt_file(key, x, destination[:-4] + '.jpg')
    else:
        print('Wrong mode!')