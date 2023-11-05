from Crypto.Cipher import AES
import hashlib
import random
from binascii import hexlify

# /usr/share/dict/words from
# https://gist.githubusercontent.com/wchargin/8927565/raw/d9783627c731268fb2935a731a618aa8e95cf465/words
# with open("/usr/share/dict/words") as f:
#     words = [w.strip() for w in f.readlines()]
# keyword = random.choice(words)

# KEY = hashlib.md5(keyword.encode()).digest()

def decrypt(ciphertext, password_hash):
    ciphertext = bytes.fromhex(ciphertext)
    key = bytes.fromhex(password_hash)

    cipher = AES.new(key, AES.MODE_ECB)
    try:
        decrypted = cipher.decrypt(ciphertext)
    except ValueError as e:
        return {"error": str(e)}

    return {"plaintext": decrypted.hex()}


# @chal.route('/passwords_as_keys/encrypt_flag/'
# def encrypt_flag():
#     cipher = AES.new(KEY, AES.MODE_ECB)
#     encrypted = cipher.encrypt(FLAG.encode())

#     return {"ciphertext": encrypted.hex()}

ciphertext = "c92b7734070205bdf6c0087a751466ec13ae15e6f1bcdd3f3a535ec0f4bbae66"
with open("words.txt") as f:
    for w in f.readlines():
        keyword = w.strip()
        hash = hashlib.md5(keyword.encode()).digest()
        plain = bytes.fromhex(decrypt(ciphertext, hash.hex())['plaintext'])
        if (plain[:7] == bytes("crypto{", "utf-8")):
            print(plain)
            print(keyword)