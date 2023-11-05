from requests import Session

s = Session()

def encrypt(plain):
    url = "https://aes.cryptohack.org/lazy_cbc/encrypt/" + plain.hex() + "/"
    return bytes.fromhex(s.get(url).json()["ciphertext"])

def decrypt(cipher):
    url = "https://aes.cryptohack.org/lazy_cbc/receive/" + cipher.hex() + "/"
    return bytes.fromhex(s.get(url).json()["error"][19:])

def get_flag(key):
    url = "https://aes.cryptohack.org/lazy_cbc/get_flag/" + key.hex() + "/"
    return bytes.fromhex(s.get(url).json()["plaintext"])

# Idea: Encrypt random plaintext p1 to get some ciphertext c1
# xor c1 with b'\xff'*16 to get p2. We now have ciphertext output of b'\xff'*16, call this c2
# decrypt c2, we get key ^ b'a'*16 to get key

p1 = b'\x01' * 16
c1 = encrypt(p1)

p2 = bytes(x ^ 255 for x in c1)
print(p2)
c2 = encrypt(p1 + p2)[16:32]

d = decrypt(c2)
key = bytes(x ^ 255 for x in d)
print(get_flag(key))