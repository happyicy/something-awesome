# Provided file for decrypting given a shared secret
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib


def is_pkcs7_padded(message):
    padding = message[-message[-1]:]
    return all(padding[i] == len(padding) for i in range(0, len(padding)))


def decrypt_flag(shared_secret: int, iv: str, ciphertext: str):
    # Derive AES key from shared secret
    sha1 = hashlib.sha1()
    sha1.update(str(shared_secret).encode('ascii'))
    key = sha1.digest()[:16]
    # Decrypt flag
    ciphertext = bytes.fromhex(ciphertext)
    iv = bytes.fromhex(iv)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)

    if is_pkcs7_padded(plaintext):
        return unpad(plaintext, 16).decode('ascii')
    else:
        return plaintext.decode('ascii')


shared_secret = 1297372229892292205990454833841981331808950855337835830867059105664519973711466723648810735759940953049703162459109910221423081422596983109713676813443647288063840071278131395099530616669323972619129332225564090325560961156739945075315655919899406363255038141195789152317077453835728518192606611917177490614591307141674153160198210674700115542600918783896908699339727232910932499638920024694376057416374864710649784974191458269432909186739442841173928410227766598
iv = "56f012103d8e6077016f4b0b471ea85c"
ciphertext = "a505575952b48e26b6b17208c511bde4d5de60d862636cd3ee5843fb5a84031c540fe6b2d2c65662f2d444cab945a610"

print(decrypt_flag(shared_secret, iv, ciphertext))
