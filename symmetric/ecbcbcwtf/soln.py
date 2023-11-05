from requests import Session

s = Session()

def decrypt(data):
    url = "https://aes.cryptohack.org/ecbcbcwtf/decrypt/" + data.hex() + "/"
    return bytes.fromhex(s.get(url).json()["plaintext"])

ciphertext = bytes.fromhex("415ec7687f0059bcd9b3eadaef0672ac4b15309b7572af30b770737e68d2fe2d94c6335518cbf15725b954a61b349639")

blocks = []
for x in range(0, len(ciphertext), 16):
    blocks.append(ciphertext[x:x+16])

# CBC xors the plaintext with the previous ciphertext block when encrypting,
# so we decrypt the block then xor with the previous ciphertext block to get
# the original plaintext
for i in range(len(blocks)-1, 0, -1):
    print(bytes(x^y for x, y in zip(decrypt(blocks[i]), blocks[i-1])))