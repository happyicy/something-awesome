from requests import Session

s = Session()

def encrypt(data):
    url = "https://aes.cryptohack.org/ecb_oracle/encrypt/" + data.hex() + "/"
    return bytes.fromhex(s.get(url).json()["ciphertext"])

f = open("symmetric/ecb_oracle/flag.txt", "a")
flag = b""
for i in range(25):
    x = b'a' * (31 - i)
    subs = 0
    cipher = encrypt(x + flag + bytes([subs]) + x)
    while (cipher[:32] != cipher[32:64]):
        subs += 1
        cipher = encrypt(x + flag + bytes([subs]) + x)
    print("next char: " + str(subs))
    flag += bytes([subs])
    f.write(chr(subs))
print(flag)