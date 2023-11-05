key = "CLASS"
key = [ord(x) - 65 for x in key]
plaintext = "How many meals on average do you eat?"

def vigenere_encrpyt(key, plain):
    ciphertext = ""
    i = 0
    for x in plaintext:
        if 'A' <= x <= 'Z':
            ciphertext += chr(ord('A') + (ord(x) - ord('A') + key[i % len(key)]) % 26)
            i += 1
        elif 'a' <= x <= 'z':
            ciphertext += chr(ord('a') + (ord(x) - ord('a') + key[i % len(key)]) % 26)
            i += 1
        else:
            ciphertext += x
    return ciphertext

def vigenere_decrpyt(key, cipher):
    plaintext = ""
    i = 0
    for x in cipher:
        if 'A' <= x <= 'Z':
            plaintext += chr(ord('A') + (ord(x) - ord('A') - key[i % len(key)]) % 26)
            i += 1
        elif 'a' <= x <= 'z':
            plaintext += chr(ord('a') + (ord(x) - ord('a') - key[i % len(key)]) % 26)
            i += 1
        else:
            plaintext += x
    return plaintext

print(vigenere_encrpyt(key, plaintext))