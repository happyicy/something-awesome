# xoring a bunch of bytes with a repeating key
inp = "\x0e\x0b!?&\x04\x1eH\x0b&!\x7f'4.\x17]\x0e\x07\n<[\x10>%&!\x7f'4.\x17]\x0e\x07~&4Q\x15\x01\x04"
key = 'myXORkey'
out = ""

for i in range(len(inp)):
    out += chr(ord(inp[i]) ^ ord(key[i % len(key)]))
print(out)

# xoring a bunch of bytes together
key1 = bytes.fromhex('a6c8b6733c9b22de7bc0253266a3867df55acde8635e19c73313')
key2 = bytes.fromhex('c1545756687e7573db23aa1c3452a098b71a7fbf0fddddde5fc1')

enc = bytes.fromhex('04ee9855208a2cd59091d04767ae47963170d1660df7f56f5faf')

print(bytes(x ^ y ^ z for x, y, z in zip(key1, key2, enc)))