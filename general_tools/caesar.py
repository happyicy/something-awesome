s = input()

for shift in range(26):
    out = ""
    for x in s:
        if 'A' <= x <= 'Z':
            out += chr(ord('A') + (ord(x) - ord('A') + shift) % 26)
        elif 'a' <= x <= 'z':
            out += chr(ord('a') + (ord(x) - ord('a') + shift) % 26)
        else:
            out += x
    print(out)