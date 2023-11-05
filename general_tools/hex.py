from binascii import hexlify
input = "63727970746f7b626c30636b5f633170683372355f3472335f663435375f217d"

output = bytes.fromhex(input)
print(output)
input = hexlify(output)
print(input)
print(output[0])
for x in "crypto{":
    print(str(hex(ord(x))))