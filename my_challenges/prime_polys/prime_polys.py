# I have this polynomial I really like, so I've implemented RSA
# using this polynomial. Seems fine to me, just a quirky second prime.

from Crypto.Util.number import getPrime, inverse, GCD, bytes_to_long, long_to_bytes
from sympy.ntheory import nextprime, isprime


e = 65537

f = open("flag.txt", "rb")
flag = f.read()

p = getPrime(400)
q = 0
while True:
    q = p**4 + 2*p**3 + 4*p**2 + 8*p + 16
    if isprime(q):
        phi = (p-1) * (q-1)
        if GCD(e, phi) == 1:
            d = inverse(e, phi)
            break
    p = nextprime(p)

n = p*q
pt = bytes_to_long(flag)
ct = pow(pt, e, n)

print(f"n = {n}")
print(f"e = {e}")
print(f"ct = {ct}")

pt = pow(ct, d, n)
decrypted = long_to_bytes(pt)
assert decrypted == flag