from Crypto.Util.number import getPrime, inverse, GCD, bytes_to_long, long_to_bytes
from sympy.ntheory import nextprime, isprime

e1 = 65537
e2 = 257

p1 = getPrime(600)
while not isprime(2 * p1 * e1 + 1):
    p1 = nextprime(p1, 1)
print(p1)
p2 = getPrime(600)
while not isprime(2 * p2 * e2 + 1):
    p2 = nextprime(p2, 1)
print(p2)
    
p = 2 * p1 * e1 + 1
q = 2 * p2 * e2 + 1

n = p * q
flag = bytes_to_long(b'FLAG{w0w_gcd_41g0_0n_pOw3r5?}')

ct1 = pow(flag, e1, n)
ct2 = pow(flag, e2, n)

print(f"n = {n}")
print(f"e1 = {e1}")
print(f"ct1 = {ct1}")
print(f"e2 = {e2}")
print(f"ct2 = {ct2}")