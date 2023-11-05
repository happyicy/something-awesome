from Crypto.Util.number import isPrime

powers = [588, 665, 216, 113, 642, 4, 836, 114, 851, 492, 819, 237]

# Brute force
for p in range(852, 1000):
    if not isPrime(p): continue
    x = (pow(588, -1, p) * 665) % p
    for i in range(2, len(powers)):
        if (x * powers[i-1]) % p != powers[i]: break
        if i == len(powers) - 1:
            print(p, x)
            
# Nice solution
# From the powers list, we have 4x = 836, so x = 209 mod p
# We then have 113x = 642, so 113 * 209 = 642 mod p
# This gives us (113 * 209 - 642) = 22975 = 0 mod p
# Factorising gives 25 * 919, so p = 919