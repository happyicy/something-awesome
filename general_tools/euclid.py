def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

# assume a > b
def extended_euclid(a, b):
    if b % (a % b) == 0: return 1, -int(a / b)
    d = int(a / b)
    p, q = extended_euclid(b, a % b)
    return q, (p - q*d)

# p = 3 mod 4
def sqrt(a, p):
    answer = pow(a, (p+1) // 4, p)
    return max(answer, p - answer)