# Finding a generator mod 28151
n = 28151
tests = [int((n-1)/x) for x in [2, 5, 563]]

# A generator should not power to 1 mod n for any power smaller than n-1
for x in range(1, n):
    r = [pow(x, y, n) for y in tests]
    if not r.count(1):
        print(x)
        break