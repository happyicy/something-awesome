def g_add(x, y):
    return x ^ y

def g_mul(x, y):
    product = 0
    for i in range(8):
        if y & 1:
           product ^= x
        high_bit = x >= 128
        x <<= 1
        if high_bit:
            x ^= 0x1b
        y >>= 1
    return product
        
print(g_mul(3, 7), g_mul(7, 3))