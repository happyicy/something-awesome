from Crypto.Util.number import long_to_bytes
# factordb is op, instantly factorised n for me
# The parameter for getPrime is bits, not bytes, so n was only 200 bits which is small
n = 742449129124467073921545687640895127535705902454369756401331
phi = (752708788837165590355094155871-1) * (986369682585281993933185289261-1)
e = 3
d = pow(e, -1, phi)
ct = 39207274348578481322317340648475596807303160111338236677373
    
print(long_to_bytes(pow(ct, d, n)))