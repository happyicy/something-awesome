ciphertext = bytes.fromhex("87e70073d7a18ca137d6baf2211fec810e075eebcf015c1b1f9d96a2609c8762a436f9130197afc6d1a88ea92b7acb78")
curr_iv = ciphertext[:16]
current_ct = b"admin=False;expi"

goal_plain = b"admin=True;;expi"

# We want a different plaintext to be made when we decrypt
# current_ctly we get decrypt(ciphertext[16:32]) = current_ct ^ curr_iv
# We want goal_iv ^ decrypt = 'admin=True;;expi', so goal_iv = current_ct ^ curr_iv ^ 'admin=True;;expi'

goal_iv = bytes(x ^ y ^ z for x, y, z in zip(curr_iv, current_ct, goal_plain))

iv = goal_iv.hex()
cookie = ciphertext[16:].hex()
print(iv, cookie)
# {"flag":"crypto{4u7h3n71c4710n_15_3553n714l}"}

# solution notes: Crypto.Util.strxor is a thing, so is xor in pwntools
# don't even even need to zip, just strxor(bytes1, bytes2)