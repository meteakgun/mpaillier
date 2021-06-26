from core.paillier import *

priv, pub = generate_keypair(512)
cipher1 = encrypt(pub,12)
cipher2 = encrypt(pub,5)
cipher3 = add(pub, cipher1, cipher2)
cipher4 = mul_const(pub, cipher3, 3)
cipher5 = add_const(pub,cipher4,9)
plain1 = decrypt(priv,cipher5)
print(plain1)
p_cipher5 = proxy_decrypt(priv,cipher5)
plain2 = decrypt2(priv,p_cipher5)
print(plain2)
