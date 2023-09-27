from Crypto.Util.number import *
from random import *
from math import gcd
from hashlib import *


def gen_rsa_keypair(bits):

    p = getPrime(bits//2)
    q = getPrime(bits//2)

    n = p * q
    phi_n = (p - 1) * (q - 1)

    e = 65537

    while (gcd(e, phi_n) != 1 ):
        e = randint(1, (phi_n - 1))

    d = inverse(e, phi_n)

    pk = (n, e)
    sk = d

    return pk, sk

# print(gen_rsa_keypair(512))


def rsa(m, e, n):

    return pow(m, e, n)

cle = gen_rsa_keypair(300)
e = cle[0][1]
n = cle[0][0]
sk = cle[1]

cleb = gen_rsa_keypair(300)
eb = cleb[0][1]
nb = cleb[0][0]
skb = cleb[1]

# print(cle)

def rsa_enc(m, e, n):

    c = int.from_bytes(m.encode('utf-8'), 'big')

    if c > n:
        return None

    return rsa(c, e, n)

def rsa_dec(c, sk, n):

    if c == None:
        return None

    msg = (rsa(c, n, sk))

    return msg.to_bytes((msg.bit_length() + 7) // 8, 'big').decode('utf-8')



# print(rsa_dec(rsa_enc('Licence P8', e, n), n, sk))


def simulation():

    msgB = rsa_enc("hey alice!", e, n)

    recuA = rsa_dec(msgB, n, sk)

    print(msgB, recuA)

    msgA = rsa_enc("hey bob!", eb, nb)

    recuB = rsa_dec(msgA, nb, skb)

    print(msgA, recuB)



def hashash(x):

    h = sha256()

    T = x.to_bytes(x.bit_length(), 'big')

    h.update(T)

    K = h.digest()

    a = int.from_bytes(K, 'big')

    return a

# print(hashash(1))

def rsa_sign(m, sk, n):

    Hm = hashash(m)

    s = pow(Hm, sk, n)

    return s

# print(rsa_sign(1, sk, n))

def rsa_verify(m, s, e, n):

    Hm = hashash(m)
    H2 = pow(s, e, n)

    if H2 == Hm:
        return True
    else:
        return False

# print(rsa_verify(1, rsa_sign(1, sk, n), e, n))

def simulation_hash(sk, n, e, skb, nb, eb):

    print(rsa_verify(3, rsa_sign(3, sk, n), e, n))

    print(rsa_verify(3, rsa_sign(3, skb, nb), eb, nb))

# print(cle, cleb)

# simulation_hash(sk, n, e, skb, nb, eb)
