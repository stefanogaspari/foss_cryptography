import hashlib
from cryptography.ellipticCurves import EllipticCurve

def sha(str):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(str.encode('utf-8'))
    return int(sha256_hash.hexdigest(),16)

class ECDSA:
    def __init__(self,m,a,b,G,n):
        self.m = m
        self.a = a
        self.b = b
        self.G = G
        self.n = n
    # Sign a message msg
    def sign(self,k,msg,privKey):
        secp256k1 = EllipticCurve(self.m,self.a,self.b)
        h = sha(msg)
        if k < 1 or k > self.n - 1:
            raise ValueError("Value Error: k is not included in the range ] 1 , n-1 [")
        R = secp256k1.scalar_multiply(k,self.G)
        r = R[0]
        if r == 0:
            raise ValueError("Value Error: r = 0. Start over")
        s = (pow(k, -1, self.n) * (h + r * privKey)) % self.n
        if s == 0:
            raise ValueError("Value Error: s = 0. Start over")
        return [r,s]
    # Verify a message msg
    def verify(self,sig,msg,pubKey):
        secp256k1 = EllipticCurve(self.m,self.a,self.b)
        h = sha(msg)
        r = sig[0]
        s = sig[1]
        isVerified = False
        if r < 1 or r > self.n - 1:
            raise ValueError("Error: r is not included in the range ] 1 , n-1 [")
        if s < 1 or s > self.n - 1:
            raise ValueError("Error: s is not included in the range ] 1 , n-1 [")
        s1 = pow(s, -1, self.n)
        random_Point = secp256k1.add(secp256k1.scalar_multiply(h*s1, self.G), secp256k1.scalar_multiply(r*s1, pubKey))
        r_first = random_Point[0]
        if r_first == r:
            isVerified = True
        return isVerified
