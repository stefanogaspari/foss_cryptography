from typing import List
from cryptography.ellipticCurves import EllipticCurve
from cryptography.hashing import hash
from cryptography.rfc6979 import generate_k


class ECDSA:
    
    # Constructor: set an instance of a specific ECDSA linked to a specific elliptic curve and a specific hash function
    def __init__(self, p: int, a: int, b: int, G: List[int], n: int, hash_function: str):
        self.p = p
        self.a = a
        self.b = b
        self.G = G
        self.n = n
        self.hash_function = hash_function

    # Sign a message <msg> in a non deterministic way (secure random entropy k)
    def non_deterministic_sign(self, k: int, msg: bytes, privKey: bytes) -> bytes:
        ec = EllipticCurve(self.p, self.a, self.b)
        h = int.from_bytes(hash(msg, self.hash_function), byteorder='big')
        privK = int.from_bytes(privKey, byteorder='big')
        if k < 1 or k > self.n - 1:
            raise ValueError("Value Error: k is not included in the range [ 1 , n-1 ]")
        R = ec.scalar_multiply(k, self.G)
        r = R[0]
        if r == 0:
            raise ValueError("Value Error: r = 0. Start over")
        s = (pow(k, -1, self.n) * (h + r * privK)) % self.n
        if s == 0:
            raise ValueError("Value Error: s = 0. Start over")
        if len(hex(r)[2:]) % 2 == 0:
            len_r_bytes = len(hex(r)[2:]) // 2
        else:
            len_r_bytes = len(hex(r)[2:]) // 2 + 1
        if len(hex(s)[2:]) % 2 == 0:
            len_s_bytes = len(hex(s)[2:]) // 2
        else:
            len_s_bytes = len(hex(s)[2:]) // 2 + 1
        r_bytes = r.to_bytes(len_r_bytes, byteorder='big')
        s_bytes = s.to_bytes(len_s_bytes, byteorder='big')
        return r_bytes , s_bytes
    
    # Sign a message <msg> in a deterministic way (RFC6979)
    def deterministic_sign(self, msg: bytes, privKey: bytes) -> bytes:
        ec = EllipticCurve(self.p, self.a, self.b)
        h = int.from_bytes(hash(msg, self.hash_function), byteorder='big')
        privK = int.from_bytes(privKey, byteorder='big')
        k = generate_k(self.hash_function, msg, privK, self.n)
        R = ec.scalar_multiply(k,self.G)
        r = R[0]
        if r == 0:
            raise ValueError("Value Error: r = 0. Start over")
        s = (pow(k, -1, self.n) * (h + r * privK)) % self.n
        if s == 0:
            raise ValueError("Value Error: s = 0. Start over")
        if len(hex(r)[2:]) % 2 == 0:
            len_r_bytes = len(hex(r)[2:]) // 2
        else:
            len_r_bytes = len(hex(r)[2:]) // 2 + 1
        if len(hex(s)[2:]) % 2 == 0:
            len_s_bytes = len(hex(s)[2:]) // 2
        else:
            len_s_bytes = len(hex(s)[2:]) // 2 + 1
        r_bytes = r.to_bytes(len_r_bytes, byteorder='big')
        s_bytes = s.to_bytes(len_s_bytes, byteorder='big')
        return r_bytes , s_bytes
    
    # Verify a message msg
    def verify(self, sig: bytes, msg: bytes, pubKey: bytes) -> bool:
        ec = EllipticCurve(self.p, self.a, self.b)
        h = int.from_bytes(hash(msg, self.hash_function), byteorder='big')
        r = int.from_bytes(sig[:len(sig)//2], byteorder='big')
        s = int.from_bytes(sig[len(sig)//2:], byteorder='big')
        pubK_x = int.from_bytes(pubKey[:len(pubKey)//2], byteorder='big')
        pubK_y = int.from_bytes(pubKey[len(pubKey)//2:], byteorder='big')
        pubK = [pubK_x, pubK_y]
        isVerified = False
        if r <= 1 or r >= self.n - 1:
            raise ValueError("Value Error: r is not included in the range [ 1 , n-1 ]")
        if s <= 1 or s >= self.n - 1:
            raise ValueError("Value Error: s is not included in the range [ 1 , n-1 ]")
        s1 = pow(s, -1, self.n)
        random_Point = ec.add(ec.scalar_multiply(h*s1, self.G), ec.scalar_multiply(r*s1, pubK))
        r_first = random_Point[0]
        if r_first == r:
            isVerified = True
        return isVerified
