from typing import List

class EllipticCurve:

    # Constructor: set an instance of a specific elliptic curve
    def __init__(self, mod: int, a: int, b: int):
        self.mod = mod
        self.a = a
        self.b = b
        self.Infinity = None
        if (4 * pow(self.a,3) + 27 * pow(self.b,2)) == 0:
            raise ValueError("Value Error: elliptic curve with singularity")
        
    # P + P = R
    def double(self, P: List[int]) -> List[int]:
        if P is self.Infinity:
            return self.Infinity
        Px, Py = P
        lam = (3 * pow(Px, 2, self.mod) + self.a) * pow(2 * Py, -1, self.mod)
        Rx = (pow(lam, 2) - 2 * Px) % self.mod
        Ry = (lam * (Px - Rx) - Py) % self.mod
        return [Rx, Ry]
    
    # P + Q = R
    def add(self, P: List[int], Q: List[int]) -> List[int]:
        if P is self.Infinity:
            return Q
        if Q is self.Infinity:
            return P
        if P == Q:
            return self.double(P)
        Px, Py = P
        Qx, Qy = Q
        lam = ((Qy - Py) * pow(Qx - Px, -1, self.mod)) % self.mod
        Rx = (pow(lam, 2) - Px - Qx) % self.mod
        Ry = (lam * (Px - Rx) - Py) % self.mod
        return [Rx, Ry]
    
    # n * P = R
    def scalar_multiply(self, n: int, P: List[int]) -> List[int]:
        result = self.Infinity
        while n > 0:
            if n % 2 == 1:
                result = self.add(result, P)
            n //= 2
            P = self.double(P)
        return result