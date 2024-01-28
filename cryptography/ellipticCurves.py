from typing import List

class EllipticCurve:

    # Constructor: set an instance of a specific elliptic curve
    def __init__(self, p: int, a: int, b: int):
        self.p = p
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
        lam = (3 * pow(Px, 2, self.p) + self.a) * pow(2 * Py, -1, self.p)
        Rx = (pow(lam, 2) - 2 * Px) % self.p
        Ry = (lam * (Px - Rx) - Py) % self.p
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
        lam = ((Qy - Py) * pow(Qx - Px, -1, self.p)) % self.p
        Rx = (pow(lam, 2) - Px - Qx) % self.p
        Ry = (lam * (Px - Rx) - Py) % self.p
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