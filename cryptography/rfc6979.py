# RFC6979 - Deterministic Usage of the Digital Signature Algorithm (DSA) and Elliptic Curve Digital Signature Algorithm (ECDSA)
# Generation of k
# https://datatracker.ietf.org/doc/html/rfc6979#section-3.2


import hmac
import hashlib
from hmac_digest_hash import hash


def bits2int(bit_string: str, q: int) -> int:
    """
    The bits2int transform takes as input a sequence of blen bits and
    outputs a non-negative integer that is less than 2^qlen.  It consists
    of the following steps:

    1.  The sequence is first truncated or expanded to length qlen:

       *  if qlen < blen, then the qlen leftmost bits are kept, and
          subsequent bits are discarded;

       *  otherwise, qlen-blen bits (of value zero) are added to the
          left of the sequence (i.e., before the input bits in the
          sequence order).
    
    2.  The resulting sequence is then converted to an integer value
       using the big-endian convention: if input bits are called b_0
       (leftmost) to b_(qlen-1) (rightmost), then the resulting value
       is:

          b_0*2^(qlen-1) + b_1*2^(qlen-2) + ... + b_(qlen-1)*2^0
    
    The bits2int transform can also be described in the following way:
    the input bit sequence (of length blen) is transformed into an
    integer using the big-endian convention.  Then, if blen is greater
    than qlen, the resulting integer is divided by two to the power
    blen-qlen (Euclidian division: the remainder is discarded); in many
    software implementations of arithmetics on big integers, that
    division is equivalent to a "right shift" by blen-qlen bits.
    """
    qlen = len(bin(q)[2:])
    blen = len(bit_string)
    if qlen < blen:
        bit_string = bit_string[:qlen]
    else:
        bit_string = bit_string.zfill(qlen)
    return int(bit_string, 2)


def int2octets(x: int, q: int) -> bytes:
    """
    int2octets()
    An integer value x less than q (and, in particular, a value that has
    been taken modulo q) can be converted into a sequence of rlen bits,
    where rlen = 8*ceil(qlen/8).  This is the sequence of bits obtained
    by big-endian encoding.  In other words, the sequence bits x_i (for i
    ranging from 0 to rlen-1) are such that:

      x = x_0*2^(rlen-1) + x_1*2^(rlen-2) + ... + x_(rlen-1)

    We call this transform int2octets.  Since rlen is a multiple of 8
    (the smallest multiple of 8 that is not smaller than qlen), then the
    resulting sequence of bits is also a sequence of octets, hence the
    name.
    """
    if x < q:
        qlen = len(bin(q)[2:])
        rlen = 8*ceil(qlen)
        x_bits = bin(x)[2:]
        if len(x_bits) < rlen:
            return int(x_bits.zfill(rlen), 2).to_bytes(rlen // 8, byteorder='big')
        else:
            return int(x_bits, 2).to_bytes(rlen // 8, byteorder='big')
    else:
        raise ValueError("Value Error: private key higher or equal than the order q of the elliptic curve")


def bits2octets(bit_string: str, q: int) -> bytes:
    """
    The bits2octets transform takes as input a sequence of blen bits and
    outputs a sequence of rlen bits.  It consists of the following steps:

    1.  The input sequence b is converted into an integer value z1
        through the bits2int transform:

        z1 = bits2int(b)

    2.  z1 is reduced modulo q, yielding z2 (an integer between 0 and
        q-1, inclusive):

        z2 = z1 mod q

        Note that since z1 is less than 2^qlen, that modular reduction
        can be implemented with a simple conditional subtraction:
        z2 = z1-q if that value is non-negative; otherwise, z2 = z1.

    3.  z2 is transformed into a sequence of octets (a sequence of rlen
        bits) by applying int2octets.
    """
    z1 = bits2int(bit_string, q)
    z2 = z1 % q
    return int2octets(z2, q)


class HMAC_K():
    """
    HMAC_K.V returns a sequence of bits of length hlen (the output length of
    the underlying hash function H)
    """
    def __init__(self, hash_func_name: str):
        if hash_func_name == "sha256":
            self.H = hashlib.sha256
    def V(self, K: bytes, V: bytes) -> bytes:
        hmac_obj = hmac.new(K, V, self.H)
        return hmac_obj.digest()
    

def ceil(hlen: int) -> int:
    if hlen % 8 == 0:
        return hlen // 8
    else:
        return hlen // 8 + 1


def generate_k(hash_func_name: str, msg: bytes, x: int, q: int) -> int:
    hmac_k = HMAC_K(hash_func_name)

    qlen = len(bin(q)[2:])

    # Step a
    h1_bytes = hash(msg, hash_func_name)
    h1 = ''.join(format(byte, '08b') for byte in h1_bytes)
    hlen = len(h1)

    # Step b
    V = bytes([int('0x01', 16)] * ceil(hlen))

    # Step c
    K = bytes([int('0x00', 16)] * ceil(hlen))

    # Step d
    Data = V + int('0x00', 16).to_bytes(1, byteorder='big') + int2octets(x, q) + bits2octets(h1, q)
    K = hmac_k.V(K, Data)

    # Step e
    V = hmac_k.V(K, V)

    # Step f
    Data = V + int('0x01', 16).to_bytes(1, byteorder='big') + int2octets(x, q) + bits2octets(h1, q)
    K = hmac_k.V(K, Data)

    # Step g
    V = hmac_k.V(K, V)

    # Step h
    while True:

        # h.1.
        T_bytes = bytes()
        T = ''.join(format(byte, '08b') for byte in T_bytes)
        tlen = len(T)

        # h.2.
        while tlen < qlen:
            V = hmac_k.V(K, V)
            T_bytes = T_bytes + V
            T = ''.join(format(byte, '08b') for byte in T_bytes)

            # h.3.
            k = bits2int(T, q)
            if k >= 1 and k <= q - 1:
                return k
            else:
                K = hmac_k.V(K, V + int('0x00', 16).to_bytes(1, byteorder='big'))
                V = hmac_k.V(K, V)
