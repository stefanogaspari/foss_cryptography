from cryptography.ellipticCurves import EllipticCurve
from cryptography.curves.secp256k1 import p, a, b, origin_G
from tests.vectors import privKey, pubKey


def test_EllipticOperations():
    secp256k1 = EllipticCurve(p,a,b)
    pubKeyTest = secp256k1.scalar_multiply(privKey, origin_G)
    assert pubKeyTest[0] == pubKey[0]