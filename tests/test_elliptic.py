from cryptography.ellipticCurves import EllipticCurve
from cryptography.secp256k1 import mod, a, b, origin_G
from cryptography.vectorsForTesting import privKey, pubKey


def test_EllipticOperations():
    secp256k1 = EllipticCurve(mod,a,b)
    pubKeyTest = secp256k1.scalar_multiply(privKey, origin_G)
    assert pubKeyTest[0] == pubKey[0]