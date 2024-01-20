from cryptography.ecdsa import ECDSA
from cryptography.secp256k1 import mod, a, b, origin_G, n
from cryptography.vectorsForTesting import privKey, pubKey, k, message, s

def test_sign():
    crypto = ECDSA(mod,a,b,origin_G,n)
    signature = crypto.sign(k, message, privKey)
    assert signature[1] == s

def test_verify():
    crypto = ECDSA(mod,a,b,origin_G,n)
    signature = crypto.sign(k, message, privKey)
    assert crypto.verify(signature, message, pubKey)