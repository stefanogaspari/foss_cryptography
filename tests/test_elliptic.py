from cryptography.ellipticCurves import EllipticCurve
from cryptography.curves.secp256k1 import p, a, b, origin_G
from tests.vectors import n, n_times_P_vector


def test_EllipticOperations():
    secp256k1 = EllipticCurve(p,a,b)
    n_times_P = secp256k1.scalar_multiply(n, origin_G)
    assert n_times_P[0] == n_times_P_vector[0]
    assert n_times_P[1] == n_times_P_vector[1]