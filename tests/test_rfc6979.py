from cryptography.rfc6979 import generate_k
from cryptography.curves.secp256r1 import n
from tests.vectors import h_sha256_sample_secp256r1, m_sha256_sample_secp256r1, x_sha256_sample_secp256r1, k_sha256_sample_secp256r1

def test_generate_k():
    k = generate_k(h_sha256_sample_secp256r1, m_sha256_sample_secp256r1, x_sha256_sample_secp256r1, n)
    assert k == k_sha256_sample_secp256r1