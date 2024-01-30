from cryptography.ecdsa import ECDSA
from cryptography.curves.secp256r1 import p, a, b, origin_G, n
from tests.vectors import h_sha256_sample_secp256r1, m_sha256_sample_secp256r1, x_sha256_sample_secp256r1, x1_pub_sha256_sample_secp256r1, x2_pub_sha256_sample_secp256r1, r_sha256_sample_secp256r1, s_sha256_sample_secp256r1, k_sha256_sample_secp256r1


def test_non_deterministic_sign():
    ecdsa_test = ECDSA(p, a, b, origin_G, n, h_sha256_sample_secp256r1)
    if len(hex(r_sha256_sample_secp256r1)[2:]) // 2 == 0:
        len_r_bytes = len(hex(r_sha256_sample_secp256r1)[2:])
    else:
        len_r_bytes = len(hex(r_sha256_sample_secp256r1)[2:]) + 1
    if len(hex(s_sha256_sample_secp256r1)[2:]) // 2 == 0:
        len_s_bytes = len(hex(r_sha256_sample_secp256r1)[2:])
    else:
        len_s_bytes = len(hex(r_sha256_sample_secp256r1)[2:]) + 1
    if len(hex(x_sha256_sample_secp256r1)[2:]) // 2 == 0:
        len_x_bytes = len(hex(x_sha256_sample_secp256r1)[2:])
    else:
        len_x_bytes = len(hex(x_sha256_sample_secp256r1)[2:]) + 1
    r_vector = r_sha256_sample_secp256r1.to_bytes(len_r_bytes, byteorder='big')
    s_vector = s_sha256_sample_secp256r1.to_bytes(len_s_bytes, byteorder='big')
    x_vector = x_sha256_sample_secp256r1.to_bytes(len_x_bytes, byteorder='big')
    sig_vector = r_vector + s_vector
    assert ecdsa_test.non_deterministic_sign(k_sha256_sample_secp256r1, m_sha256_sample_secp256r1, x_vector) == sig_vector


def test_deterministic_sign():
    ecdsa_test = ECDSA(p, a, b, origin_G, n, h_sha256_sample_secp256r1)
    if len(hex(r_sha256_sample_secp256r1)[2:]) // 2 == 0:
        len_r_bytes = len(hex(r_sha256_sample_secp256r1)[2:])
    else:
        len_r_bytes = len(hex(r_sha256_sample_secp256r1)[2:]) + 1
    if len(hex(s_sha256_sample_secp256r1)[2:]) // 2 == 0:
        len_s_bytes = len(hex(r_sha256_sample_secp256r1)[2:])
    else:
        len_s_bytes = len(hex(r_sha256_sample_secp256r1)[2:]) + 1
    if len(hex(x_sha256_sample_secp256r1)[2:]) // 2 == 0:
        len_x_bytes = len(hex(x_sha256_sample_secp256r1)[2:])
    else:
        len_x_bytes = len(hex(x_sha256_sample_secp256r1)[2:]) + 1
    r_vector = r_sha256_sample_secp256r1.to_bytes(len_r_bytes, byteorder='big')
    s_vector = s_sha256_sample_secp256r1.to_bytes(len_s_bytes, byteorder='big')
    x_vector = x_sha256_sample_secp256r1.to_bytes(len_x_bytes, byteorder='big')
    sig_vector = r_vector + s_vector
    assert ecdsa_test.deterministic_sign(m_sha256_sample_secp256r1, x_vector) == sig_vector


def test_verify():
    ecdsa_test = ECDSA(p, a, b, origin_G, n, h_sha256_sample_secp256r1)
    if len(hex(r_sha256_sample_secp256r1)[2:]) // 2 == 0:
        len_r_bytes = len(hex(r_sha256_sample_secp256r1)[2:])
    else:
        len_r_bytes = len(hex(r_sha256_sample_secp256r1)[2:]) + 1
    if len(hex(s_sha256_sample_secp256r1)[2:]) // 2 == 0:
        len_s_bytes = len(hex(r_sha256_sample_secp256r1)[2:])
    else:
        len_s_bytes = len(hex(r_sha256_sample_secp256r1)[2:]) + 1
    r_vector = r_sha256_sample_secp256r1.to_bytes(len_r_bytes, byteorder='big')
    s_vector = s_sha256_sample_secp256r1.to_bytes(len_s_bytes, byteorder='big')
    x1_pub_vector = x1_pub_sha256_sample_secp256r1.to_bytes(32, byteorder='big')
    x2_pub_vector = x2_pub_sha256_sample_secp256r1.to_bytes(32, byteorder='big')
    sig_vector = r_vector + s_vector
    pubKey_vector = x1_pub_vector + x2_pub_vector
    assert ecdsa_test.verify(sig_vector, m_sha256_sample_secp256r1, pubKey_vector)