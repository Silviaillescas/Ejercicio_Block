import pytest
from src.des_cipher import encrypt_des_ecb, decrypt_des_ecb
from src.tripledes_cipher import encrypt_3des_cbc, decrypt_3des_cbc
from src.utils import generate_des_key


def test_des_ecb_roundtrip():
    msg = b"Hola DES ECB"
    key, ct = encrypt_des_ecb(msg)
    pt = decrypt_des_ecb(ct, key)
    assert pt == msg


def test_des_ecb_deterministic_same_key():
    msg = b"Mensaje fijo"
    key = generate_des_key()
    _, ct1 = encrypt_des_ecb(msg, key=key)
    _, ct2 = encrypt_des_ecb(msg, key=key)
    assert ct1 == ct2


def test_des_ecb_different_keys_different_ciphertext():
    msg = b"Mensaje fijo"
    key1, ct1 = encrypt_des_ecb(msg)
    key2, ct2 = encrypt_des_ecb(msg)
    assert key1 != key2
    assert ct1 != ct2


def test_3des_cbc_roundtrip():
    msg = b"Hola 3DES CBC"
    key, iv, ct = encrypt_3des_cbc(msg, key_option=2)
    pt = decrypt_3des_cbc(ct, key, iv)
    assert pt == msg


@pytest.mark.parametrize("msg", [b"a", b"1234567", b"12345678", b"1234567890", b"x" * 1000])
def test_des_ecb_various_lengths(msg):
    key, ct = encrypt_des_ecb(msg)
    pt = decrypt_des_ecb(ct, key)
    assert pt == msg