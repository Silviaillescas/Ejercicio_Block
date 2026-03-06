from __future__ import annotations
from Crypto.Cipher import DES
from .utils import generate_des_key, pkcs7_pad, pkcs7_unpad


def encrypt_des_ecb(plaintext: bytes, key: bytes | None = None) -> tuple[bytes, bytes]:
    """
    Cifra DES-ECB usando padding PKCS#7 MANUAL (bloque 8).
    Retorna: (key, ciphertext)
    """
    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError("plaintext debe ser bytes o bytearray")

    plaintext = bytes(plaintext)

    if key is None:
        key = generate_des_key()

    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("key debe ser bytes o bytearray")

    key = bytes(key)
    if len(key) != 8:
        raise ValueError("La clave DES debe ser de 8 bytes")

    padded = pkcs7_pad(plaintext, 8)

    cipher = DES.new(key, DES.MODE_ECB)
    ciphertext = cipher.encrypt(padded)

    return key, ciphertext


def decrypt_des_ecb(ciphertext: bytes, key: bytes) -> bytes:
    """Descifra DES-ECB y remueve padding PKCS#7 manual."""
    if not isinstance(ciphertext, (bytes, bytearray)):
        raise TypeError("ciphertext debe ser bytes o bytearray")
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("key debe ser bytes o bytearray")

    ciphertext = bytes(ciphertext)
    key = bytes(key)

    if len(key) != 8:
        raise ValueError("La clave DES debe ser de 8 bytes")
    if len(ciphertext) == 0 or (len(ciphertext) % 8) != 0:
        raise ValueError("ciphertext inválido: debe ser múltiplo de 8 y no vacío")

    cipher = DES.new(key, DES.MODE_ECB)
    padded_plain = cipher.decrypt(ciphertext)

    return pkcs7_unpad(padded_plain)