from __future__ import annotations
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
from .utils import generate_3des_key, generate_iv

def _normalize_3des_key(key: bytes) -> bytes:
    """
    Asegura que la clave 3DES tenga paridad correcta y no sea una clave inválida/débil
    """
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("key debe ser bytes o bytearray")

    key = bytes(key)

    if len(key) not in (16, 24):
        raise ValueError("La clave 3DES debe ser de 16 o 24 bytes")

    try:
        return DES3.adjust_key_parity(key)
    except ValueError as e:
        raise ValueError(f"Clave 3DES inválida o débil: {e}") from e


def encrypt_3des_cbc(plaintext: bytes, key_option: int = 2) -> tuple[bytes, bytes, bytes]:
    """
    Cifra con 3DES en modo CBC usando:
    - Clave 3DES segura generada con generate_3des_key(16 o 24 bytes)
    - IV aleatorio por operación con generate_iv(8)
    - pad() de Crypto.Util.Padding (PKCS#7)

    Retorna: (key, iv, ciphertext)
    """
    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError("plaintext debe ser bytes o bytearray")

    # 1) Generar clave dinámica (16 o 24 bytes) usando lo que ya hicimos
    key = generate_3des_key(key_option)
    key = _normalize_3des_key(key)

    # 2) Generar IV aleatorio (8 bytes para DES/3DES)
    iv = generate_iv(8)

    # 3) Crear cifrador CBC y aplicar padding (bloque 8)
    cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)
    padded = pad(bytes(plaintext), 8)

    # 4) Cifrar
    ciphertext = cipher.encrypt(padded)

    return key, iv, ciphertext


def decrypt_3des_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Descifra con 3DES en modo CBC usando:
    - unpad() de Crypto.Util.Padding

    Recibe: ciphertext, key (16/24 bytes), iv (8 bytes)
    Retorna: plaintext
    """
    if not isinstance(ciphertext, (bytes, bytearray)):
        raise TypeError("ciphertext debe ser bytes o bytearray")
    if not isinstance(iv, (bytes, bytearray)):
        raise TypeError("iv debe ser bytes o bytearray")

    ciphertext = bytes(ciphertext)
    iv = bytes(iv)

    if len(ciphertext) == 0 or (len(ciphertext) % 8) != 0:
        raise ValueError("ciphertext inválido: debe ser múltiplo de 8 y no vacío")

    if len(iv) != 8:
        raise ValueError("IV inválido: para 3DES-CBC debe ser de 8 bytes")

    key = _normalize_3des_key(key)

    cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)
    padded_plain = cipher.decrypt(ciphertext)

    try:
        plaintext = unpad(padded_plain, 8)
    except ValueError as e:
        raise ValueError(f"No se pudo remover padding: {e}") from e

    return plaintext


if __name__ == "__main__":
    msg = b"Hola hola 3des"
    key, iv, ct = encrypt_3des_cbc(msg, key_option=2)  # 2 - 16 bytes, 3 - 24 bytes

    pt = decrypt_3des_cbc(ct, key, iv)

    print("Plaintext:", msg)
    print("Key (hex):", key.hex())
    print("IV  (hex):", iv.hex())
    print("CT  (hex):", ct.hex())
    print("Decrypted:", pt)
    print("OK:", pt == msg)