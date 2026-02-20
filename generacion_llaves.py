"""
Generación de claves criptográficas usando secrets.
Estas funciones serán reutilizadas en todas las partes del laboratorio.
"""

import secrets
import random 


def generate_des_key() -> bytes:
    """
    Genera una clave DES de 8 bytes (64 bits).
    """
    return secrets.token_bytes(8)


def generate_3des_key(key_option: int = 2) -> bytes:
    """
    Genera una clave para 3DES.

    key_option:
    - 2 -> 16 bytes (2-key 3DES)
    - 3 -> 24 bytes (3-key 3DES)
    """
    if key_option not in (2, 3):
        raise ValueError("key_option debe ser 2 o 3")

    key_length = 16 if key_option == 2 else 24
    return secrets.token_bytes(key_length)


def generate_aes_key(key_size: int = 256) -> bytes:
    """
    Genera una clave AES.

    key_size válido: 128, 192 o 256 bits.
    """
    if key_size not in (128, 192, 256):
        raise ValueError("key_size debe ser 128, 192 o 256")

    return secrets.token_bytes(key_size // 8)


def generate_iv(block_size: int = 8) -> bytes:
    """
    Genera un vector de inicialización (IV) aleatorio.

    - DES / 3DES -> block_size = 8
    - AES        -> block_size = 16
    """
    if not isinstance(block_size, int) or block_size <= 0:
        raise ValueError("block_size debe ser un entero positivo")

    return secrets.token_bytes(block_size)


if __name__ == "__main__":
    des_key = generate_des_key()
    des3_key_2 = generate_3des_key(2)
    des3_key_3 = generate_3des_key(3)
    aes_key_128 = generate_aes_key(128)
    aes_key_256 = generate_aes_key(256)
    iv_des = generate_iv(8)
    iv_aes = generate_iv(16)

    print("DES key:", des_key.hex())
    print("3DES (2-key):", des3_key_2.hex())
    print("3DES (3-key):", des3_key_3.hex())
    print("AES-128:", aes_key_128.hex())
    print("AES-256:", aes_key_256.hex())
    print("IV DES:", iv_des.hex())
    print("IV AES:", iv_aes.hex())
