import secrets

# Generación de llaves

def generate_des_key() -> bytes:
    """Genera una clave DES de 8 bytes (64 bits)."""
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
    """Genera una clave AES de 128, 192 o 256 bits."""
    if key_size not in (128, 192, 256):
        raise ValueError("key_size debe ser 128, 192 o 256")
    return secrets.token_bytes(key_size // 8)


def generate_iv(block_size: int) -> bytes:
    """
    Genera un IV aleatorio.
    - DES/3DES: 8 bytes
    - AES: 16 bytes
    """
    if not isinstance(block_size, int) or block_size <= 0:
        raise ValueError("block_size debe ser un entero positivo")
    return secrets.token_bytes(block_size)


# PKCS#7 manual 
def pkcs7_pad(data: bytes, block_size: int = 8) -> bytes:
    """Aplica padding PKCS#7 manual."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data debe ser bytes o bytearray")
    if not isinstance(block_size, int) or not (1 <= block_size <= 255):
        raise ValueError("block_size debe ser un entero entre 1 y 255")

    data = bytes(data)
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size

    return data + (bytes([pad_len]) * pad_len)


def pkcs7_unpad(data: bytes) -> bytes:
    """Remueve padding PKCS#7 manual."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data debe ser bytes o bytearray")

    data = bytes(data)
    if len(data) == 0:
        raise ValueError("No se puede remover padding de datos vacíos")

    pad_len = data[-1]
    if pad_len < 1 or pad_len > len(data):
        raise ValueError("Padding inválido")

    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Padding inválido")

    return data[:-pad_len]