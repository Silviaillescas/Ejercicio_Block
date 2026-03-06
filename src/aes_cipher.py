from Crypto.Cipher import AES
from PIL import Image

from .utils import generate_aes_key, generate_iv


def _load_image_bytes(image_path: str) -> tuple[bytes, tuple[int, int], str]:
    """
    Abre una imagen PNG y devuelve:
    - bytes de pixeles
    - tamaño
    - modo
    """
    img = Image.open(image_path).convert("RGB")
    data = img.tobytes()
    return data, img.size, img.mode


def _save_image_bytes(data: bytes, size: tuple[int, int], mode: str, output_path: str):
    """
    Reconstruye una imagen a partir de bytes de pixeles.
    """
    img = Image.frombytes(mode, size, data)
    img.save(output_path)


def encrypt_image_aes_ecb(input_path: str, output_path: str) -> bytes:
    """
    Cifra los pixeles de una imagen PNG usando AES-256 en modo ECB.
    """
    key = generate_aes_key(256)

    pixel_data, size, mode = _load_image_bytes(input_path)

    body_len = len(pixel_data) - (len(pixel_data) % 16)
    body_to_encrypt = pixel_data[:body_len]
    remainder = pixel_data[body_len:]

    cipher = AES.new(key, AES.MODE_ECB)
    encrypted_body = cipher.encrypt(body_to_encrypt)

    encrypted_data = encrypted_body + remainder
    _save_image_bytes(encrypted_data, size, mode, output_path)

    return key


def encrypt_image_aes_cbc(input_path: str, output_path: str) -> tuple[bytes, bytes]:
    """
    Cifra los pixeles de una imagen PNG usando AES-256 en modo CBC.
    """
    key = generate_aes_key(256)
    iv = generate_iv(16)

    pixel_data, size, mode = _load_image_bytes(input_path)

    body_len = len(pixel_data) - (len(pixel_data) % 16)
    body_to_encrypt = pixel_data[:body_len]
    remainder = pixel_data[body_len:]

    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    encrypted_body = cipher.encrypt(body_to_encrypt)

    encrypted_data = encrypted_body + remainder
    _save_image_bytes(encrypted_data, size, mode, output_path)

    return key, iv