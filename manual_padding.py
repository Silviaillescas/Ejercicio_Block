"""
Implementación manual de Padding PKCS#7.
Este módulo será reutilizado en la Parte 1.1 del laboratorio.
"""

def pkcs7_pad(data: bytes, block_size: int = 8) -> bytes:
    """
    Aplica padding PKCS#7 a los datos.

    Regla:
    - Si faltan N bytes para completar el bloque,
      se agregan N bytes con el valor N.
    - Si el mensaje ya es múltiplo del tamaño del bloque,
      se agrega un bloque completo de padding.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data debe ser bytes o bytearray")

    if not isinstance(block_size, int) or not (1 <= block_size <= 255):
        raise ValueError("block_size debe ser un entero entre 1 y 255")

    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size

    padding = bytes([pad_len]) * pad_len
    return bytes(data) + padding


def pkcs7_unpad(data: bytes) -> bytes:
    """
    Elimina el padding PKCS#7 de los datos.
    """
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


if __name__ == "__main__":
    mensaje = b"LABORATORIO"
    bloque = 8

    padded = pkcs7_pad(mensaje, bloque)
    unpadded = pkcs7_unpad(padded)

    print("Mensaje original:", mensaje)
    print("Mensaje con padding (hex):", padded.hex())
    print("Mensaje sin padding:", unpadded)
