# Parte 2: Análisis de Seguridad

## 2.1 Análisis de tamaños de clave

En esta implementación se utilizaron los siguientes tamaños de clave:

| Algoritmo | Tamaño (bytes) | Tamaño (bits) |
|---|---|---|
| DES | 8 bytes | 64 bits (56 bits efectivos) |
| 3DES (2-key) | 16 bytes | 128 bits |
| 3DES (3-key) | 24 bytes | 192 bits |
| AES-256 | 32 bytes | 256 bits |

DES se considera inseguro hoy en día porque su espacio efectivo de claves es de **2⁵⁶**, lo cual permite ataques de fuerza bruta con hardware moderno. Por esta razón, DES fue retirado como estándar criptográfico y reemplazado por algoritmos más robustos como AES.

Si se considera un hardware capaz de probar aproximadamente **10⁹ claves por segundo**, el tiempo aproximado para un ataque de fuerza bruta sería:

| Algoritmo | Espacio de claves | Tiempo aproximado |
|---|---|---|
| DES | 2⁵⁶ | ~1.14 años |
| 3DES (112 bits efectivos) | 2¹¹² | ~8.23 × 10¹⁶ años |
| AES-256 | 2²⁵⁶ | ~1.84 × 10⁶⁰ años |

Esto demuestra que DES ya no proporciona un nivel adecuado de seguridad, mientras que AES-256 sigue siendo seguro frente a ataques de fuerza bruta con la tecnología actual.

### Generación de claves en la implementación

```python
from src.utils import generate_des_key, generate_3des_key, generate_aes_key

des_key = generate_des_key()
des3_key_2 = generate_3des_key(2)
des3_key_3 = generate_3des_key(3)
aes_key = generate_aes_key(256)

print("DES:", len(des_key), "bytes =", len(des_key)*8, "bits")
print("3DES (2-key):", len(des3_key_2), "bytes =", len(des3_key_2)*8, "bits")
print("3DES (3-key):", len(des3_key_3), "bytes =", len(des3_key_3)*8, "bits")
print("AES-256:", len(aes_key), "bytes =", len(aes_key)*8, "bits")
```

---

## 2.2 Comparación de modos de operación

En este laboratorio se implementaron los siguientes modos de operación:

- **DES → ECB**
- **3DES → CBC**
- **AES → ECB y CBC**

La diferencia principal entre ambos modos es que **ECB cifra cada bloque de forma independiente**, mientras que **CBC encadena cada bloque con el anterior mediante una operación XOR y un vector de inicialización (IV)**.

Debido a esto:

- En **ECB**, bloques idénticos de texto plano producen bloques cifrados idénticos.
- En **CBC**, el encadenamiento rompe ese patrón.

Esto se puede observar claramente al cifrar una imagen.

### Comparación visual

| Original | AES-ECB | AES-CBC |
|---|---|---|
| ![](images/pic.png) | ![](images/aes_ecb.png) | ![](images/aes_cbc.png) |

En la imagen cifrada con **ECB** aún se pueden distinguir patrones de la imagen original, especialmente en áreas grandes con el mismo color. En cambio, en **CBC** esos patrones desaparecen, mostrando una distribución aparentemente aleatoria de los píxeles.

### Código utilizado

```python
from src.aes_cipher import encrypt_image_aes_ecb, encrypt_image_aes_cbc

encrypt_image_aes_ecb("images/pic.png", "images/aes_ecb.png")
encrypt_image_aes_cbc("images/pic.png", "images/aes_cbc.png")
```

---

## 2.3 Vulnerabilidad de ECB

El modo ECB no debe utilizarse para datos sensibles porque **filtra patrones del texto plano**.

Para demostrar esto se utilizó un mensaje repetido:

```python
mensaje = b"ATAQUE ATAQUE ATAQUE"
```

Cuando se cifra este mensaje:

- **ECB:** bloques idénticos producen cifrados idénticos.
- **CBC:** los bloques cifrados cambian debido al encadenamiento y al IV.

### Ejemplo conceptual

| Bloque | Texto plano | ECB | CBC |
|---|---|---|---|
| 1 | ATAQUE | A1B3... | C8F2... |
| 2 | ATAQUE | A1B3... | 7D9A... |
| 3 | ATAQUE | A1B3... | 19C4... |

Esto puede revelar información sobre:

- patrones en imágenes
- registros repetidos en bases de datos
- estructuras de documentos
- campos repetidos en formularios

---

## 2.4 Vector de Inicialización (IV)

El **Vector de Inicialización (IV)** es un valor aleatorio utilizado en modos como CBC para introducir variabilidad en el cifrado.

Su propósito es evitar que el mismo mensaje cifrado con la misma clave produzca siempre el mismo resultado.

### Experimento

Se cifró el mismo mensaje dos veces:

1. usando **el mismo IV**
2. usando **IVs diferentes**

```python
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad
from src.utils import generate_3des_key, generate_iv

msg = b"Mensaje CBC"
key = generate_3des_key(2)

iv1 = generate_iv(8)
iv2 = generate_iv(8)

cipher1 = DES3.new(key, DES3.MODE_CBC, iv=iv1)
ct1 = cipher1.encrypt(pad(msg, 8))

cipher2 = DES3.new(key, DES3.MODE_CBC, iv=iv1)
ct2 = cipher2.encrypt(pad(msg, 8))

cipher3 = DES3.new(key, DES3.MODE_CBC, iv=iv2)
ct3 = cipher3.encrypt(pad(msg, 8))

print(ct1.hex())
print(ct2.hex())
print(ct3.hex())
```

Resultados esperados:

- `ct1 == ct2` cuando se usa el mismo IV.
- `ct3` es diferente cuando se usa un IV distinto.

---

## 2.5 Padding

El **padding** permite completar el tamaño del bloque cuando el mensaje no tiene la longitud requerida por el algoritmo.

En DES y 3DES el tamaño de bloque es **8 bytes**, por lo que se utilizó **PKCS#7 padding**.

### Ejemplos

```python
from src.utils import pkcs7_pad, pkcs7_unpad

m1 = b"HELLO"
m2 = b"12345678"
m3 = b"ABCDEFGHIJ"

print(pkcs7_pad(m1, 8).hex())
print(pkcs7_pad(m2, 8).hex())
print(pkcs7_pad(m3, 8).hex())

print(pkcs7_unpad(pkcs7_pad(m1, 8)))
print(pkcs7_unpad(pkcs7_pad(m2, 8)))
print(pkcs7_unpad(pkcs7_pad(m3, 8)))
```

Explicación:

| Mensaje | Padding agregado |
|---|---|
| 5 bytes | `03 03 03` |
| 8 bytes | `08 08 08 08 08 08 08 08` |
| 10 bytes | `06 06 06 06 06 06` |

La función `pkcs7_unpad` elimina correctamente el padding y recupera el mensaje original.

---

## 2.6 Recomendaciones de uso

| Modo | Uso recomendado | Desventajas |
|---|---|---|
| ECB | Uso educativo o datos sin estructura | Filtra patrones |
| CBC | Cifrado tradicional de archivos o datos | Requiere IV y no autentica |
| CTR | Cifrado rápido tipo stream | Requiere nonce único |
| GCM | Aplicaciones modernas seguras | Requiere manejo correcto de nonce |

Actualmente, los sistemas modernos prefieren **modos autenticados (AEAD)** como **AES-GCM**, ya que proporcionan:

- confidencialidad  
- integridad  
- autenticación  

