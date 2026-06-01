"""
MCE - Matricial Cipher Engine
Metodo criptografico propio basado en transformaciones matriciales.
Autor: Trabajo de Fase - Criptografia
"""

import numpy as np
import hashlib
import os
import struct

# ─────────────────────────────────────────
# CONSTANTES DEL ALGORITMO
# ─────────────────────────────────────────
BLOCK_SIZE  = 32   # bytes por bloque
ROWS        = 4    # filas de la matriz
COLS        = 8    # columnas (4x8 = 32 bytes)
ROUNDS      = 5    # rondas de cifrado
MAGIC       = b'MCE1'  # firma del archivo cifrado

# Tabla de desplazamientos por fila (ROT fija, varía por ronda)
ROW_SHIFTS = [1, 3, 5, 7, 2]  # uno por ronda, para las 4 filas rota distinto


# ─────────────────────────────────────────
# DERIVACION DE CLAVE
# ─────────────────────────────────────────

def derive_subkeys(password: str, keyfile: bytes, rounds: int = ROUNDS) -> list[bytes]:
    """
    Deriva 'rounds' subclaves de 32 bytes cada una.
    Combina contrasena + contenido del archivo de clave con SHA-256.
    Cada subclave se obtiene con una semilla diferente por ronda.
    """
    # Material base: hash de password + hash de keyfile
    base = hashlib.sha256(password.encode('utf-8') + keyfile).digest()

    subkeys = []
    for i in range(rounds):
        # Mezcla la base con el indice de ronda para diversificar
        seed = base + struct.pack('>I', i) + base[::-1]
        sk   = hashlib.sha256(seed).digest()  # 32 bytes exactos
        subkeys.append(sk)

    return subkeys  # lista de 'rounds' bytes-objects de 32 bytes


# ─────────────────────────────────────────
# TRANSFORMACIONES MATRICIALES
# ─────────────────────────────────────────

def bytes_to_matrix(block: bytes) -> np.ndarray:
    """Convierte 32 bytes en matriz 4x8 de uint8."""
    return np.frombuffer(block, dtype=np.uint8).reshape(ROWS, COLS).copy()


def matrix_to_bytes(mat: np.ndarray) -> bytes:
    """Convierte matriz 4x8 de regreso a 32 bytes."""
    return mat.flatten().tobytes()


def xor_with_subkey(mat: np.ndarray, subkey: bytes) -> np.ndarray:
    """XOR de cada byte de la matriz con el byte correspondiente de la subclave."""
    sk_mat = np.frombuffer(subkey, dtype=np.uint8).reshape(ROWS, COLS)
    return np.bitwise_xor(mat, sk_mat)


def row_shift(mat: np.ndarray, shift: int, inverse: bool = False) -> np.ndarray:
    """
    Desplazamiento circular de filas.
    Fila i se rota (i+1)*shift posiciones a la izquierda.
    Inverso: rota a la derecha.
    """
    result = mat.copy()
    for i in range(ROWS):
        n = ((i + 1) * shift) % COLS
        if inverse:
            result[i] = np.roll(mat[i], n)    # derecha
        else:
            result[i] = np.roll(mat[i], -n)   # izquierda
    return result


def modular_transform(mat: np.ndarray, subkey: bytes, inverse: bool = False) -> np.ndarray:
    """
    Transformacion modular columna a columna.
    Suma o resta el valor de la subclave mod 256 a cada columna.
    """
    sk = np.frombuffer(subkey, dtype=np.uint8).reshape(ROWS, COLS)
    if inverse:
        return ((mat.astype(np.int16) - sk.astype(np.int16)) % 256).astype(np.uint8)
    else:
        return ((mat.astype(np.int16) + sk.astype(np.int16)) % 256).astype(np.uint8)


def transpose_matrix(mat: np.ndarray) -> np.ndarray:
    """
    Transpone la matriz 4x8 → 8x4 y la reshape a 4x8 de nuevo.
    Esto permuta los bytes de manera no trivial.
    """
    transposed = mat.T.flatten()              # 8x4 aplanado = 32 bytes
    return transposed.reshape(ROWS, COLS)     # vuelve a 4x8


def inverse_transpose(mat: np.ndarray) -> np.ndarray:
    """
    Inverso de transpose_matrix.
    Reconstruye el orden original antes de transposicion.
    """
    flat = mat.flatten()
    return flat.reshape(COLS, ROWS).T.reshape(ROWS, COLS)


# ─────────────────────────────────────────
# CIFRADO / DESCIFRADO DE UN BLOQUE
# ─────────────────────────────────────────

def encrypt_block(block: bytes, subkeys: list[bytes]) -> bytes:
    """
    Cifra un bloque de 32 bytes aplicando 5 rondas.
    Cada ronda: XOR → row_shift → modular_transform → transpose
    """
    mat = bytes_to_matrix(block)

    for r in range(ROUNDS):
        mat = xor_with_subkey(mat, subkeys[r])
        mat = row_shift(mat, ROW_SHIFTS[r], inverse=False)
        mat = modular_transform(mat, subkeys[r], inverse=False)
        mat = transpose_matrix(mat)

    return matrix_to_bytes(mat)


def decrypt_block(block: bytes, subkeys: list[bytes]) -> bytes:
    """
    Descifra un bloque de 32 bytes revirtiendo exactamente las 5 rondas.
    Cada ronda inversa: inv_transpose → inv_modular → inv_row_shift → XOR
    """
    mat = bytes_to_matrix(block)

    for r in reversed(range(ROUNDS)):
        mat = inverse_transpose(mat)
        mat = modular_transform(mat, subkeys[r], inverse=True)
        mat = row_shift(mat, ROW_SHIFTS[r], inverse=True)
        mat = xor_with_subkey(mat, subkeys[r])

    return matrix_to_bytes(mat)


# ─────────────────────────────────────────
# PADDING (para archivos que no son multiplo de 32)
# ─────────────────────────────────────────

def add_padding(data: bytes) -> bytes:
    """
    PKCS7-style: agrega N bytes de valor N para completar el bloque.
    Si ya es multiplo exacto, agrega un bloque completo de padding.
    """
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len] * pad_len)


def remove_padding(data: bytes) -> bytes:
    """Elimina el padding agregado por add_padding."""
    if not data:
        return data
    pad_len = data[-1]
    if pad_len < 1 or pad_len > BLOCK_SIZE:
        raise ValueError("Padding invalido: el archivo puede estar corrupto o la clave es incorrecta.")
    return data[:-pad_len]


# ─────────────────────────────────────────
# CIFRADO / DESCIFRADO DE ARCHIVO COMPLETO
# ─────────────────────────────────────────

def encrypt_data(plaintext: bytes, password: str, keyfile: bytes) -> bytes:
    """
    Cifra datos completos (cualquier longitud).
    Formato de salida:
      [MAGIC 4B][IV 32B][DATOS_CIFRADOS]
    El IV es un bloque aleatorio que cifra el primer bloque real
    para que el mismo archivo con la misma clave de resultados distintos.
    """
    subkeys = derive_subkeys(password, keyfile)

    # IV aleatorio para evitar determinismo
    iv = os.urandom(BLOCK_SIZE)

    # Aplicar padding
    padded = add_padding(plaintext)

    # Cifrar bloque a bloque (CBC-like: XOR con bloque anterior)
    ciphertext = b''
    prev_block  = iv

    for i in range(0, len(padded), BLOCK_SIZE):
        block     = padded[i:i + BLOCK_SIZE]
        # CBC: XOR con bloque previo antes de cifrar
        chained   = bytes(a ^ b for a, b in zip(block, prev_block))
        enc_block = encrypt_block(chained, subkeys)
        ciphertext += enc_block
        prev_block  = enc_block

    return MAGIC + iv + ciphertext


def decrypt_data(ciphertext_full: bytes, password: str, keyfile: bytes) -> bytes:
    """
    Descifra datos cifrados con encrypt_data.
    Verifica la firma MAGIC antes de proceder.
    """
    # Verificar firma
    if not ciphertext_full.startswith(MAGIC):
        raise ValueError("El archivo no es un archivo MCE valido o esta corrupto.")

    # Extraer IV y datos cifrados
    offset     = len(MAGIC)
    iv         = ciphertext_full[offset:offset + BLOCK_SIZE]
    ciphertext = ciphertext_full[offset + BLOCK_SIZE:]

    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError("Longitud de datos cifrados invalida.")

    subkeys = derive_subkeys(password, keyfile)

    # Descifrar bloque a bloque (CBC inverso)
    plaintext  = b''
    prev_block = iv

    for i in range(0, len(ciphertext), BLOCK_SIZE):
        enc_block = ciphertext[i:i + BLOCK_SIZE]
        dec_block = decrypt_block(enc_block, subkeys)
        # Des-encadenar: XOR con bloque previo
        block     = bytes(a ^ b for a, b in zip(dec_block, prev_block))
        plaintext += block
        prev_block = enc_block

    return remove_padding(plaintext)


# ─────────────────────────────────────────
# INTEGRIDAD: HMAC-SHA256
# ─────────────────────────────────────────

import hmac

def _compute_hmac(data: bytes, password: str, keyfile: bytes) -> bytes:
    """Calcula HMAC-SHA256 para verificar integridad."""
    mac_key = hashlib.sha256(b'MCE-HMAC' + password.encode() + keyfile).digest()
    return hmac.new(mac_key, data, hashlib.sha256).digest()


def encrypt_data_v2(plaintext: bytes, password: str, keyfile: bytes) -> bytes:
    """
    Cifra + agrega HMAC para detectar corrupcion o clave incorrecta.
    Formato: [MAGIC 4B][HMAC 32B][IV 32B][DATOS_CIFRADOS]
    """
    # Cifrar primero
    raw = encrypt_data(plaintext, password, keyfile)
    # Calcular HMAC sobre todo el contenido cifrado
    mac = _compute_hmac(raw, password, keyfile)
    # Insertar HMAC despues del MAGIC
    return raw[:4] + mac + raw[4:]


def decrypt_data_v2(ciphertext_full: bytes, password: str, keyfile: bytes) -> bytes:
    """
    Verifica HMAC y luego descifra.
    Lanza ValueError si la clave es incorrecta o el archivo esta corrupto.
    """
    if not ciphertext_full.startswith(MAGIC):
        raise ValueError("Firma MCE invalida.")

    # Extraer HMAC (bytes 4..36)
    stored_mac = ciphertext_full[4:36]
    # Reconstruir datos sin el HMAC intercalado
    raw = ciphertext_full[:4] + ciphertext_full[36:]

    # Verificar HMAC
    expected_mac = _compute_hmac(raw, password, keyfile)
    if not hmac.compare_digest(stored_mac, expected_mac):
        raise ValueError("HMAC invalido: archivo corrupto o clave incorrecta.")

    return decrypt_data(raw, password, keyfile)
