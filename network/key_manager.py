"""
MCE - Key Manager
Genera y carga archivos de clave (.mce.key)
"""

import os
import hashlib


KEY_SIZE = 256  # bytes de entropia en el archivo de clave


def generate_keyfile(path: str) -> bytes:
    """
    Genera un archivo de clave aleatorio de 256 bytes.
    Lo guarda en 'path' y retorna su contenido.
    """
    key_data = os.urandom(KEY_SIZE)
    with open(path, 'wb') as f:
        f.write(key_data)
    print(f"[MCE] Archivo de clave generado: {path}")
    return key_data


def load_keyfile(path: str) -> bytes:
    """
    Carga un archivo de clave existente.
    Lanza FileNotFoundError si no existe.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"Archivo de clave no encontrado: {path}")
    with open(path, 'rb') as f:
        data = f.read()
    if len(data) < 32:
        raise ValueError("El archivo de clave es demasiado pequeno (minimo 32 bytes).")
    # Normalizar a 256 bytes usando hash si es mas corto
    if len(data) < KEY_SIZE:
        data = hashlib.sha256(data).digest() * (KEY_SIZE // 32)
    return data[:KEY_SIZE]
