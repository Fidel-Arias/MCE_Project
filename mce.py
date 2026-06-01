"""
MCE - Matricial Cipher Engine
Interfaz de linea de comandos

Uso:
  python mce.py genkey --out mi_clave.mce.key
  python mce.py encrypt --in archivo.txt --key mi_clave.mce.key --password MiPass123
  python mce.py decrypt --in archivo.txt.mce --key mi_clave.mce.key --password MiPass123
"""

import argparse
import sys
import os
import time

# Agregar el directorio raiz al path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.mce_engine  import encrypt_data_v2 as encrypt_data, decrypt_data_v2 as decrypt_data
from core.key_manager import generate_keyfile, load_keyfile


ENCRYPTED_EXT = '.mce'


def cmd_genkey(args):
    """Genera un nuevo archivo de clave."""
    out_path = args.out or 'clave.mce.key'
    generate_keyfile(out_path)
    print(f"[OK] Clave generada correctamente en: {out_path}")
    print(f"     IMPORTANTE: Guarda este archivo de forma segura.")
    print(f"     Sin el, no podras descifrar tus archivos.")


def cmd_encrypt(args):
    """Cifra un archivo."""
    in_path  = args.input
    key_path = args.key
    password = args.password

    # Validaciones
    if not os.path.exists(in_path):
        print(f"[ERROR] Archivo no encontrado: {in_path}")
        sys.exit(1)

    # Ruta de salida
    out_path = args.out or (in_path + ENCRYPTED_EXT)

    print(f"[MCE] Cifrando: {in_path}")
    print(f"      Clave   : {key_path}")
    print(f"      Salida  : {out_path}")

    # Cargar keyfile y datos
    keyfile   = load_keyfile(key_path)
    with open(in_path, 'rb') as f:
        plaintext = f.read()

    file_size = len(plaintext)
    print(f"      Tamanio : {file_size:,} bytes")

    # Cifrar
    t_start    = time.perf_counter()
    ciphertext = encrypt_data(plaintext, password, keyfile)
    t_end      = time.perf_counter()

    # Guardar
    with open(out_path, 'wb') as f:
        f.write(ciphertext)

    elapsed = t_end - t_start
    ratio   = len(ciphertext) / file_size if file_size > 0 else 1

    print(f"\n[OK] Cifrado exitoso!")
    print(f"     Tiempo    : {elapsed:.4f} segundos")
    print(f"     Entrada   : {file_size:,} bytes")
    print(f"     Salida    : {len(ciphertext):,} bytes ({ratio:.2f}x)")


def cmd_decrypt(args):
    """Descifra un archivo."""
    in_path  = args.input
    key_path = args.key
    password = args.password

    # Validaciones
    if not os.path.exists(in_path):
        print(f"[ERROR] Archivo no encontrado: {in_path}")
        sys.exit(1)

    # Ruta de salida (quitar extension .mce si existe)
    if args.out:
        out_path = args.out
    elif in_path.endswith(ENCRYPTED_EXT):
        out_path = in_path[:-len(ENCRYPTED_EXT)]
    else:
        out_path = in_path + '.dec'

    print(f"[MCE] Descifrando: {in_path}")
    print(f"      Clave      : {key_path}")
    print(f"      Salida     : {out_path}")

    # Cargar keyfile y datos cifrados
    keyfile = load_keyfile(key_path)
    with open(in_path, 'rb') as f:
        ciphertext = f.read()

    # Descifrar
    t_start = time.perf_counter()
    try:
        plaintext = decrypt_data(ciphertext, password, keyfile)
    except ValueError as e:
        print(f"\n[ERROR] Descifrado fallido: {e}")
        print("        Verifica que la contrasena y el archivo de clave sean correctos.")
        sys.exit(1)
    t_end = time.perf_counter()

    # Guardar
    with open(out_path, 'wb') as f:
        f.write(plaintext)

    elapsed = t_end - t_start
    print(f"\n[OK] Descifrado exitoso!")
    print(f"     Tiempo  : {elapsed:.4f} segundos")
    print(f"     Salida  : {len(plaintext):,} bytes → {out_path}")


def main():
    parser = argparse.ArgumentParser(
        prog='mce',
        description='MCE - Matricial Cipher Engine | Cifrado de archivos por bloques matriciales'
    )
    subparsers = parser.add_subparsers(dest='command', help='Comandos disponibles')

    # Subcomando: genkey
    p_gen = subparsers.add_parser('genkey', help='Genera un archivo de clave .mce.key')
    p_gen.add_argument('--out', help='Ruta del archivo de clave a generar')

    # Subcomando: encrypt
    p_enc = subparsers.add_parser('encrypt', help='Cifra un archivo')
    p_enc.add_argument('--in',       dest='input',    required=True, help='Archivo a cifrar')
    p_enc.add_argument('--key',      required=True,  help='Archivo de clave .mce.key')
    p_enc.add_argument('--password', required=True,  help='Contrasena de cifrado')
    p_enc.add_argument('--out',      help='Archivo de salida (default: entrada.mce)')

    # Subcomando: decrypt
    p_dec = subparsers.add_parser('decrypt', help='Descifra un archivo')
    p_dec.add_argument('--in',       dest='input',    required=True, help='Archivo .mce a descifrar')
    p_dec.add_argument('--key',      required=True,  help='Archivo de clave .mce.key')
    p_dec.add_argument('--password', required=True,  help='Contrasena de cifrado')
    p_dec.add_argument('--out',      help='Archivo de salida (default: nombre sin .mce)')

    args = parser.parse_args()

    if args.command == 'genkey':
        cmd_genkey(args)
    elif args.command == 'encrypt':
        cmd_encrypt(args)
    elif args.command == 'decrypt':
        cmd_decrypt(args)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
