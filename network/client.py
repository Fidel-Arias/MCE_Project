"""
MCE Network - CLIENTE
========================================
Uso:
  python client.py --host 192.168.1.X --key secret.mce.key
                   --password TuPassword --file documento.pdf

Cifra el archivo con MCE y lo envía al servidor por TCP.
"""

import socket
import struct
import os
import sys
import argparse
import datetime
import time

from mce_engine  import encrypt_data_v2
from key_manager import load_keyfile

# ── Configuración ─────────────────────────────────────────
PORT   = 9999
BUFFER = 4096


def log(msg, tipo='INFO'):
    hora = datetime.datetime.now().strftime('%H:%M:%S')
    iconos = {'INFO': '📡', 'OK': '✅', 'ERROR': '❌', 'SEND': '📤'}
    print(f"[{hora}] {iconos.get(tipo,'·')} {msg}")


def human_size(n):
    for unit in ['B', 'KB', 'MB']:
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"


def send_file(host, port, filepath, password, keyfile):
    """Cifra el archivo y lo envía al servidor."""

    # ── Leer archivo ────────────────────────────────────────
    if not os.path.exists(filepath):
        log(f"Archivo no encontrado: {filepath}", 'ERROR')
        sys.exit(1)

    filename = os.path.basename(filepath)
    with open(filepath, 'rb') as f:
        plaintext = f.read()

    log(f"Archivo    : {filename} ({human_size(len(plaintext))})", 'INFO')

    # ── Cifrar con MCE ──────────────────────────────────────
    log("Cifrando con MCE v2...", 'INFO')
    t0         = time.perf_counter()
    ciphertext = encrypt_data_v2(plaintext, password, keyfile)
    t_enc      = time.perf_counter() - t0
    log(f"Cifrado OK : {human_size(len(ciphertext))} en {t_enc*1000:.1f} ms", 'OK')

    # El nombre que se envía lleva .mce para que el servidor sepa que está cifrado
    send_name = filename + '.mce'

    # ── Conectar al servidor ────────────────────────────────
    log(f"Conectando a {host}:{port}...", 'INFO')

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(15)
        sock.connect((host, port))
        log(f"Conexión establecida con {host}:{port}", 'OK')
    except (ConnectionRefusedError, socket.timeout):
        log(f"No se pudo conectar a {host}:{port}. Verifica que el servidor esté corriendo.", 'ERROR')
        sys.exit(1)

    try:
        # ── Protocolo de envío ──────────────────────────────
        # 1. Enviar longitud del nombre (4 bytes)
        name_bytes = send_name.encode('utf-8')
        sock.sendall(struct.pack('>I', len(name_bytes)))

        # 2. Enviar nombre del archivo
        sock.sendall(name_bytes)

        # 3. Enviar longitud del contenido cifrado (8 bytes)
        sock.sendall(struct.pack('>Q', len(ciphertext)))

        # 4. Enviar contenido cifrado en chunks con barra de progreso
        log(f"Enviando archivo cifrado...", 'SEND')
        sent    = 0
        t_start = time.perf_counter()

        while sent < len(ciphertext):
            chunk = ciphertext[sent:sent + BUFFER]
            sock.sendall(chunk)
            sent += len(chunk)
            pct   = (sent / len(ciphertext)) * 100
            print(f"\r   Progreso: {pct:.0f}% ({human_size(sent)} / {human_size(len(ciphertext))})", end='', flush=True)

        t_send = time.perf_counter() - t_start
        print()  # nueva línea tras la barra

        speed = len(ciphertext) / t_send / 1024 if t_send > 0 else 0
        log(f"Envío completo en {t_send*1000:.0f} ms ({speed:.0f} KB/s)", 'OK')

        # ── Recibir confirmación del servidor ───────────────
        sock.settimeout(10)
        ack_len  = struct.unpack('>I', sock.recv(4))[0]
        ack      = sock.recv(ack_len).decode('utf-8')

        if ack.startswith('OK:'):
            parts     = ack.split(':')
            saved_as  = parts[1] if len(parts) > 1 else 'desconocido'
            saved_sz  = parts[2] if len(parts) > 2 else '?'
            log(f"Servidor confirmó recepción → guardado como '{saved_as}' ({saved_sz} bytes)", 'OK')
        else:
            log(f"El servidor reportó un error: {ack}", 'ERROR')

    except Exception as e:
        log(f"Error durante el envío: {e}", 'ERROR')
    finally:
        sock.close()


def main():
    parser = argparse.ArgumentParser(description='MCE Network — Cliente emisor')
    parser.add_argument('--host',     required=True, help='IP del servidor (ej: 192.168.1.10)')
    parser.add_argument('--file',     required=True, help='Archivo a cifrar y enviar')
    parser.add_argument('--key',      required=True, help='Archivo de clave .mce.key')
    parser.add_argument('--password', required=True, help='Contraseña de cifrado')
    parser.add_argument('--port',     type=int, default=PORT, help=f'Puerto (default: {PORT})')
    args = parser.parse_args()

    print("\n" + "="*50)
    print("   MCE Network — CLIENTE EMISOR")
    print("="*50)
    print(f"   Destino  : {args.host}:{args.port}")
    print(f"   Archivo  : {args.file}")
    print(f"   Clave    : {args.key}")
    print("="*50 + "\n")

    keyfile = load_keyfile(args.key)
    send_file(args.host, args.port, args.file, args.password, keyfile)

    print()


if __name__ == '__main__':
    main()
