"""
MCE Network - SERVIDOR
========================================
Uso:
  python server.py --key secret.mce.key --password TuPassword

El servidor espera conexiones entrantes, recibe el archivo
cifrado, lo descifra con MCE y lo guarda en la carpeta recibidos/
"""

import socket
import struct
import os
import sys
import argparse
import datetime

from mce_engine  import decrypt_data_v2
from key_manager import load_keyfile

# ── Configuración ─────────────────────────────────────────
HOST    = '0.0.0.0'   # escucha en todas las interfaces de red
PORT    = 9999
BUFFER  = 4096
OUTDIR  = 'recibidos'

os.makedirs(OUTDIR, exist_ok=True)


def log(msg, tipo='INFO'):
    hora = datetime.datetime.now().strftime('%H:%M:%S')
    iconos = {'INFO': '📡', 'OK': '✅', 'ERROR': '❌', 'RECV': '📥'}
    print(f"[{hora}] {iconos.get(tipo,'·')} {msg}")


def receive_all(sock, n):
    """Recibe exactamente n bytes del socket."""
    data = b''
    while len(data) < n:
        chunk = sock.recv(min(n - len(data), BUFFER))
        if not chunk:
            raise ConnectionError("Conexión cerrada inesperadamente.")
        data += chunk
    return data


def handle_client(conn, addr, password, keyfile):
    """Maneja una conexión entrante: recibe y descifra el archivo."""
    log(f"Conexión desde {addr[0]}:{addr[1]}", 'INFO')

    try:
        # ── Protocolo de recepción ──────────────────────────
        # 1. Recibir longitud del nombre del archivo (4 bytes)
        name_len_bytes = receive_all(conn, 4)
        name_len       = struct.unpack('>I', name_len_bytes)[0]

        # 2. Recibir nombre del archivo
        filename = receive_all(conn, name_len).decode('utf-8')
        log(f"Archivo entrante: {filename}", 'RECV')

        # 3. Recibir longitud del contenido cifrado (8 bytes)
        data_len_bytes = receive_all(conn, 8)
        data_len       = struct.unpack('>Q', data_len_bytes)[0]
        log(f"Tamaño cifrado: {data_len:,} bytes", 'RECV')

        # 4. Recibir contenido cifrado
        ciphertext = receive_all(conn, data_len)
        log(f"Recepción completa. Descifrando...", 'INFO')

        # ── Descifrar con MCE ───────────────────────────────
        plaintext = decrypt_data_v2(ciphertext, password, keyfile)

        # ── Guardar archivo ─────────────────────────────────
        # Quitar extensión .mce si viene cifrado
        save_name = filename[:-4] if filename.endswith('.mce') else filename
        save_path = os.path.join(OUTDIR, save_name)

        # Evitar sobreescribir: agregar timestamp si ya existe
        if os.path.exists(save_path):
            ts        = datetime.datetime.now().strftime('%H%M%S')
            base, ext = os.path.splitext(save_name)
            save_name = f"{base}_{ts}{ext}"
            save_path = os.path.join(OUTDIR, save_name)

        with open(save_path, 'wb') as f:
            f.write(plaintext)

        log(f"Archivo guardado: {OUTDIR}/{save_name} ({len(plaintext):,} bytes)", 'OK')

        # ── Enviar confirmación al cliente ──────────────────
        ack = f"OK:{save_name}:{len(plaintext)}".encode('utf-8')
        conn.sendall(struct.pack('>I', len(ack)) + ack)

    except ValueError as e:
        log(f"Error de descifrado: {e}", 'ERROR')
        err = f"ERROR:{e}".encode('utf-8')
        conn.sendall(struct.pack('>I', len(err)) + err)

    except Exception as e:
        log(f"Error inesperado: {e}", 'ERROR')

    finally:
        conn.close()


def main():
    parser = argparse.ArgumentParser(description='MCE Network — Servidor receptor')
    parser.add_argument('--key',      required=True, help='Archivo de clave .mce.key')
    parser.add_argument('--password', required=True, help='Contraseña de descifrado')
    parser.add_argument('--port',     type=int, default=PORT, help=f'Puerto (default: {PORT})')
    args = parser.parse_args()

    # Cargar clave
    keyfile = load_keyfile(args.key)

    # Obtener IP local para mostrarla
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except:
        local_ip = "desconocida"

    print("\n" + "="*50)
    print("   MCE Network — SERVIDOR RECEPTOR")
    print("="*50)
    print(f"   IP de esta máquina : {local_ip}")
    print(f"   Puerto             : {args.port}")
    print(f"   Clave              : {args.key}")
    print(f"   Carpeta de salida  : {OUTDIR}/")
    print("="*50)
    print(f"\n   Dile al cliente que use:")
    print(f"   python client.py --host {local_ip} --port {args.port} \\")
    print(f"          --key secret.mce.key --password TuPassword \\")
    print(f"          --file archivo.txt")
    print("\n   Esperando conexiones...\n")

    # ── Iniciar servidor ────────────────────────────────────
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, args.port))
    server.listen(5)

    try:
        while True:
            conn, addr = server.accept()
            handle_client(conn, addr, args.password, keyfile)
            print()  # línea en blanco entre conexiones
    except KeyboardInterrupt:
        log("Servidor detenido por el usuario.", 'INFO')
    finally:
        server.close()


if __name__ == '__main__':
    main()
