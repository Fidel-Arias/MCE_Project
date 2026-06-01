"""
SecureVault - Plataforma de cifrado MCE
Demo web con Flask — incluye módulo de red TCP
"""

from flask import Flask, render_template, request, jsonify
import os, io, time, base64, math, socket, struct, threading, datetime

from mce_engine  import encrypt_data_v2, decrypt_data_v2
from key_manager import generate_keyfile

app = Flask(__name__)
app.secret_key = os.urandom(32)

UPLOAD_FOLDER   = os.path.join(os.path.dirname(__file__), 'uploads')
DOWNLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'downloads')
RECEIVED_FOLDER = os.path.join(os.path.dirname(__file__), 'recibidos')
MAX_SIZE_MB     = 10
BUFFER          = 4096

os.makedirs(UPLOAD_FOLDER,   exist_ok=True)
os.makedirs(DOWNLOAD_FOLDER, exist_ok=True)
os.makedirs(RECEIVED_FOLDER, exist_ok=True)

# ── Estado global del servidor TCP ────────────────────────
server_state = {
    'running'  : False,
    'thread'   : None,
    'socket'   : None,
    'log'      : [],
    'port'     : 9999,
    'password' : '',
    'keyfile'  : None,
}


# ── Utilidades ────────────────────────────────────────────

def human_size(n):
    for unit in ['B', 'KB', 'MB']:
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"

def b64(data): return base64.b64encode(data).decode()
def unb64(s):  return base64.b64decode(s)

def slog(msg, tipo='INFO'):
    """Agrega entrada al log del servidor."""
    hora = datetime.datetime.now().strftime('%H:%M:%S')
    iconos = {'INFO':'📡','OK':'✅','ERROR':'❌','RECV':'📥'}
    entry = f"[{hora}] {iconos.get(tipo,'·')} {msg}"
    server_state['log'].append(entry)
    if len(server_state['log']) > 100:
        server_state['log'] = server_state['log'][-100:]
    print(entry)

def receive_all(sock, n):
    data = b''
    while len(data) < n:
        chunk = sock.recv(min(n - len(data), BUFFER))
        if not chunk:
            raise ConnectionError("Conexión cerrada inesperadamente.")
        data += chunk
    return data


# ── Lógica del servidor TCP ───────────────────────────────

def handle_client(conn, addr):
    slog(f"Conexión entrante desde {addr[0]}:{addr[1]}", 'INFO')
    try:
        name_len  = struct.unpack('>I', receive_all(conn, 4))[0]
        filename  = receive_all(conn, name_len).decode('utf-8')
        slog(f"Archivo: {filename}", 'RECV')

        data_len   = struct.unpack('>Q', receive_all(conn, 8))[0]
        slog(f"Tamaño cifrado: {human_size(data_len)}", 'RECV')
        ciphertext = receive_all(conn, data_len)

        plaintext  = decrypt_data_v2(
            ciphertext,
            server_state['password'],
            server_state['keyfile']
        )

        save_name = filename[:-4] if filename.endswith('.mce') else filename
        save_path = os.path.join(RECEIVED_FOLDER, save_name)
        if os.path.exists(save_path):
            ts   = datetime.datetime.now().strftime('%H%M%S')
            base_n, ext = os.path.splitext(save_name)
            save_name   = f"{base_n}_{ts}{ext}"
            save_path   = os.path.join(RECEIVED_FOLDER, save_name)

        with open(save_path, 'wb') as f:
            f.write(plaintext)

        slog(f"Guardado: recibidos/{save_name} ({human_size(len(plaintext))})", 'OK')

        ack = f"OK:{save_name}:{len(plaintext)}".encode()
        conn.sendall(struct.pack('>I', len(ack)) + ack)

    except ValueError as e:
        slog(f"Error de descifrado: {e}", 'ERROR')
        err = f"ERROR:{e}".encode()
        try: conn.sendall(struct.pack('>I', len(err)) + err)
        except: pass
    except Exception as e:
        slog(f"Error: {e}", 'ERROR')
    finally:
        conn.close()


def server_loop(port):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.settimeout(1.0)
    srv.bind(('0.0.0.0', port))
    srv.listen(5)
    server_state['socket'] = srv

    # Obtener IP local
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except:
        local_ip = "desconocida"

    slog(f"Servidor iniciado en {local_ip}:{port}", 'OK')
    slog(f"Esperando conexiones entrantes...", 'INFO')

    while server_state['running']:
        try:
            conn, addr = srv.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()
        except socket.timeout:
            continue
        except Exception as e:
            if server_state['running']:
                slog(f"Error en servidor: {e}", 'ERROR')
            break

    try: srv.close()
    except: pass
    slog("Servidor detenido.", 'INFO')


# ══════════════════════════════════════════════════════════
# RUTAS FLASK
# ══════════════════════════════════════════════════════════

@app.route('/')
def index():
    return render_template('index.html')


# ── Clave ─────────────────────────────────────────────────
@app.route('/api/genkey', methods=['POST'])
def api_genkey():
    key_data = os.urandom(256)
    return jsonify({'ok': True, 'key_b64': b64(key_data),
                    'size': len(key_data), 'filename': 'secret.mce.key'})


# ── Cifrar ────────────────────────────────────────────────
@app.route('/api/encrypt', methods=['POST'])
def api_encrypt():
    try:
        if 'file' not in request.files:
            return jsonify({'ok': False, 'error': 'No se recibió archivo.'}), 400

        f        = request.files['file']
        password = request.form.get('password', '').strip()
        key_b64  = request.form.get('key_b64', '').strip()

        if not password: return jsonify({'ok': False, 'error': 'Contraseña requerida.'}), 400
        if not key_b64:  return jsonify({'ok': False, 'error': 'Clave requerida.'}), 400

        plaintext = f.read()
        if len(plaintext) > MAX_SIZE_MB * 1024 * 1024:
            return jsonify({'ok': False, 'error': f'Máximo {MAX_SIZE_MB} MB.'}), 400
        if len(plaintext) == 0:
            return jsonify({'ok': False, 'error': 'Archivo vacío.'}), 400

        keyfile    = unb64(key_b64)
        t0         = time.perf_counter()
        ciphertext = encrypt_data_v2(plaintext, password, keyfile)
        elapsed    = time.perf_counter() - t0

        freq = [0] * 256
        for byte in ciphertext[68:]: freq[byte] += 1
        n       = max(len(ciphertext) - 68, 1)
        entropy = -sum((c/n)*math.log2(c/n) for c in freq if c > 0)

        mod_key     = bytearray(keyfile); mod_key[0] ^= 0x01
        cipher2     = encrypt_data_v2(plaintext, password, bytes(mod_key))
        diff        = sum(a != b for a, b in zip(ciphertext[68:], cipher2[68:]))
        avalanche   = (diff / max(len(ciphertext)-68, 1)) * 100

        return jsonify({
            'ok': True,
            'cipher_b64'    : b64(ciphertext),
            'filename'      : f.filename + '.mce',
            'original_size' : human_size(len(plaintext)),
            'cipher_size'   : human_size(len(ciphertext)),
            'time_ms'       : round(elapsed * 1000, 2),
            'entropy'       : round(entropy, 4),
            'entropy_max'   : 8.0,
            'avalanche_pct' : round(avalanche, 1),
            'blocks'        : (len(plaintext) // 32) + 1,
            'algo'          : 'MCE-v2 (Matricial + CBC + HMAC-SHA256)'
        })
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500


# ── Descifrar ─────────────────────────────────────────────
@app.route('/api/decrypt', methods=['POST'])
def api_decrypt():
    try:
        if 'file' not in request.files:
            return jsonify({'ok': False, 'error': 'No se recibió archivo.'}), 400

        f          = request.files['file']
        password   = request.form.get('password', '').strip()
        key_b64    = request.form.get('key_b64', '').strip()

        if not password: return jsonify({'ok': False, 'error': 'Contraseña requerida.'}), 400
        if not key_b64:  return jsonify({'ok': False, 'error': 'Clave requerida.'}), 400

        ciphertext = f.read()
        keyfile    = unb64(key_b64)
        t0         = time.perf_counter()
        plaintext  = decrypt_data_v2(ciphertext, password, keyfile)
        elapsed    = time.perf_counter() - t0

        orig_name  = f.filename[:-4] if f.filename.endswith('.mce') else f.filename

        return jsonify({
            'ok': True,
            'plain_b64' : b64(plaintext),
            'filename'  : orig_name,
            'size'      : human_size(len(plaintext)),
            'time_ms'   : round(elapsed * 1000, 2),
        })
    except ValueError as e:
        return jsonify({'ok': False, 'error': str(e)}), 400
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500


# ══════════════════════════════════════════════════════════
# RUTAS DE RED TCP
# ══════════════════════════════════════════════════════════

@app.route('/api/net/start_server', methods=['POST'])
def api_start_server():
    """Inicia el servidor TCP en background."""
    if server_state['running']:
        return jsonify({'ok': False, 'error': 'El servidor ya está corriendo.'})

    data     = request.get_json()
    password = data.get('password', '').strip()
    key_b64  = data.get('key_b64', '').strip()
    port     = int(data.get('port', 9999))

    if not password: return jsonify({'ok': False, 'error': 'Contraseña requerida.'})
    if not key_b64:  return jsonify({'ok': False, 'error': 'Clave requerida.'})

    server_state['running']  = True
    server_state['password'] = password
    server_state['keyfile']  = unb64(key_b64)
    server_state['port']     = port
    server_state['log']      = []

    t = threading.Thread(target=server_loop, args=(port,), daemon=True)
    server_state['thread'] = t
    t.start()

    # IP local
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except:
        local_ip = "desconocida"

    return jsonify({'ok': True, 'ip': local_ip, 'port': port})


@app.route('/api/net/stop_server', methods=['POST'])
def api_stop_server():
    """Detiene el servidor TCP."""
    server_state['running'] = False
    try:
        if server_state['socket']:
            server_state['socket'].close()
    except: pass
    return jsonify({'ok': True})


@app.route('/api/net/server_log', methods=['GET'])
def api_server_log():
    """Retorna el log actual del servidor y archivos recibidos."""
    files = []
    for fname in sorted(os.listdir(RECEIVED_FOLDER)):
        fpath = os.path.join(RECEIVED_FOLDER, fname)
        files.append({
            'name': fname,
            'size': human_size(os.path.getsize(fpath))
        })
    return jsonify({
        'ok'     : True,
        'running': server_state['running'],
        'log'    : server_state['log'][-30:],
        'files'  : files
    })


@app.route('/api/net/send_file', methods=['POST'])
def api_send_file():
    """Cifra y envía un archivo al servidor remoto via TCP."""
    try:
        if 'file' not in request.files:
            return jsonify({'ok': False, 'error': 'No se recibió archivo.'})

        f        = request.files['file']
        host     = request.form.get('host', '').strip()
        port     = int(request.form.get('port', 9999))
        password = request.form.get('password', '').strip()
        key_b64  = request.form.get('key_b64', '').strip()

        if not host:     return jsonify({'ok': False, 'error': 'Host requerido.'})
        if not password: return jsonify({'ok': False, 'error': 'Contraseña requerida.'})
        if not key_b64:  return jsonify({'ok': False, 'error': 'Clave requerida.'})

        plaintext = f.read()
        filename  = f.filename
        keyfile   = unb64(key_b64)

        if len(plaintext) == 0:
            return jsonify({'ok': False, 'error': 'Archivo vacío.'})

        # Cifrar
        t0         = time.perf_counter()
        ciphertext = encrypt_data_v2(plaintext, password, keyfile)
        t_enc      = time.perf_counter() - t0

        # Conectar y enviar
        send_name  = filename + '.mce'
        t1         = time.perf_counter()

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(15)
        sock.connect((host, port))

        name_bytes = send_name.encode('utf-8')
        sock.sendall(struct.pack('>I', len(name_bytes)))
        sock.sendall(name_bytes)
        sock.sendall(struct.pack('>Q', len(ciphertext)))
        sock.sendall(ciphertext)

        t_send = time.perf_counter() - t1

        # Confirmación
        sock.settimeout(10)
        ack_len = struct.unpack('>I', sock.recv(4))[0]
        ack     = sock.recv(ack_len).decode('utf-8')
        sock.close()

        if ack.startswith('OK:'):
            parts    = ack.split(':')
            saved_as = parts[1] if len(parts) > 1 else filename
            return jsonify({
                'ok'       : True,
                'saved_as' : saved_as,
                'enc_ms'   : round(t_enc * 1000, 1),
                'send_ms'  : round(t_send * 1000, 1),
                'orig_size': human_size(len(plaintext)),
                'enc_size' : human_size(len(ciphertext)),
            })
        else:
            return jsonify({'ok': False, 'error': ack})

    except ConnectionRefusedError:
        return jsonify({'ok': False, 'error': f'No se pudo conectar a {host}:{port}. ¿Está el servidor corriendo?'})
    except socket.timeout:
        return jsonify({'ok': False, 'error': 'Timeout: el servidor no respondió.'})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})


@app.route('/api/net/download_received/<filename>')
def api_download_received(filename):
    """Descarga un archivo de la carpeta recibidos/."""
    from flask import send_from_directory
    return send_from_directory(RECEIVED_FOLDER, filename, as_attachment=True)


if __name__ == '__main__':
    print("\n  SecureVault MCE corriendo en http://localhost:5000\n")
    app.run(debug=True, port=5000, threaded=True)
