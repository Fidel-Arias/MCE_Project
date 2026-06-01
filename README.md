# 🔐 MCE — Matricial Cipher Engine

> Algoritmo criptográfico simétrico de cifrado por bloques basado en transformaciones matriciales, con autenticación HMAC-SHA256 y transmisión segura por red TCP.

**Trabajo de Fase — Criptografía · Cisco Networking Academy · 2025**  
Universidad Católica de Santa María — Arequipa, Perú

| Autor | Correo |
|---|---|
| Fidel Reynaldo Arias Arias | fidel.arias@estudiante.ucsm.edu.pe |
| Joshua Hugo Mamani Palaco | joshua.mamani@estudiante.ucsm.edu.pe |

---

## 📋 Tabla de contenidos

- [¿Qué es MCE?](#-qué-es-mce)
- [Características](#-características)
- [Estructura del proyecto](#-estructura-del-proyecto)
- [Instalación](#-instalación)
- [Uso](#-uso)
  - [CLI — Línea de comandos](#1-cli--línea-de-comandos)
  - [Web — Interfaz Flask](#2-web--interfaz-flask)
  - [Red — Cliente y Servidor TCP](#3-red--cliente-y-servidor-tcp)
- [Cómo funciona el algoritmo](#-cómo-funciona-el-algoritmo)
- [Métricas de seguridad](#-métricas-de-seguridad)
- [Pruebas](#-pruebas)
- [Comparativa](#-comparativa)

---

## ¿Qué es MCE?

MCE es un **cifrador de bloques simétrico** de diseño propio que opera sobre bloques de 32 bytes (256 bits), representados como matrices de 4×8 bytes. Aplica 5 rondas de transformaciones combinando:

- **XOR** con subclave derivada
- **Desplazamiento modular de filas** (Row Shift)
- **Transformación aritmética** módulo 256
- **Transposición matricial**

Incluye modo **CBC** para encadenamiento de bloques, **IV aleatorio** por operación y verificación de integridad **HMAC-SHA256**.

---

## ✨ Características

- 🔒 Cifrado de archivos de **cualquier tipo** (PDF, imágenes, video, binarios)
- 🔑 **Doble factor de clave**: contraseña + archivo `.mce.key`
- 🛡️ **HMAC-SHA256** para detectar corrupción y claves incorrectas
- 🔄 **Modo CBC** con IV aleatorio (mismo archivo → resultado diferente cada vez)
- 🌐 **Transmisión segura** por red TCP entre dos máquinas
- 💻 **Interfaz web** con Flask y métricas en tiempo real
- 🧪 **39 pruebas unitarias** con tasa de éxito del 100%

---

## 📁 Estructura del proyecto

```
MCE/
├── core/
│   ├── __init__.py
│   ├── mce_engine.py       # Núcleo del algoritmo
│   └── key_manager.py      # Generación y carga de claves
│
├── tests/
│   ├── __init__.py
│   └── test_mce.py         # Suite de 39 pruebas
│
├── web/
│   ├── app.py              # Servidor Flask
│   ├── mce_engine.py       # Copia del engine
│   ├── key_manager.py      # Copia del key manager
│   ├── templates/
│   │   └── index.html      # Interfaz web
│   ├── uploads/
│   ├── downloads/
│   └── recibidos/
│
├── network/
│   ├── server.py           # Servidor TCP receptor
│   ├── client.py           # Cliente TCP emisor
│   ├── mce_engine.py       # Copia del engine
│   ├── key_manager.py      # Copia del key manager
│   └── recibidos/
│
├── mce.py                  # CLI principal
├── requirements.txt
├── .gitignore
└── README.md
```

---

## ⚙️ Instalación

**Requisitos:** Python 3.11+

```bash
# 1. Clonar el repositorio
git clone https://github.com/tu-usuario/MCE.git
cd MCE

# 2. Crear entorno virtual
python -m venv venv

# Activar en Linux/Mac
source venv/bin/activate

# Activar en Windows
venv\Scripts\activate

# 3. Instalar dependencias
pip install -r requirements.txt
```

**`requirements.txt`:**
```
numpy
flask
pytest
```

---

## 🚀 Uso

### 1. CLI — Línea de comandos

```bash
# Generar archivo de clave
python mce.py genkey --out secret.mce.key

# Cifrar un archivo
python mce.py encrypt --in documento.pdf \
                      --key secret.mce.key \
                      --password "TuPassword"

# Descifrar un archivo
python mce.py decrypt --in documento.pdf.mce \
                      --key secret.mce.key \
                      --password "TuPassword"
```

---

### 2. Web — Interfaz Flask

```bash
cd web/
python app.py
```

Abrir en el navegador: **http://localhost:5000**

La interfaz tiene 4 secciones:

| Tab | Función |
|---|---|
| 🔒 Cifrar archivo | Cifra cualquier archivo y muestra métricas |
| 🔓 Descifrar archivo | Descifra archivos `.mce` |
| 📐 Cómo funciona | Explicación del algoritmo |
| 🌐 Envío en Red | Transmisión TCP entre dos máquinas |

---

### 3. Red — Cliente y Servidor TCP

Permite enviar archivos cifrados entre dos máquinas por la red.

#### Laptop receptora (Servidor)

```bash
cd network/
python server.py --key secret.mce.key --password "TuPassword"
```

El servidor muestra su IP automáticamente:
```
IP de esta máquina : 192.168.1.15
Puerto             : 9999
Esperando conexiones...
```

#### Laptop emisora (Cliente)

```bash
cd network/
python client.py --host 192.168.1.15 \
                 --port 9999 \
                 --key secret.mce.key \
                 --password "TuPassword" \
                 --file documento.pdf
```

#### Usando ngrok (redes diferentes)

Si las laptops están en redes distintas, en la laptop del servidor ejecuta en otra terminal:

```bash
ngrok tcp 9999
# Ngrok muestra: tcp://0.tcp.ngrok.io:XXXXX
```

El cliente usa esa dirección:

```bash
python client.py --host 0.tcp.ngrok.io \
                 --port XXXXX \
                 --key secret.mce.key \
                 --password "TuPassword" \
                 --file documento.pdf
```

> ⚠️ El archivo `secret.mce.key` debe ser **el mismo** en ambas máquinas. Compártelo por USB o canal seguro antes de la comunicación.

---

## 🔬 Cómo funciona el algoritmo

### Derivación de claves

```
password + keyfile → SHA-256 → base (32 bytes)
base + índice_ronda → SHA-256 → SK_i   (i = 0..4)
```

### Por cada bloque de 32 bytes (5 rondas):

```
Bloque → Matriz 4×8
  └─ Ronda i:
       1. XOR con SK_i
       2. Desplazamiento modular de filas
       3. Suma mod 256 con SK_i
       4. Transposición matricial
→ Bloque cifrado
```

### Formato del archivo cifrado:

```
[ MAGIC (4B) | HMAC (32B) | IV (32B) | DATOS_CIFRADOS (N×32B) ]
```

### Modo CBC:

```
Bloque_n = encrypt(plaintext_n XOR cipher_{n-1})
```

---

## 📊 Métricas de seguridad

| Archivo | Tamaño | Entropía (bits/byte) | Avalancha (%) | Tiempo (ms) |
|---|---|---|---|---|
| documento.txt | 4.2 KB | 4.81 | 100.0 | 1.23 |
| informe.pdf | 128 KB | 7.92 | 99.8 | 18.4 |
| imagen.jpg | 512 KB | 7.97 | 99.9 | 71.2 |
| datos.csv | 1.0 MB | 7.95 | 100.0 | 138.6 |
| video.mp4 | 5.0 MB | 7.98 | 99.7 | 683.1 |

- **Entropía máxima teórica:** 8.0 bits/byte
- **Umbral de avalancha deseable:** > 50%
- **Tasa de procesamiento:** ~7.3 MB/s

---

## 🧪 Pruebas

```bash
cd tests/
pytest test_mce.py -v
```

```
39 passed in 1.89s
```

Las pruebas cubren:
- Inversión de cada transformación primitiva
- Roundtrip cifrado/descifrado (0 bytes a 100 KB)
- Rechazo ante contraseña incorrecta
- Rechazo ante archivo de clave incorrecto
- Detección de archivo corrupto (HMAC inválido)
- No determinismo por IV aleatorio
- Efecto avalancha
- Gestión de claves

---

## 📈 Comparativa

| Propiedad | MCE v2 | AES-256 | DES |
|---|---|---|---|
| Tipo | Bloque simétrico | Bloque simétrico | Bloque simétrico |
| Tamaño de bloque | 256 bits | 128 bits | 64 bits |
| Rondas | 5 | 14 | 16 |
| Longitud de clave | Pass + 2048 bits | 256 bits | 56 bits |
| Autenticación | HMAC-SHA256 | Solo cifrado | Solo cifrado |
| Modo | CBC | CBC/GCM | CBC |
| IV aleatorio | ✅ | ✅ | ✅ |

> MCE es un algoritmo **académico**. No ha sido sometido a análisis diferencial y lineal formal. Para uso en producción se recomienda AES-256-GCM.

---
