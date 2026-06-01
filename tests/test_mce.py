"""
MCE - Suite de pruebas
Corre con: pytest tests/test_mce.py -v
"""

import os
import sys
import pytest
import hashlib

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core.mce_engine  import (
    bytes_to_matrix, matrix_to_bytes,
    xor_with_subkey, row_shift, modular_transform,
    transpose_matrix, inverse_transpose,
    encrypt_block, decrypt_block,
    encrypt_data, decrypt_data,
    encrypt_data_v2, decrypt_data_v2,
    add_padding, remove_padding,
    derive_subkeys, BLOCK_SIZE
)
from core.key_manager import generate_keyfile, load_keyfile


# ─────────────────────────────────────────
# FIXTURES
# ─────────────────────────────────────────

@pytest.fixture
def password():
    return "MiContrasena_Segura_2024!"

@pytest.fixture
def keyfile_bytes():
    return os.urandom(256)

@pytest.fixture
def sample_block():
    return bytes(range(32))  # 0x00..0x1F

@pytest.fixture
def subkeys(password, keyfile_bytes):
    return derive_subkeys(password, keyfile_bytes)


# ─────────────────────────────────────────
# PRUEBA 1: Conversion matriz
# ─────────────────────────────────────────

class TestMatrixConversion:

    def test_bytes_to_matrix_shape(self, sample_block):
        mat = bytes_to_matrix(sample_block)
        assert mat.shape == (4, 8), "La matriz debe ser 4x8"

    def test_roundtrip_conversion(self, sample_block):
        mat    = bytes_to_matrix(sample_block)
        result = matrix_to_bytes(mat)
        assert result == sample_block, "bytes→matriz→bytes debe ser identico"

    def test_all_zeros(self):
        block = bytes(32)
        mat   = bytes_to_matrix(block)
        assert mat.sum() == 0

    def test_all_ones(self):
        block = bytes([255] * 32)
        mat   = bytes_to_matrix(block)
        assert (mat == 255).all()


# ─────────────────────────────────────────
# PRUEBA 2: Transformaciones inversas
# ─────────────────────────────────────────

class TestTransformations:

    def test_xor_self_inverse(self, sample_block, subkeys):
        mat  = bytes_to_matrix(sample_block)
        enc  = xor_with_subkey(mat, subkeys[0])
        dec  = xor_with_subkey(enc, subkeys[0])
        assert (dec == mat).all(), "XOR aplicado dos veces debe dar el original"

    def test_row_shift_inverse(self, sample_block):
        mat  = bytes_to_matrix(sample_block)
        enc  = row_shift(mat, 3, inverse=False)
        dec  = row_shift(enc, 3, inverse=True)
        assert (dec == mat).all(), "row_shift inverso debe restaurar el original"

    def test_modular_transform_inverse(self, sample_block, subkeys):
        mat  = bytes_to_matrix(sample_block)
        enc  = modular_transform(mat, subkeys[0], inverse=False)
        dec  = modular_transform(enc, subkeys[0], inverse=True)
        assert (dec == mat).all(), "Transformacion modular inversa debe restaurar"

    def test_transpose_inverse(self, sample_block):
        mat  = bytes_to_matrix(sample_block)
        enc  = transpose_matrix(mat)
        dec  = inverse_transpose(enc)
        assert (dec == mat).all(), "Transpuesta inversa debe restaurar el original"

    def test_row_shift_no_data_loss(self, sample_block):
        mat  = bytes_to_matrix(sample_block)
        enc  = row_shift(mat, 5, inverse=False)
        # El conjunto de bytes debe ser el mismo, solo diferente orden
        assert sorted(mat.flatten()) == sorted(enc.flatten())


# ─────────────────────────────────────────
# PRUEBA 3: Cifrado/Descifrado de bloque
# ─────────────────────────────────────────

class TestBlockCipher:

    def test_encrypt_decrypt_roundtrip(self, sample_block, subkeys):
        encrypted = encrypt_block(sample_block, subkeys)
        decrypted = decrypt_block(encrypted, subkeys)
        assert decrypted == sample_block, "El bloque descifrado debe ser igual al original"

    def test_encrypted_differs_from_plaintext(self, sample_block, subkeys):
        encrypted = encrypt_block(sample_block, subkeys)
        assert encrypted != sample_block, "El texto cifrado no debe ser igual al original"

    def test_different_keys_different_output(self, sample_block, password):
        key1 = os.urandom(256)
        key2 = os.urandom(256)
        sk1  = derive_subkeys(password, key1)
        sk2  = derive_subkeys(password, key2)
        enc1 = encrypt_block(sample_block, sk1)
        enc2 = encrypt_block(sample_block, sk2)
        assert enc1 != enc2, "Distintas claves deben producir distintos cifrados"

    def test_wrong_key_fails_decryption(self, sample_block, password):
        key1 = os.urandom(256)
        key2 = os.urandom(256)
        sk1  = derive_subkeys(password, key1)
        sk2  = derive_subkeys(password, key2)
        encrypted = encrypt_block(sample_block, sk1)
        decrypted = decrypt_block(encrypted, sk2)
        assert decrypted != sample_block, "Clave incorrecta debe dar resultado diferente"

    def test_all_zeros_block(self, subkeys):
        block     = bytes(32)
        encrypted = encrypt_block(block, subkeys)
        decrypted = decrypt_block(encrypted, subkeys)
        assert decrypted == block

    def test_all_max_block(self, subkeys):
        block     = bytes([255] * 32)
        encrypted = encrypt_block(block, subkeys)
        decrypted = decrypt_block(encrypted, subkeys)
        assert decrypted == block


# ─────────────────────────────────────────
# PRUEBA 4: Padding
# ─────────────────────────────────────────

class TestPadding:

    def test_padding_added_correctly(self):
        data    = b"Hola"  # 4 bytes
        padded  = add_padding(data)
        pad_len = BLOCK_SIZE - 4
        assert len(padded) == BLOCK_SIZE
        assert padded[-1] == pad_len

    def test_padding_removed_correctly(self):
        data     = b"Hola Mundo"
        padded   = add_padding(data)
        restored = remove_padding(padded)
        assert restored == data

    def test_exact_block_size_gets_full_padding(self):
        data   = bytes(BLOCK_SIZE)
        padded = add_padding(data)
        assert len(padded) == BLOCK_SIZE * 2

    def test_padding_roundtrip_various_sizes(self):
        for size in [1, 15, 16, 17, 31, 32, 33, 63, 64, 100]:
            data     = os.urandom(size)
            padded   = add_padding(data)
            restored = remove_padding(padded)
            assert restored == data, f"Fallo en size={size}"


# ─────────────────────────────────────────
# PRUEBA 5: Cifrado/Descifrado completo
# ─────────────────────────────────────────

class TestFullEncryption:

    def test_text_file_roundtrip(self, password, keyfile_bytes):
        plaintext = b"Este es un mensaje de prueba para MCE. Hola mundo! 123456789."
        encrypted = encrypt_data(plaintext, password, keyfile_bytes)
        decrypted = decrypt_data(encrypted, password, keyfile_bytes)
        assert decrypted == plaintext

    def test_binary_data_roundtrip(self, password, keyfile_bytes):
        plaintext = os.urandom(1024)  # 1 KB aleatorio
        encrypted = encrypt_data(plaintext, password, keyfile_bytes)
        decrypted = decrypt_data(encrypted, password, keyfile_bytes)
        assert decrypted == plaintext

    def test_large_file_roundtrip(self, password, keyfile_bytes):
        plaintext = os.urandom(100 * 1024)  # 100 KB
        encrypted = encrypt_data(plaintext, password, keyfile_bytes)
        decrypted = decrypt_data(encrypted, password, keyfile_bytes)
        assert decrypted == plaintext

    def test_empty_data_roundtrip(self, password, keyfile_bytes):
        plaintext = b""
        encrypted = encrypt_data(plaintext, password, keyfile_bytes)
        decrypted = decrypt_data(encrypted, password, keyfile_bytes)
        assert decrypted == plaintext

    def test_single_byte_roundtrip(self, password, keyfile_bytes):
        plaintext = b"X"
        encrypted = encrypt_data(plaintext, password, keyfile_bytes)
        decrypted = decrypt_data(encrypted, password, keyfile_bytes)
        assert decrypted == plaintext

    def test_magic_header_present(self, password, keyfile_bytes):
        encrypted = encrypt_data(b"test", password, keyfile_bytes)
        assert encrypted[:4] == b'MCE1', "El archivo debe comenzar con la firma MCE1"

    def test_wrong_password_raises(self, password, keyfile_bytes):
        plaintext = b"mensaje secreto"
        encrypted = encrypt_data(plaintext, password, keyfile_bytes)
        with pytest.raises((ValueError, Exception)):
            decrypt_data(encrypted, "ContrasenaEquivocada!", keyfile_bytes)

    def test_wrong_keyfile_raises(self, password, keyfile_bytes):
        plaintext    = b"mensaje secreto"
        encrypted    = encrypt_data(plaintext, password, keyfile_bytes)
        wrong_keyfile = os.urandom(256)
        with pytest.raises((ValueError, Exception)):
            decrypt_data(encrypted, password, wrong_keyfile)

    def test_corrupted_file_raises(self, password, keyfile_bytes):
        """Con HMAC, cualquier corrupcion debe lanzar ValueError."""
        plaintext = b"mensaje secreto"
        encrypted = bytearray(encrypt_data_v2(plaintext, password, keyfile_bytes))
        encrypted[50] ^= 0xFF  # Corromper un byte en datos cifrados
        with pytest.raises(ValueError):
            decrypt_data_v2(bytes(encrypted), password, keyfile_bytes)

    def test_v2_roundtrip(self, password, keyfile_bytes):
        """Verifica que v2 (con HMAC) funciona correctamente."""
        plaintext = b"Mensaje con integridad verificada"
        encrypted = encrypt_data_v2(plaintext, password, keyfile_bytes)
        decrypted = decrypt_data_v2(encrypted, password, keyfile_bytes)
        assert decrypted == plaintext

    def test_v2_wrong_password_raises(self, password, keyfile_bytes):
        plaintext = b"mensaje secreto"
        encrypted = encrypt_data_v2(plaintext, password, keyfile_bytes)
        with pytest.raises(ValueError):
            decrypt_data_v2(encrypted, "ClaveEquivocada!", keyfile_bytes)

    def test_same_plaintext_different_ciphertext(self, password, keyfile_bytes):
        """El IV aleatorio debe hacer que el mismo texto cifre diferente cada vez."""
        plaintext = b"mismo mensaje"
        enc1 = encrypt_data(plaintext, password, keyfile_bytes)
        enc2 = encrypt_data(plaintext, password, keyfile_bytes)
        assert enc1 != enc2, "Dos cifrados del mismo texto deben ser distintos (IV aleatorio)"

    def test_invalid_magic_raises(self, password, keyfile_bytes):
        bad_data = b"XXXX" + os.urandom(64)
        with pytest.raises(ValueError):
            decrypt_data(bad_data, password, keyfile_bytes)


# ─────────────────────────────────────────
# PRUEBA 6: Analisis - Efecto Avalancha
# ─────────────────────────────────────────

class TestAvalancheEffect:

    def _bit_difference(self, b1: bytes, b2: bytes) -> float:
        """Calcula el % de bits diferentes entre dos secuencias de bytes."""
        if len(b1) != len(b2):
            min_len = min(len(b1), len(b2))
            b1, b2 = b1[:min_len], b2[:min_len]
        diff_bits  = sum(bin(a ^ b).count('1') for a, b in zip(b1, b2))
        total_bits = len(b1) * 8
        return (diff_bits / total_bits) * 100 if total_bits > 0 else 0

    def test_single_bit_change_in_password(self, keyfile_bytes):
        plaintext = os.urandom(BLOCK_SIZE * 4)
        enc1 = encrypt_data(plaintext, "Password123", keyfile_bytes)
        enc2 = encrypt_data(plaintext, "Password124", keyfile_bytes)
        # Comparar solo la parte cifrada (sin IV que es aleatorio)
        diff = self._bit_difference(enc1[36:], enc2[36:])
        print(f"\n[Avalancha] Cambio en password: {diff:.1f}% bits distintos")
        assert diff > 10, f"Efecto avalancha insuficiente: {diff:.1f}%"

    def test_subkeys_are_diverse(self, password, keyfile_bytes):
        """Verifica que cada subclave sea diferente entre si."""
        subkeys = derive_subkeys(password, keyfile_bytes)
        for i in range(len(subkeys)):
            for j in range(i + 1, len(subkeys)):
                assert subkeys[i] != subkeys[j], f"Subclaves {i} y {j} son identicas"

    def test_encrypted_data_entropy(self, password, keyfile_bytes):
        """Verifica que los datos cifrados tienen buena distribucion de bytes."""
        plaintext = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"  # datos uniformes
        encrypted = encrypt_data(plaintext, password, keyfile_bytes)
        # Datos cifrados no deben ser todos iguales
        unique_bytes = len(set(encrypted[36:]))  # ignorar header+IV
        print(f"\n[Entropia] Bytes unicos en cifrado: {unique_bytes}/256")
        assert unique_bytes > 10, f"Datos cifrados poco diversos: {unique_bytes} valores unicos"


# ─────────────────────────────────────────
# PRUEBA 7: Key Manager
# ─────────────────────────────────────────

class TestKeyManager:

    def test_generate_keyfile(self, tmp_path):
        key_path = str(tmp_path / "test.mce.key")
        data     = generate_keyfile(key_path)
        assert os.path.exists(key_path)
        assert len(data) == 256

    def test_load_keyfile(self, tmp_path):
        key_path = str(tmp_path / "test.mce.key")
        generate_keyfile(key_path)
        loaded = load_keyfile(key_path)
        assert len(loaded) == 256

    def test_generated_keys_are_random(self, tmp_path):
        path1 = str(tmp_path / "k1.mce.key")
        path2 = str(tmp_path / "k2.mce.key")
        k1 = generate_keyfile(path1)
        k2 = generate_keyfile(path2)
        assert k1 != k2, "Dos claves generadas deben ser diferentes"

    def test_missing_keyfile_raises(self):
        with pytest.raises(FileNotFoundError):
            load_keyfile("/ruta/inexistente/clave.mce.key")
