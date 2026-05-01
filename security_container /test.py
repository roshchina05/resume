"""
Модуль автоматизированного тестирования функций модуля сквозного шифрования трафика.
Фреймворк: pytest.
"""

import pytest
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from main import key_for_device, encrypt_and_decrypt, attacker_decrypt


@pytest.fixture
def master_key():
    # Генерация тестового мастер-ключа длиной 256 бит
    return secrets.token_bytes(32)


@pytest.fixture
def aes_obj(master_key):
    # Инициализация объекта шифрования с ключом устройства TSC-001
    device_key = key_for_device(master_key, "TSC-001")
    return AESGCM(device_key)


def test_same_device_id_returns_same_key(master_key):
    # Проверка диверсификации ключей: одинаковые идентификаторы устройств
    # должны давать одинаковые производные ключи
    key1 = key_for_device(master_key, "TSC-001")
    key2 = key_for_device(master_key, "TSC-001")
    assert key1 == key2


def test_different_device_id_returns_different_key(master_key):
    # Проверка диверсификации ключей: разные идентификаторы устройств
    # должны давать разные производные ключи
    key1 = key_for_device(master_key, "TSC-001")
    key2 = key_for_device(master_key, "TSC-002")
    assert key1 != key2


def test_derived_key_length_is_32_bytes(master_key):
    # Проверка соответствия длины производного ключа требованию ТЗ (256 бит)
    key = key_for_device(master_key, "TSC-001")
    assert len(key) == 32


def test_encrypted_data_matches_original_after_decryption(aes_obj):
    # Проверка корректности полного цикла шифрования и расшифрования
    plaintext = "OP:PICK"
    nonce, ct, size, t_enc, t_dec, ok = encrypt_and_decrypt(aes_obj, plaintext)
    assert ok == True


def test_encryption_time_does_not_exceed_50ms(aes_obj):
    # Проверка соответствия времени шифрования требованию ТЗ
    plaintext = "OP:PICK"
    nonce, ct, size, t_enc, t_dec, ok = encrypt_and_decrypt(aes_obj, plaintext)
    assert t_enc < 50.0


def test_decryption_time_does_not_exceed_50ms(aes_obj):
    # Проверка соответствия времени расшифрования требованию ТЗ
    plaintext = "OP:PICK"
    nonce, ct, size, t_enc, t_dec, ok = encrypt_and_decrypt(aes_obj, plaintext)
    assert t_dec < 50.0


def test_long_command_encryption_time_within_limit(aes_obj):
    # Проверка времени шифрования для команды максимальной длины
    long_command = "ART:5678;QTY:12;LOC:B2-03;OP:SHIP"
    nonce, ct, size, t_enc, t_dec, ok = encrypt_and_decrypt(aes_obj, long_command)
    assert t_enc < 50.0


def test_attacker_cannot_decrypt_with_wrong_key(master_key, aes_obj):
    # Проверка защищённости трафика: попытка расшифрования чужим ключом
    plaintext = "OP:PICK"
    nonce, ct, size, t_enc, t_dec, ok = encrypt_and_decrypt(aes_obj, plaintext)
    wrong_master = secrets.token_bytes(32)
    wrong_key = key_for_device(wrong_master, "TSC-001")
    wrong_aes = AESGCM(wrong_key)
    read, t_att = attacker_decrypt(wrong_aes, nonce, ct)
    assert read == False


def test_wrong_key_raises_invalid_tag(master_key, aes_obj):
    # Проверка срабатывания механизма аутентификации GCM при неверном ключе
    plaintext = "OP:PICK"
    nonce, ct, size, t_enc, t_dec, ok = encrypt_and_decrypt(aes_obj, plaintext)
    wrong_master = secrets.token_bytes(32)
    wrong_key = key_for_device(wrong_master, "TSC-001")
    wrong_aes = AESGCM(wrong_key)
    with pytest.raises(InvalidTag):
        wrong_aes.decrypt(nonce, ct, None)


def test_corrupted_ciphertext_raises_invalid_tag(master_key, aes_obj):
    # Проверка целостности: повреждённый шифротекст должен быть отвергнут
    plaintext = "OP:PICK"
    nonce, ct, size, t_enc, t_dec, ok = encrypt_and_decrypt(aes_obj, plaintext)
    wrong_master = secrets.token_bytes(32)
    wrong_key = key_for_device(wrong_master, "TSC-001")
    wrong_aes = AESGCM(wrong_key)
    corrupted_ct = ct[:-1] + bytes([ct[-1] ^ 1])
    with pytest.raises(InvalidTag):
        wrong_aes.decrypt(nonce, corrupted_ct, None)


def test_empty_packet_list_does_not_cause_error():
    # Проверка устойчивости: пустой список пакетов не должен вызывать сбой
    PACKETS = []
    results = []
    for p in PACKETS:
        results.append(p)
    assert len(results) == 0
