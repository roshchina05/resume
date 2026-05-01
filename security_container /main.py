import secrets
import time
import base64

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

print("=" * 90)
print("КОНТЕЙНЕР ШИФРОВАНИЯ ТРАФИКА")
print("=" * 90)

print("\n1. ПОДГОТОВКА СИСТЕМЫ")
print("-" * 90)

SECRET_KEY = secrets.token_bytes(32)
print(f"  Ключ шифрования: {SECRET_KEY.hex()[:8]}...{SECRET_KEY.hex()[-4:]}")
print(f"  Длина ключа: 256 бит | Алгоритм: AES-256-GCM | HKDF-SHA-256")

# команды ТСД
PACKETS = [
    {"device": "TSC-001", "user": "klad_1",  "data": "OP:PICK"},
    {"device": "TSC-002", "user": "klad_2",  "data": "ART:5678;QTY:12;LOC:B2-03;OP:SHIP"},
    {"device": "TAB-101", "user": "kompl_1", "data": "ART:9012;QTY:200;LOC:C1-07;OP:PICK"},
    {"device": "TAB-102", "user": "kompl_2", "data": "ART:3456;QTY:5;LOC:A3-02;OP:PICK"},
    {"device": "TSC-001", "user": "klad_1",  "data": "ART:7890;QTY:80;LOC:D4-10;OP:MOVE"},
    {"device": "TAB-101", "user": "kompl_1", "data": "ART:1111;QTY:30;LOC:E2-05;OP:COUNT"},
]

print(f"  Пакетов для передачи: {len(PACKETS)}")
print(f"  Размеры команд: от 7 до 34 байт")

ATTACKER_KEY = secrets.token_bytes(32)
print(f"  Ключ злоумышленника: {ATTACKER_KEY.hex()[:8]}...{ATTACKER_KEY.hex()[-4:]}")


def key_for_device(master: bytes, device_id: str) -> bytes:
    """Диверсификация ключей согласно п.4.5 ТЗ"""
    return HKDF(hashes.SHA256(), 32, device_id.encode("utf-8"), b"wms-lr3").derive(master)


def encrypt_and_decrypt(aes: AESGCM, text: str):
    raw = text.encode("utf-8")
    nonce = secrets.token_bytes(12)

    t0 = time.perf_counter()
    ct = aes.encrypt(nonce, raw, None)
    t_enc = (time.perf_counter() - t0) * 1000

    t0 = time.perf_counter()
    restored = aes.decrypt(nonce, ct, None)
    t_dec = (time.perf_counter() - t0) * 1000

    return nonce, ct, len(raw), t_enc, t_dec, restored.decode() == text


def attacker_decrypt(aes_wrong: AESGCM, nonce: bytes, ct: bytes):
    t0 = time.perf_counter()
    try:
        aes_wrong.decrypt(nonce, ct, None)
        t_att = (time.perf_counter() - t0) * 1000
        return True, t_att
    except InvalidTag:
        t_att = (time.perf_counter() - t0) * 1000
        return False, t_att


print("\n2. КОНТЕЙНЕР РАСЧЕТА")
print("-" * 90)
print("  2.1 Легитимная передача (правильный ключ)")

master_legit = SECRET_KEY
results = []
encrypted_pairs = []

for p in PACKETS:
    key = key_for_device(master_legit, p["device"])
    aes = AESGCM(key)
    nonce, ct, size, t_enc, t_dec, ok = encrypt_and_decrypt(aes, p["data"])
    encrypted_pairs.append((nonce, ct))
    results.append({
        "Устройство": p["device"],
        "Пользователь": p["user"],
        "Исходный пакет": p["data"],
        "Исх. размер (байт)": size,
        "Время шифр. (мс)": round(t_enc, 6),
        "Время расшифр. (мс)": round(t_dec, 6),
        "Зашифр. размер (байт)": len(nonce) + len(ct),
        "Статус": "OK" if ok else "ОШИБКА",

    })
    encrypted_b64 = base64.b64encode(ct).decode()[:20]
    print(f"  {p['device']}: {p['data'][:28]:28} -> {encrypted_b64}... -> {'OK' if ok else 'FAIL'}")

print("\n  2.2 Попытка злоумышленника (чужой ключ)")

attack_results = []
for p, (nonce, ct) in zip(PACKETS, encrypted_pairs):
    key = key_for_device(ATTACKER_KEY, p["device"])
    aes = AESGCM(key)
    read, t_att = attacker_decrypt(aes, nonce, ct)
    attack_results.append({
        "Устройство": p["device"],
        "Результат перехвата": "ДАННЫЕ ЗАЩИЩЕНЫ" if not read else "ДАННЫЕ СКОМПРОМЕТИРОВАНЫ",
        "Время атаки (мс)": round(t_att, 6),
    })
    status = "НЕ ЧИТАЕМ" if not read else "ПРОЧИТАН"
    print(f"  [{p['device']}] перехвачен -> попытка дешифровать -> {status}")

df = pd.DataFrame(results)
df_att = pd.DataFrame(attack_results)

print("\n3. КОНТЕЙНЕР ТАБЛИЧНОГО ПРЕДСТАВЛЕНИЯ")
print("-" * 90)

print("\nТАБЛИЦА 1: ЛЕГИТИМНАЯ ПЕРЕДАЧА")
print("-" * 90)
print(f"{'Устройство':<10} {'Пользователь':<12} {'Исходный пакет':<35} {'Статус':<6}")
print("-" * 90)
for _, r in df.iterrows():
    data_short = r['Исходный пакет'][:33] + "..." if len(r['Исходный пакет']) > 35 else r['Исходный пакет']
    print(f"{r['Устройство']:<10} {r['Пользователь']:<12} {data_short:<35} {r['Статус']:<6}")

print("\nТАБЛИЦА 2: ВРЕМЕННЫЕ ХАРАКТЕРИСТИКИ")
print("-" * 90)
print(f"{'Устройство':<10} {'Исх. размер':<12} {'Зашифр. размер':<15} {'Время шифр. (мс)':<18} {'Время расшифр. (мс)':<18}")
print("-" * 90)
for _, r in df.iterrows():
    print(f"{r['Устройство']:<10} {r['Исх. размер (байт)']:<12} {r['Зашифр. размер (байт)']:<15} {r['Время шифр. (мс)']:<18.6f} {r['Время расшифр. (мс)']:<18.6f}")

print("\nТАБЛИЦА 3: ПОПЫТКА ПЕРЕХВАТА ЗЛОУМЫШЛЕННИКОМ")
print("-" * 90)
print(f"{'Устройство':<12} {'Результат перехвата':<25}")
print("-" * 90)
for _, r in df_att.iterrows():
    print(f"{r['Устройство']:<12} {r['Результат перехвата']:<25}")

# Сохраняем CSV 
df.to_csv("encryption_log.csv", index=False, encoding='utf-8-sig')
df_att.to_csv("attacker_log.csv", index=False, encoding='utf-8-sig')
print("\n  Данные сохранены: encryption_log.csv, attacker_log.csv")

print("\n4. КОНТЕЙНЕР ВИЗУАЛИЗАЦИИ")
print("-" * 90)

#  ГРАФИК 1: Время шифрования/расшифрования 
fig, ax = plt.subplots(figsize=(10, 5))
x = np.arange(1, len(df) + 1)

ax.plot(x, df["Время шифр. (мс)"], 'b-o', lw=2, ms=8, label="Шифрование", alpha=0.8)
ax.plot(x, df["Время расшифр. (мс)"], 'r-s', lw=2, ms=8, label="Расшифрование", alpha=0.8)

# Добавляем подписи значений
for i, (enc, dec) in enumerate(zip(df["Время шифр. (мс)"], df["Время расшифр. (мс)"])):
    ax.annotate(f'{enc:.4f}', (x[i], enc), textcoords="offset points", 
                xytext=(0, 10), ha='center', fontsize=8, color='blue')
    ax.annotate(f'{dec:.4f}', (x[i], dec), textcoords="offset points", 
                xytext=(0, -15), ha='center', fontsize=8, color='red')

ax.set_xlabel("Номер пакета")
ax.set_ylabel("Время (миллисекунды)")
ax.set_title("Время шифрования и расшифрования пакетов ТСД")
ax.set_xticks(x)
ax.legend(loc='upper left')
ax.grid(True, alpha=0.3)

plt.tight_layout()
plt.savefig("chart_time.png", dpi=120)
plt.close()
print("   chart_time.png")

# ГРАФИК 2: Размер пакетов до и после шифрования
fig, ax = plt.subplots(figsize=(10, 5))

plain = df["Исх. размер (байт)"].values
wire = df["Зашифр. размер (байт)"].values
width = 0.35

bars1 = ax.bar(x - width/2, plain, width, label="Исходные данные", 
               color="#3498DB", edgecolor='k', alpha=0.8)
bars2 = ax.bar(x + width/2, wire, width, label="После шифрования", 
               color="#E74C3C", edgecolor='k', alpha=0.8)

# Подписи значений
for i, (p, w) in enumerate(zip(plain, wire)):
    ax.text(x[i] - width/2, p + 2, str(p), ha='center', va='bottom', fontsize=9)
    ax.text(x[i] + width/2, w + 2, str(w), ha='center', va='bottom', fontsize=9)

ax.set_xlabel("Номер пакета")
ax.set_ylabel("Размер (байт)")
ax.set_title("Сравнение размера пакетов до и после шифрования")
ax.set_xticks(x)
ax.legend()
ax.grid(True, axis='y', alpha=0.3)

plt.tight_layout()
plt.savefig("chart_size.png", dpi=120)
plt.close()
print("   chart_size.png")

print("\n" + "=" * 90)
print("ИТОГИ РАБОТЫ КОНТЕЙНЕРА")
print("=" * 90)

successful_attacks = sum(1 for r in attack_results if r['Результат перехвата'] == 'ДАННЫЕ СКОМПРОМЕТИРОВАНЫ')
avg_enc_time = df["Время шифр. (мс)"].mean()
avg_dec_time = df["Время расшифр. (мс)"].mean()

print(f"""
СТАТИСТИКА:

  Зашифровано пакетов:           {len(results)}
  Успешно расшифровано:          {sum(1 for r in results if r['Статус'] == 'OK')}
  Перехвачено злоумышленником:   {len(attack_results)}
  Из них прочитано:              {successful_attacks}
  Среднее время шифрования:      {avg_enc_time:.6f} мс
  Среднее время расшифрования:   {avg_dec_time:.6f} мс
  Требование ТЗ:                 ≤50 мс

""")

print("=" * 90)
