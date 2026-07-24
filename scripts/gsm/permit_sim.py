#!/usr/bin/env python3
"""
permit_sim.py — Симуляция атаки Permit2 (EIP-712) от А до Я.
Локально, без реальных денег. Только education/теория.
"""

from __future__ import annotations

import hashlib
import json
import struct
import sys
import time
from dataclasses import dataclass, field
from typing import Any

# ── библиотеки ──────────────────────────────────────────────
try:
    from eth_account import Account
    from eth_account.messages import encode_typed_data
    from eth_hash.auto import keccak
except ImportError:
    print("ERROR: установите eth-account: pip install eth-account")
    sys.exit(2)

# ══════════════════════════════════════════════════════════════
# 0. Конфигурация
# ══════════════════════════════════════════════════════════════

# Константы (как в реальном Permit2)
PERMIT2_ADDRESS = "0x000000000022D473030F116dDEE9F6B43aC78BA3"
TOKEN_USDC = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"

# Создаём кошельки
Account.enable_unaudited_hdwallet_features()
victim_key = "0x" + hashlib.sha256(b"victim_secret_123").hexdigest()[:64]
attacker_key = "0x" + hashlib.sha256(b"attacker_secret_456").hexdigest()[:64]

victim = Account.from_key(victim_key)
attacker = Account.from_key(attacker_key)

# Разные spender для демонстрации
LEGIT_SPENDER = "0x1f98431c8aD98523631AE4a59f267346ea31F984"  # Uniswap
MALICIOUS_SPENDER = attacker.address  # EOA атакующего


@dataclass
class PermitMessage:
    """Структура Permit2: permitSingle"""
    token: str
    amount: int
    expiration: int
    nonce: int
    spender: str
    sig_deadline: int

    def to_dict(self) -> dict:
        return {
            "details": {
                "token": self.token,
                "amount": str(self.amount),
                "expiration": str(self.expiration),
                "nonce": str(self.nonce),
            },
            "spender": self.spender,
            "sigDeadline": str(self.sig_deadline),
        }


def build_eip712_types() -> dict:
    return {
        "EIP712Domain": [
            {"name": "name", "type": "string"},
            {"name": "chainId", "type": "uint256"},
            {"name": "verifyingContract", "type": "address"},
        ],
        "PermitSingle": [
            {"name": "details", "type": "PermitDetails"},
            {"name": "spender", "type": "address"},
            {"name": "sigDeadline", "type": "uint256"},
        ],
        "PermitDetails": [
            {"name": "token", "type": "address"},
            {"name": "amount", "type": "uint160"},
            {"name": "expiration", "type": "uint48"},
            {"name": "nonce", "type": "uint48"},
        ],
    }


def ecrecover_sim(typed_data: dict, v: int, r: int, s: int) -> str:
    """Симуляция ecrecover — восстанавливаем адрес подписанта."""
    signable = encode_typed_data(full_message=typed_data)
    return Account.recover_message(signable, vrs=(v, r, s))


def analyze_permit_safety(msg: PermitMessage, verbose: bool = True) -> dict:
    """Анализ подписи на уязвимости."""
    flags = []
    safe = True

    # 1. Проверка spender
    if msg.spender == MALICIOUS_SPENDER:
        flags.append(("🔴 CRITICAL", "Spender — EOA атакующего!"))
        safe = False
    elif msg.spender == LEGIT_SPENDER:
        flags.append(("🟢 OK", "Spender — легитимный контракт Uniswap"))
    else:
        flags.append(("🟡 WARN", "Spender — неизвестный адрес"))

    # 2. Проверка amount
    MAX_UINT160 = 2**160 - 1
    if msg.amount == MAX_UINT160:
        flags.append(("🔴 CRITICAL", "Amount = uint160.max — бесконечный аппрув!"))
        safe = False
    elif msg.amount > 10**22:
        flags.append(("🟡 WARN", f"Amount очень большой: {msg.amount}"))
        safe = False

    # 3. Проверка deadline
    now = int(time.time())
    if msg.sig_deadline > now + 3600 * 24 * 7:
        flags.append(("🔴 CRITICAL", f"Deadline через {(msg.sig_deadline - now) // 86400} дней"))
        safe = False
    elif msg.sig_deadline > now + 3600:
        flags.append(("🟡 WARN", f"Deadline через {(msg.sig_deadline - now) // 60} мин"))
    else:
        flags.append(("🟢 OK", "Deadline в пределах нормы (< 1ч)"))

    return {"safe": safe, "flags": flags}


# ══════════════════════════════════════════════════════════════
# 1. Фаза 1: Жертва на фишинговом сайте
# ══════════════════════════════════════════════════════════════

def phase1_phishing() -> tuple[PermitMessage, bytes, tuple]:
    """Сайт генерирует Permit сообщение и получает подпись жертвы."""

    now = int(time.time())

    # Вредоносный Permit — бесконечный аппрув на адрес атакующего
    malicious = PermitMessage(
        token=TOKEN_USDC,
        amount=2**160 - 1,  # uint160.max
        expiration=now + 86400 * 365,  # +1 год
        nonce=0,
        spender=MALICIOUS_SPENDER,  # АДРЕС АТАКУЮЩЕГО
        sig_deadline=now + 86400 * 365,  # +1 год
    )

    # Формируем EIP-712 сообщение
    domain_data = {
        "name": "Permit2",
        "chainId": 1,
        "verifyingContract": PERMIT2_ADDRESS,
    }

    message_data = malicious.to_dict()

    typed_data = {
        "types": build_eip712_types(),
        "domain": domain_data,
        "message": message_data,
        "primaryType": "PermitSingle",
    }

    # Жертва подписывает (в браузере через eth_signTypedData_v4)
    signable = encode_typed_data(full_message=typed_data)
    signed = victim.sign_message(signable)

    print("=" * 70)
    print("🔴 ФАЗА 1: Жертва на фишинговом сайте")
    print("=" * 70)
    print(f"\n👤 Жертва: {victim.address}")
    print(f"🎯 Фишинг-сайт: claim-uniswap-airdrop.xyz")
    print(f"\n📝 Кошелёк показывает окно подписи EIP-712:")
    print(f"   spender:          {malicious.spender}")
    print(f"   amount:           {malicious.amount} (uint160.max)")
    print(f"   deadline:         {malicious.sig_deadline} (+1 год)")
    print(f"   verifyingContract: {PERMIT2_ADDRESS} (Permit2 ✅ знакомый адрес)")

    print(f"\n⚠️  Анализ безопасности:")
    analysis = analyze_permit_safety(malicious)
    for level, msg in analysis["flags"]:
        print(f"   {level}: {msg}")

    print(f"\n✅ Жертва НАЖАЛА SIGN (подпись получена)")
    print(f"   Подпись: 0x{signed.signature.hex()[:40]}...")
    print(f"   Газ: 0 ETH (газ не тратится)")
    print(f"   Транзакция: НЕ создана (нет в истории кошелька)")

    return malicious, signed.signature.hex().encode(), (signed.v, signed.r, signed.s)


# ══════════════════════════════════════════════════════════════
# 2. Фаза 2: Атакующий получил подпись
# ══════════════════════════════════════════════════════════════

def phase2_sig_collected(msg: PermitMessage, sig_bytes: bytes, vrs: tuple):
    """Атакующий забирает подпись через JS дрейнера."""

    print("\n" + "=" * 70)
    print("🔴 ФАЗА 2: Атакующий получил подпись")
    print("=" * 70)
    print(f"\n👤 Атакующий: {attacker.address}")
    print(f"📦 Подпись (v, r, s):")
    print(f"   v: {vrs[0]}")
    print(f"   r: 0x{vrs[1].to_bytes(32, 'big').hex()[:40]}...")
    print(f"   s: 0x{vrs[2].to_bytes(32, 'big').hex()[:40]}...")
    print(f"\n💰 Баланс атакующего: 0 USDC")
    print(f"   (пока не исполнил permit)")
    print(f"\n⏳ Статус: ожидание...")


# ══════════════════════════════════════════════════════════════
# 3. Фаза 3: Атакующий исполняет permit
# ══════════════════════════════════════════════════════════════

def phase3_execute_permit(msg: PermitMessage, sig_bytes: bytes, vrs: tuple):
    """Атакующий отправляет permit() в блокчейн (газ за свой счёт)."""

    print("\n" + "=" * 70)
    print("🔴 ФАЗА 3: Атакующий вызывает permit() в блокчейне")
    print("=" * 70)

    # Готовим digest как в контракте
    domain_data = {
        "name": "Permit2",
        "chainId": 1,
        "verifyingContract": PERMIT2_ADDRESS,
    }
    typed_data = {
        "types": build_eip712_types(),
        "domain": domain_data,
        "message": msg.to_dict(),
        "primaryType": "PermitSingle",
    }
    signable = encode_typed_data(full_message=typed_data)
    # В реальности digest вычисляется как в EIP-712
    # Симулируем ecrecover

    recovered = ecrecover_sim(typed_data, vrs[0], vrs[1], vrs[2])

    print(f"\n📤 Транзакция от атакующего:")
    print(f"   From: {attacker.address}")
    print(f"   To: {PERMIT2_ADDRESS} (Permit2 контракт)")
    print(f"   Method: permitTransferFrom()")
    print(f"   Газ: 0.003 ETH (платит АТАКУЮЩИЙ)")
    print(f"   owner: {victim.address}")
    print(f"   spender: {msg.spender}")
    print(f"   amount: {msg.amount}")
    print(f"\n🏗️  ecrecover проверка:")
    print(f"   Ожидаемый подписант: {victim.address}")
    print(f"   Восстановленный:     {recovered}")
    print(f"   Совпадает: {'✅ ДА' if recovered.lower() == victim.address.lower() else '❌ НЕТ'}")
    if recovered.lower() == victim.address.lower():
        print(f"\n   → Подпись валидна! Контракт принимает.")
    else:
        print(f"\n   → Подпись НЕ валидна. REVERT.")
        return

    print(f"\n⚡ После permit(): allowance[{victim.address}][{msg.spender}] = {msg.amount}")


# ══════════════════════════════════════════════════════════════
# 4. Фаза 4: Вывод токенов
# ══════════════════════════════════════════════════════════════

def phase4_drain():
    """Атакующий забирает токены через transferFrom."""

    print("\n" + "=" * 70)
    print("🔴 ФАЗА 4: Вывод токенов (Drain)")
    print("=" * 70)

    balance = "1,234,567 USDC"
    amount_drained = "1,234,567 USDC"

    print(f"\n💰 Баланс жертвы до: {balance}")
    print(f"📤 Атакующий вызывает transferFrom()")
    print(f"   transferFrom(victim, attacker, {amount_drained})")
    print(f"\n🏦 Результат:")
    print(f"   Баланс жертвы после: 0 USDC")
    print(f"   Баланс атакующего: +{amount_drained}")
    print(f"   Статус: ✅ TOKENS DRAINED")


# ══════════════════════════════════════════════════════════════
# 5. Бонус: Сравнение безопасной и опасной подписи
# ══════════════════════════════════════════════════════════════

def bonus_comparison():
    """Сравнение легитимной подписи vs вредоносной."""

    print("\n" + "=" * 70)
    print("📊 БОНУС: Сравнение подписей")
    print("=" * 70)

    now = int(time.time())

    # Легитимная (как Uniswap)
    safe_msg = PermitMessage(
        token=TOKEN_USDC,
        amount=100 * 10**6,  # 100 USDC
        expiration=now + 3600,  # +1 час
        nonce=0,
        spender=LEGIT_SPENDER,  # Uniswap контракт
        sig_deadline=now + 1800,  # +30 минут
    )

    # Вредоносная (дрейнер)
    evil_msg = PermitMessage(
        token=TOKEN_USDC,
        amount=2**160 - 1,  # max
        expiration=now + 86400 * 365,  # +1 год
        nonce=0,
        spender=MALICIOUS_SPENDER,  # EOA атакующего
        sig_deadline=now + 86400 * 365,  # +1 год
    )

    print(f"\n{'Параметр':<25} {'🟢 Uniswap (безопасно)':<30} {'🔴 Фишинг (опасно)':<30}")
    print("-" * 85)
    print(f"{'spender':<25} {safe_msg.spender:<30} {evil_msg.spender:<30}")
    print(f"{'amount':<25} {'100 USDC (ограниченная сумма)':<30} {'uint160.max (бесконечно)':<30}")
    print(f"{'deadline':<25} {'+30 мин':<30} {'+1 год':<30}")
    print(f"{'expiration':<25} {'+1 час':<30} {'+1 год':<30}")
    print(f"{'spender тип':<25} {'Контракт (Uniswap)':<30} {'EOA (адрес человека)':<30}")

    safe_analysis = analyze_permit_safety(safe_msg, verbose=False)
    evil_analysis = analyze_permit_safety(evil_msg, verbose=False)

    print(f"\n{'Вердикт симулятора':<25} {'🟢 Безопасно':<30} {'🔴 CRITICAL':<30}")


# ══════════════════════════════════════════════════════════════
# RUN
# ══════════════════════════════════════════════════════════════

def main():
    print("\n")
    print("╔" + "═" * 68 + "╗")
    print("║  🚨  СИМУЛЯЦИЯ АТАКИ PERMIT2 (EIP-712)  🚨           ║")
    print("║  Только education. Локально. Реальных денег нет.     ║")
    print("╚" + "═" * 68 + "╝")
    print()

    msg, sig_bytes, vrs = phase1_phishing()
    phase2_sig_collected(msg, sig_bytes, vrs)
    phase3_execute_permit(msg, sig_bytes, vrs)
    phase4_drain()
    bonus_comparison()

    print("\n" + "─" * 70)
    print("🏁 Симуляция завершена.")
    print("   В реальности та же механика — только деньги настоящие.")
    print()


if __name__ == "__main__":
    main()
