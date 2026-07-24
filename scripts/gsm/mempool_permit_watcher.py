#!/usr/bin/env python3
"""
mempool_permit_watcher.py — Мониторинг мемпула на Permit/Permit2 транзакции.

Подписывается на newPendingTransactions через WebSocket,
фильтрует permit-вызовы по селектору, декодирует аргументы,
шлёт алерты (звук/Telegram/webhook) — как crypto_sms_guard.

Использование:
  # С реальным WS RPC (QuickNode/Infura/локальная нода)
  python3 scripts/gsm/mempool_permit_watcher.py --ws wss://eth-mainnet.g.alchemy.com/v2/YOUR_KEY

  # Демо-режим без RPC (симуляция)
  python3 scripts/gsm/mempool_permit_watcher.py --demo

Требуется: pip install web3 websockets eth-account
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

# ── зависимости ──────────────────────────────────────────────
try:
    from eth_account import Account
    from eth_account.messages import encode_typed_data
    from eth_hash.auto import keccak
except ImportError:
    print("ERROR: pip install eth-account")
    sys.exit(2)

try:
    from web3 import AsyncWeb3, Web3
    from web3.types import TxData
except ImportError:
    print("ERROR: pip install web3 websockets")
    sys.exit(2)

# ── константы ────────────────────────────────────────────────
ROOT = Path(__file__).resolve().parents[2]
ARTIFACT = ROOT / "artifacts" / "gsm"
ARTIFACT.mkdir(parents=True, exist_ok=True)

LOG_FILE = ARTIFACT / "mempool-permit-log.jsonl"

# Селекторы функций
SELECTORS = {
    "0xd505174f": ("ERC-2612 Permit", "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)"),
    "0x2b67b570": ("Permit2 permitTransferFrom", "permitTransferFrom((address,uint160,uint48,uint48),address,address,(address,uint160))"),
    "0x30f28b7a": ("Permit2 permitTransferFrom (batch)", "permitTransferFrom((address,uint160,uint48,uint48)[],address,address,(address,uint160)[])"),
    "0x1faa6d0c": ("Permit2 permitWitnessTransferFrom", "witnessTransferFrom(...)"),
    "0x8b6a4bd8": ("ERC-721 Permit (NFT)", "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)"),
}

# Адреса известных контрактов Permit2 (на разных сетях)
PERMIT2_ADDRESSES = {
    "0x000000000022D473030F116dDEE9F6B43aC78BA3": "Ethereum/Polygon/BSC/Arbitrum/Optimism",
    "0x31c2F6fcFf4F8759b3Bd5Bf0e1084A055615c768": "Uniswap V2 Router",
}

KNOWN_DRAINER_ADDRESSES: dict[str, str] = {}
DRAINER_FILE = ROOT / "config" / "known-drainers.json"


def load_drainer_db() -> dict[str, str]:
    if DRAINER_FILE.exists():
        return json.loads(DRAINER_FILE.read_text())
    return {}


# ─── ABI для декодирования ──────────────────────────────────
PERMIT2_ABI = [
    {
        "type": "function",
        "name": "permitTransferFrom",
        "inputs": [
            {"name": "permit", "type": "tuple", "components": [
                {"name": "permitted", "type": "tuple", "components": [
                    {"name": "token", "type": "address"},
                    {"name": "amount", "type": "uint160"},
                ]},
                {"name": "nonce", "type": "uint256"},
                {"name": "deadline", "type": "uint256"},
            ]},
            {"name": "transferDetails", "type": "tuple", "components": [
                {"name": "to", "type": "address"},
                {"name": "requestedAmount", "type": "uint256"},
            ]},
            {"name": "owner", "type": "address"},
            {"name": "signature", "type": "bytes"},
        ],
    },
    {
        "type": "function",
        "name": "permit",
        "inputs": [
            {"name": "owner", "type": "address"},
            {"name": "spender", "type": "address"},
            {"name": "value", "type": "uint256"},
            {"name": "deadline", "type": "uint256"},
            {"name": "v", "type": "uint8"},
            {"name": "r", "type": "bytes32"},
            {"name": "s", "type": "bytes32"},
        ],
    },
]

USDC_ADDRESSES = {
    "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": "USDC (Ethereum)",
    "0x2791bca1f2de4661ed1a30c8b986f297f41d6498": "USDC (Polygon)",
    "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913": "USDC (Base)",
}


# ─── DECODE ──────────────────────────────────────────────────
def decode_permit_input(input_data: str, tx: dict) -> dict:
    """Декодирует input_data permit-транзакции."""
    result = {
        "selector": input_data[:10],
        "method_name": SELECTORS.get(input_data[:10], ("Unknown", ""))[0],
        "to": tx.get("to", ""),
        "from": tx.get("from", ""),
        "value_eth": Web3.from_wei(tx.get("value", 0), "ether"),
    }

    # Пробуем декодировать через web3
    selector = input_data[:10]
    if selector in ("0x2b67b570", "0xd505174f"):
        try:
            w3 = Web3()
            contract = w3.eth.contract(abi=PERMIT2_ABI)
            func, params = None, None

            for abi_entry in PERMIT2_ABI:
                if abi_entry["name"] == "permitTransferFrom" and selector == "0x2b67b570":
                    func, params = contract.decode_function_input(input_data)
                    break
                elif abi_entry["name"] == "permit" and selector == "0xd505174f":
                    # Для ERC-2612 Permit
                    # owner, spender, value, deadline, v, r, s
                    data = input_data[10:]
                    if len(data) >= 448:  # 7 * 64 hex chars
                        owner = "0x" + data[24:64]
                        spender = "0x" + data[88:128]
                        value_hex = data[128:192]
                        deadline_hex = data[192:256]
                        result.update({
                            "owner": Web3.to_checksum_address(owner),
                            "spender": Web3.to_checksum_address(spender),
                            "value": int(value_hex, 16),
                            "deadline": int(deadline_hex, 16),
                            "deadline_dt": datetime.fromtimestamp(int(deadline_hex, 16)).strftime("%Y-%m-%d %H:%M") if int(deadline_hex, 16) > 1000000000 else "N/A",
                            "is_max": int(value_hex, 16) == 2**256 - 1,
                        })
                    break

            if func and params:
                pass  # уже обработано выше

        except Exception as e:
            result["decode_error"] = str(e)

    # Обогащение адресов
    to_lower = (tx.get("to") or "").lower()
    result["contract_name"] = PERMIT2_ADDRESSES.get(to_lower, "") or USDC_ADDRESSES.get(to_lower, "")

    # Проверка по базе дрейнеров
    spender = result.get("spender", "").lower()
    if spender in load_drainer_db():
        result["drainer_known"] = True
        result["drainer_name"] = load_drainer_db()[spender]

    return result


# ─── ALERTS ──────────────────────────────────────────────────
def fire_alert(message: str, entry: dict, sound: bool = False, telegram: bool = False):
    """Шлёт алерты."""
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] 🚨 {message}")

    if sound:
        try:
            subprocess.run(["afplay", "/System/Library/Sounds/Hero.aiff"], timeout=2, stderr=subprocess.DEVNULL)
            subprocess.run(["say", "-v", "Daniel", f"Permit detected: {entry.get('method_name', '')[:50]}"], timeout=5, stderr=subprocess.DEVNULL)
        except Exception:
            pass

    if telegram:
        token = os.environ.get("TELEGRAM_BOT_TOKEN")
        chat_id = os.environ.get("TELEGRAM_CHAT_ID")
        if token and chat_id:
            url = f"https://api.telegram.org/bot{token}/sendMessage"
            payload = json.dumps({"chat_id": chat_id, "text": f"🚨 MEMPOOL PERMIT\n\n{message[:2000]}", "parse_mode": "HTML"}).encode()
            try:
                req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
                urllib.request.urlopen(req, timeout=10)
            except urllib.error.URLError:
                pass


def append_log(entry: dict):
    entry["timestamp"] = datetime.now(timezone.utc).isoformat()
    with LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


# ─── АНАЛИЗ РИСКА ────────────────────────────────────────────
def risk_analysis(decoded: dict) -> tuple[int, list[str]]:
    """Анализирует риск permit-транзакции. Возвращает (score, flags)."""
    score = 0
    flags = []

    # Spender — EOA?
    spender = decoded.get("spender", "")
    if spender and len(spender) > 10:
        # Если spender — EOA (нет кода), это подозрительно
        # В реальности тут eth_getCode
        if decoded.get("drainer_known"):
            score += 50
            flags.append(f"🔴 KNOWN DRAINER: {decoded.get('drainer_name', '?')}")

    # Max amount?
    if decoded.get("is_max"):
        score += 30
        flags.append("🔴 uint256.max — бесконечный аппрув")

    # Deadline далеко?
    deadline = decoded.get("deadline", 0)
    if deadline > time.time() + 86400 * 30:
        score += 20
        flags.append(f"🔴 Deadline через {(deadline - time.time()) // 86400} дней")

    # High value?
    value = decoded.get("value", 0)
    if value > 10**30:
        score += 15
        flags.append(f"🟠 Огромная сумма: {value}")

    # Known Permit2 контракт?
    if decoded.get("contract_name"):
        score -= 10
        flags.append(f"🟢 Known: {decoded['contract_name']}")

    return score, flags


# ══════════════════════════════════════════════════════════════
# WS WATCHER
# ══════════════════════════════════════════════════════════════

async def watch_mempool(ws_url: str, sound: bool = False, telegram: bool = False):
    """Подключается к WS RPC и слушает pendingTransactions."""
    from web3.providers.persistent import WebSocketProvider

    print(f"Подключаюсь к {ws_url}...")
    async with AsyncWeb3(WebSocketProvider(ws_url)) as w3:
        if not await w3.is_connected():
            print("❌ Не удалось подключиться к WS RPC")
            return

        print("✅ Подключено. Подписка на newPendingTransactions...")
        print("   (Для остановки: Ctrl+C)")
        print()

        await w3.eth.subscribe("newPendingTransactions")
        tx_count = 0
        permit_count = 0

        async for response in w3.socket.process_subscriptions():
            tx_hash = response.get("result")
            if not tx_hash:
                continue

            tx_count += 1

            try:
                tx = await w3.eth.get_transaction(tx_hash)
                if not tx or not tx.get("input"):
                    continue

                input_data = tx["input"]
                if isinstance(input_data, bytes):
                    input_hex = input_data.hex()
                else:
                    input_hex = input_data

                selector = input_hex[:10]
                if selector in SELECTORS:
                    permit_count += 1
                    decoded = decode_permit_input(input_hex, dict(tx))
                    score, flags = risk_analysis(decoded)

                    ts = datetime.now().strftime("%H:%M:%S")
                    print(f"\n[{ts}] ⚡ PERMIT #{permit_count} (txs:{tx_count})")
                    print(f"  TxHash: {tx_hash[:66]}...")
                    print(f"  Method: {decoded['method_name']}")
                    print(f"  From:   {decoded['from']}")
                    print(f"  To:     {decoded['to']}")
                    if decoded.get("owner"):
                        print(f"  Owner:  {decoded['owner']}")
                    if decoded.get("spender"):
                        print(f"  Spender: {decoded['spender']}")
                    if decoded.get("value"):
                        formatted = f"{decoded['value']:,}"
                        max_flag = " (MAX)" if decoded.get("is_max") else ""
                        print(f"  Amount: {formatted}{max_flag}")
                    if decoded.get("deadline"):
                        print(f"  Deadline: {decoded['deadline_dt']}")
                    if decoded.get("contract_name"):
                        print(f"  Contract: {decoded['contract_name']}")

                    if flags:
                        print(f"  Risk ({score}/100):")
                        for f in flags:
                            print(f"    {f}")

                    # Лог
                    entry = {
                        "type": "mempool_permit",
                        "tx_hash": tx_hash,
                        "method": decoded["method_name"],
                        "from_addr": decoded["from"],
                        "to_addr": decoded["to"],
                        "owner": decoded.get("owner"),
                        "spender": decoded.get("spender"),
                        "value": decoded.get("value"),
                        "is_max": decoded.get("is_max"),
                        "deadline": decoded.get("deadline"),
                        "risk_score": score,
                        "flags": flags,
                    }
                    append_log(entry)

                    # Алерт при высоком риске
                    if score >= 30:
                        msg = f"Permit {decoded['method_name']}\nSpender: {decoded.get('spender','?')}\nAmount: {decoded.get('value','?')}\nScore: {score}/100"
                        fire_alert(msg, decoded, sound=sound, telegram=telegram)

            except Exception:
                pass

            if tx_count % 100 == 0:
                print(f"  [{datetime.now().strftime('%H:%M:%S')}] processed {tx_count} txs, {permit_count} permits", end="\r")


# ══════════════════════════════════════════════════════════════
# DEMO MODE (без RPC)
# ══════════════════════════════════════════════════════════════

def simulate_permit_tx() -> dict:
    """Генерирует поддельную permit-транзакцию для демо."""
    permit_data = {
        "owner": "0x6c2E081071844732CD21189C0EC5E018F576F66A",
        "spender": "0xd8da6bf26964af9d7eed9e03e53415d37aa96045",
        "value": 2**256 - 1,
        "deadline": int(time.time()) + 86400 * 365,
        "selector": "0xd505174f",
        "method_name": "ERC-2612 Permit (drain)",
        "from": "0x6c2E081071844732CD21189C0EC5E018F576F66A",
        "to": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
        "is_max": True,
        "contract_name": "USDC (Ethereum)",
        "value_eth": 0,
    }
    return permit_data


def demo_mode():
    """Демонстрация без RPC."""
    print("=" * 70)
    print("  MEMPOOL PERMIT WATCHER — демо-режим")
    print("  (без подключения к WebSocket RPC)")
    print("=" * 70)
    print()
    print("Симуляция permit-транзакций в мемпуле...")
    print()

    # Симуляция EIP-2612 Permit (вредоносный)
    print("─" * 70)
    print("  TX #1: ERC-2612 Permit (drainer)")
    print("─" * 70)
    decoded = simulate_permit_tx()
    score, flags = risk_analysis(decoded)
    print(f"  TxHash: 0x{'a'*64}")
    print(f"  Method: {decoded['method_name']}")
    print(f"  From:   {decoded['from']}")
    print(f"  To:     {decoded['to']} ({decoded['contract_name']})")
    print(f"  Owner:  {decoded['owner']}")
    print(f"  Spender: {decoded['spender']}")
    print(f"  Amount: {decoded['value']:,} (MAX)")
    print(f"  Deadline: {datetime.fromtimestamp(decoded['deadline']).strftime('%Y-%m-%d %H:%M')} (+365 дн)")
    print(f"  Risk: {score}/100")
    for f in flags:
        print(f"    {f}")
    append_log({**decoded, "type": "mempool_permit_demo", "risk_score": score, "flags": flags})
    print()

    # Симуляция Permit2 (легитимный)
    print("─" * 70)
    print("  TX #2: Permit2 permitTransferFrom (легитимный)")
    print("─" * 70)
    decoded2 = {
        "owner": "0x6c2E081071844732CD21189C0EC5E018F576F66A",
        "spender": "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45",
        "value": 10**18 * 100,
        "deadline": int(time.time()) + 1800,
        "selector": "0x2b67b570",
        "method_name": "Permit2 permitTransferFrom",
        "from": "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45",
        "to": "0x000000000022D473030F116dDEE9F6B43aC78BA3",
        "is_max": False,
        "contract_name": "Ethereum/Polygon/BSC/Arbitrum/Optimism (Permit2)",
        "value_eth": 0,
    }
    score2, flags2 = risk_analysis(decoded2)
    print(f"  TxHash: 0x{'b'*64}")
    print(f"  Method: {decoded2['method_name']}")
    print(f"  From:   {decoded2['from']}")
    print(f"  To:     {decoded2['to']} ({decoded2['contract_name']})")
    print(f"  Owner:  {decoded2['owner']}")
    print(f"  Spender: {decoded2['spender']}")
    print(f"  Amount: {decoded2['value']:,} (100 USDC)")
    print(f"  Deadline: +30 минут")
    print(f"  Risk: {score2}/100")
    for f in flags2:
        print(f"    {f}")
    print()

    print("─" * 70)
    print(f"  Лог: {LOG_FILE}")
    print("─" * 70)
    print()
    print("Для реального мониторинга укажите --ws URL")
    print("Пример: python3 scripts/gsm/mempool_permit_watcher.py --ws wss://eth-mainnet.g.alchemy.com/v2/KEY --sound")
    print()


# ══════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="Mempool Permit Watcher")
    parser.add_argument("--ws", help="WebSocket RPC URL (wss://...)")
    parser.add_argument("--demo", action="store_true", help="Демо-режим без RPC")
    parser.add_argument("--sound", action="store_true", help="macOS звуковые алерты")
    parser.add_argument("--telegram", action="store_true", help="Telegram алерты (из TELEGRAM_BOT_TOKEN/CHAT_ID)")
    args = parser.parse_args()

    if args.demo or not args.ws:
        demo_mode()
        return

    try:
        asyncio.run(watch_mempool(args.ws, sound=args.sound, telegram=args.telegram))
    except KeyboardInterrupt:
        print("\nОстановлено.")
    except ImportError:
        print("ERROR: pip install web3 websockets")


if __name__ == "__main__":
    main()
