#!/usr/bin/env python3
"""
eip712_detector.py — Детектор/анализатор EIP-712 Permit payload.

Декодирует eth_signTypedData_v4, проверяет spender по базам,
вычисляет эвристику риска, выдаёт вердикт.

Режимы:
  1. --decode <json>  — декодировать payload из JSON
  2. --simulate       — сгенерировать тестовые случаи и показать вердикты
"""

from __future__ import annotations

import hashlib
import json
import sys
import time
from dataclasses import dataclass
from typing import Any
from enum import Enum

try:
    from eth_account import Account
    from eth_account.messages import encode_typed_data
except ImportError:
    print("ERROR: pip install eth-account")
    sys.exit(2)


# ── константы ────────────────────────────────────────────────
PERMIT2_ADDRESS = "0x000000000022D473030F116dDEE9F6B43aC78BA3"

# Легитимные spender'ы (пример)
KNOWN_SAFE_SPENDERS: dict[str, str] = {
    "0x1f98431c8ad98523631ae4a59f267346ea31f984": "Uniswap",
    "0x7a250d5630b4cf539739df2c5dacb4c659f2488d": "Uniswap V2 Router",
    "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45": "Uniswap V3 Router",
    "0xd9e1ce17f2641f24ae83637ab66a2cca9c378b9e": "SushiSwap Router",
    "0x1111111254fb6c44bac0bed2854e76f90643097d": "1inch Router",
    "0xdef1c0ded9bec7f1a1670819833240f027b25eff": "0x Exchange",
}

# Типы EIP-712
FULL_TYPES = {
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
    "PermitBatch": [
        {"name": "details", "type": "PermitDetails[]"},
        {"name": "spender", "type": "address"},
        {"name": "sigDeadline", "type": "uint256"},
    ],
}


# ── результаты ──────────────────────────────────────────────
class Risk(Enum):
    CRITICAL = "🔴 CRITICAL"
    HIGH = "🟠 HIGH"
    MEDIUM = "🟡 MEDIUM"
    LOW = "🟢 LOW"
    INFO = "ℹ️ INFO"


@dataclass
class Finding:
    risk: Risk
    param: str
    message: str


@dataclass
class Verdict:
    safe: bool
    findings: list[Finding]
    score: int  # 0-100, 100 = максимальный риск

    def print(self) -> None:
        print(f"\n{'='*60}")
        print(f"  ВЕРДИКТ")
        print(f"{'='*60}")
        print(f"  Score: {self.score}/100")
        print(f"  Safe:  {'✅' if self.safe else '❌ NO!'}")
        print(f"{'─'*60}")
        for f in self.findings:
            print(f"  {f.risk.value:<15} {f.param:<20} {f.message}")
        print(f"{'='*60}\n")


# ── эвристика ──────────────────────────────────────────────
class PermitAnalyzer:
    """Анализирует EIP-712 Permit payload на уязвимости."""

    MAX_UINT160 = 2**160 - 1

    def analyze(self, payload: dict) -> Verdict:
        findings: list[Finding] = []
        score = 0

        try:
            domain = payload.get("domain", {})
            message = payload.get("message", {})
            primary_type = payload.get("primaryType", "")

            # ── Spender ──
            score += self._analyze_spender(message, domain, findings)

            # ── Amount ──
            score += self._analyze_amount(message, findings)

            # ── Deadline / Expiration ──
            score += self._analyze_deadline(message, findings)

            # ── Nonce ──
            self._analyze_nonce(message, findings)

            # ── VerifyingContract ──
            self._analyze_contract(domain, findings)

            # ── ChainId ──
            self._analyze_chain(domain, findings)

            # ── PrimaryType ──
            score += self._analyze_type(primary_type, findings)

        except Exception as e:
            findings.append(Finding(Risk.CRITICAL, "PARSE", f"Ошибка парсинга payload: {e}"))
            score = 100

        safe = score < 35
        return Verdict(safe=safe, findings=findings, score=min(score, 100))

    # ─── проверки ───────────────────────────────────────────
    def _analyze_spender(self, msg: dict, domain: dict, findings: list) -> int:
        spender = (msg.get("spender") or "").lower()
        if not spender:
            return 0

        # проверка по белому списку
        if spender in KNOWN_SAFE_SPENDERS:
            name = KNOWN_SAFE_SPENDERS.get(spender, "?")
            findings.append(Finding(Risk.LOW, "spender", f"Легитимный контракт: {name}"))
            return 0

        # проверка EOA vs контракт (симуляция)
        if self._is_likely_eoa(spender):
            findings.append(Finding(
                Risk.CRITICAL, "spender",
                f"EOA адрес (не контракт)! Вы даете разрешение человеку!"
            ))
            return 40
        else:
            findings.append(Finding(
                Risk.MEDIUM, "spender",
                f"Неизвестный контракт. Не в whiteliste."
            ))
            return 15

    def _is_likely_eoa(self, address: str) -> bool:
        # Симуляция: в реальности eth_getCode
        # Считаем EOA если адрес не в whitelist и не похож на известный контракт
        # Для симуляции: если адрес как у сгенерированного кошелька
        # Симуляция: известные контракты начинаются на определённые префиксы
        known_prefixes = ["0x0000", "0x1f98", "0x7a25", "0x68b3", "0xdef1", "0x1111"]
        return not any(address.startswith(p) for p in known_prefixes)

    def _analyze_amount(self, msg: dict, findings: list) -> int:
        details = msg.get("details", {})
        if isinstance(details, list):
            # Batch — проверяем каждый токен
            score = 0
            for i, d in enumerate(details):
                findings.append(Finding(Risk.INFO, f"token[{i}]", f"{d.get('token','?')} amount={d.get('amount','?')}"))
                score += self._check_amount(int(d.get("amount", "0")), findings, f"token[{i}]")
            return score
        raw = details.get("amount") or msg.get("amount", "0")
        try:
            amount = int(raw) if isinstance(raw, str) else int(raw)
        except (ValueError, TypeError):
            return 0

        return self._check_amount(amount, findings, "amount")

    def _check_amount(self, amount: int, findings: list, label: str) -> int:
        if amount == self.MAX_UINT160:
            findings.append(Finding(
                Risk.CRITICAL, label,
                f"uint160.max — бесконечное разрешение!"
            ))
            return 35
        elif amount > 10**30:
            findings.append(Finding(
                Risk.HIGH, label,
                f"Очень большой лимит: {amount}"
            ))
            return 20
        elif amount > 10**12:
            findings.append(Finding(
                Risk.MEDIUM, label,
                f"Большой лимит: {amount}"
            ))
            return 10
        findings.append(Finding(Risk.LOW, label, f"Лимит: {amount} (в пределах нормы)"))
        return 0

    def _analyze_deadline(self, msg: dict, findings: list) -> int:
        score = 0
        now = int(time.time())
        deadline = msg.get("sigDeadline")
        if deadline:
            try:
                dl = int(deadline)
            except (ValueError, TypeError):
                dl = 0
            if dl > now + 86400 * 30:
                findings.append(Finding(
                    Risk.CRITICAL, "deadline",
                    f"Deadline: +{(dl - now) // 86400} дней. Подпись можно использовать МЕСЯЦАМИ."
                ))
                score += 30
            elif dl > now + 86400:
                findings.append(Finding(
                    Risk.MEDIUM, "deadline",
                    f"Deadline: +{(dl - now) // 86400} дней. Больше суток."
                ))
                score += 10
            else:
                findings.append(Finding(Risk.LOW, "deadline", f"Deadline в пределах нормы (<24ч)"))

        details = msg.get("details", {})
        if isinstance(details, list):
            exp = details[0].get("expiration") if details else None
        else:
            exp = details.get("expiration")
        if exp:
            try:
                e = int(exp)
            except (ValueError, TypeError):
                e = 0
            if e > now + 86400 * 30:
                findings.append(Finding(
                    Risk.CRITICAL, "expiration",
                    f"Expiration: +{(e - now) // 86400} дней."
                ))
                score += 20
            elif e > now + 86400:
                findings.append(Finding(
                    Risk.MEDIUM, "expiration",
                    f"Expiration: +{(e - now) // 86400} дней."
                ))
                score += 5
        return score

    def _analyze_nonce(self, msg: dict, findings: list) -> None:
        details = msg.get("details", {})
        if isinstance(details, list):
            nonce = details[0].get("nonce", "0") if details else "0"
        else:
            nonce = details.get("nonce", "0")
        findings.append(Finding(Risk.INFO, "nonce", f"Nonce: {nonce}"))
        if str(nonce) == "0":
            findings.append(Finding(
                Risk.INFO, "nonce",
                "Nonce = 0. Первая подпись для этого контракта. Нормально."
            ))

    def _analyze_contract(self, domain: dict, findings: list) -> None:
        contract = (domain.get("verifyingContract") or "").lower()
        if contract == PERMIT2_ADDRESS.lower():
            findings.append(Finding(Risk.LOW, "contract", "Uniswap Permit2 — легитимный контракт"))
        elif contract:
            findings.append(Finding(
                Risk.INFO, "contract",
                f"Unknown verifyingContract: {contract}"
            ))

    def _analyze_chain(self, domain: dict, findings: list) -> None:
        chain_id = domain.get("chainId", 1)
        findings.append(Finding(Risk.INFO, "chainId", f"Chain: {chain_id} ({self._chain_name(chain_id)})"))

    def _chain_name(self, cid: int) -> str:
        names = {1: "Ethereum", 137: "Polygon", 56: "BSC", 42161: "Arbitrum", 10: "Optimism", 8453: "Base"}
        return names.get(cid, f"Chain ID {cid}")

    def _analyze_type(self, primary_type: str, findings: list) -> int:
        if "Batch" in primary_type or primary_type == "PermitBatch":
            findings.append(Finding(
                Risk.HIGH, "primaryType",
                f"PermitBatch — ОДНА подпись на МНОЖЕСТВО токенов"
            ))
            return 20
        return 0


# ── декодирование ──────────────────────────────────────────
def decode_payload(data: str) -> dict | None:
    """Парсит JSON payload или raw hex подписи."""
    if data.startswith("{"):
        return json.loads(data)
    return None


def decode_test_payloads() -> list[dict]:
    """Генерирует тестовые payloads для демонстрации."""

    now = int(time.time())

    payloads = [
        {
            "name": "🟢 Uniswap Swap (Permit2) — безопасно",
            "payload": {
                "types": FULL_TYPES,
                "domain": {
                    "name": "Permit2",
                    "chainId": 1,
                    "verifyingContract": PERMIT2_ADDRESS,
                },
                "message": {
                    "details": {
                        "token": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
                        "amount": "1000000",
                        "expiration": str(now + 3600),
                        "nonce": "1",
                    },
                    "spender": "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45",
                    "sigDeadline": str(now + 1800),
                },
                "primaryType": "PermitSingle",
            },
        },
        {
            "name": "🔴 Фишинг (дрейнер) — Permit2 с бесконечным allowance",
            "payload": {
                "types": FULL_TYPES,
                "domain": {
                    "name": "Permit2",
                    "chainId": 1,
                    "verifyingContract": PERMIT2_ADDRESS,
                },
                "message": {
                    "details": {
                        "token": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
                        "amount": str(2**160 - 1),
                        "expiration": str(now + 86400 * 365),
                        "nonce": "0",
                    },
                    "spender": "0xdead00000000000000000000000000000000dead",
                    "sigDeadline": str(now + 86400 * 365),
                },
                "primaryType": "PermitSingle",
            },
        },
        {
            "name": "🟠 Batch Permit — мульти-токен (опасно)",
            "payload": {
                "types": FULL_TYPES,
                "domain": {
                    "name": "Permit2",
                    "chainId": 1,
                    "verifyingContract": PERMIT2_ADDRESS,
                },
                "message": {
                    "details": [
                        {"token": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
                         "amount": str(2**160 - 1),
                         "expiration": str(now + 86400 * 30),
                         "nonce": "0"},
                        {"token": "0xdAC17F958D2ee523a2206206994597C13D831ec7",
                         "amount": str(2**160 - 1),
                         "expiration": str(now + 86400 * 30),
                         "nonce": "1"},
                    ],
                    "spender": "0x1f98431c8aD98523631AE4a59f267346ea31F984",
                    "sigDeadline": str(now + 86400 * 30),
                },
                "primaryType": "PermitBatch",
            },
        },
    ]
    return payloads


# ── main ────────────────────────────────────────────────────
def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description="EIP-712 Permit analyzer")
    parser.add_argument("--decode", help="JSON payload of eth_signTypedData_v4")
    parser.add_argument("--simulate", action="store_true", help="Запустить тестовые случаи")
    args = parser.parse_args()

    analyzer = PermitAnalyzer()

    if args.decode:
        payload = decode_payload(args.decode)
        if not payload:
            print("ERROR: не могу распарсить payload")
            return 1
        verdict = analyzer.analyze(payload)
        verdict.print()
        return 0 if verdict.safe else 1

    if args.simulate:
        print("=" * 60)
        print("  🛡️  EIP-712 DETECTOR — симуляция")
        print("=" * 60)
        for case in decode_test_payloads():
            print(f"\n{'─' * 60}")
            print(f"  📦 {case['name']}")
            print(f"{'─' * 60}")
            verdict = analyzer.analyze(case["payload"])
            verdict.print()
        return 0

    # Если без аргументов — интерактивный режим
    # (можно расширить)
    parser.print_help()
    return 0


if __name__ == "__main__":
    main()
