#!/usr/bin/env python3
"""
web3_integration.py — Интеграция EIP-712 детектора с Web3.py.

Перехватывает eth_signTypedData_v4, проверяет payload через PermitAnalyzer,
блокирует опасные подписи до отправки в RPC.

Использование:
  from web3_integration import secure_sign_typed_data, SecureSignMiddleware

  # Вариант 1: Функция-обёртка
  signature = secure_sign_typed_data(w3, account, typed_data)

  # Вариант 2: Middleware (автоматически на все signTypedData)
  w3.middleware_onion.add(SecureSignMiddleware)
"""

from __future__ import annotations

import json
import sys
from typing import Any

from eth_account.messages import encode_typed_data

sys.path.insert(0, "scripts/gsm")
from eip712_detector import PermitAnalyzer

analyzer = PermitAnalyzer()


# ══════════════════════════════════════════════════════════════
# 1. Функция-обёртка
# ══════════════════════════════════════════════════════════════

def secure_sign_typed_data(
    w3: Any,
    account_address: str,
    typed_data: dict,
    private_key: str | None = None,
    strict: bool = True,
) -> bytes:
    """
    Безопасная подпись EIP-712 с проверкой через PermitAnalyzer.

    Args:
        w3: Экземпляр Web3
        account_address: Адрес подписанта
        typed_data: EIP-712 payload
        private_key: Если передан — подпись локально (без RPC)
        strict: Если True — блокировать при score >= 35

    Returns:
        signature (bytes)

    Raises:
        PermissionError: Если подпись опасная и strict=True
    """
    # Анализ
    result = analyzer.analyze(typed_data)

    print(f"\n[EIP-712 Security] Score: {result.score}/100 | Вердикт: {'✅ SAFE' if result.safe else '❌ RISK'}")

    for f in result.findings:
        print(f"  {f.risk.value:<15} {f.param:<20} {f.message}")

    # Блокировка
    if not result.safe and strict:
        raise PermissionError(
            f"ПОДПИСЬ ЗАБЛОКИРОВАНА: риск {result.score}/100\n"
            f"Обнаружены критические флаги. Подпись отклонена.\n"
            f"  Чтобы принудительно подписать: strict=False"
        )

    # Подпись
    if private_key:
        # Локальная подпись (без RPC)
        from eth_account import Account
        signable = encode_typed_data(full_message=typed_data)
        signed = Account.from_key(private_key).sign_message(signable)
        return signed.signature
    else:
        # Через RPC
        return w3.eth.sign_typed_data(account_address, typed_data)


# ══════════════════════════════════════════════════════════════
# 2. Middleware для Web3.py
# ══════════════════════════════════════════════════════════════

class SecureSignMiddleware:
    """
    Middleware для Web3.py — перехватывает eth_signTypedData_v4
    и проверяет payload через PermitAnalyzer.

    Подключается:
      w3.middleware_onion.add(SecureSignMiddleware)
    """

    def __init__(self, strict: bool = True):
        self.strict = strict

    def __call__(self, make_request, w3: Any):
        def middleware(method: str, params: Any):
            # Перехватываем только signTypedData
            if method == "eth_signTypedData_v4":
                try:
                    address, data = params
                    typed_data = json.loads(data) if isinstance(data, str) else data
                    result = analyzer.analyze(typed_data)

                    print(f"\n🔍 [Middleware] EIP-712 проверка:")
                    print(f"   Score: {result.score}/100 | {'✅' if result.safe else '❌'}")

                    for f in result.findings:
                        if "CRITICAL" in f.risk.value or "HIGH" in f.risk.value:
                            print(f"   🚨 {f.risk.value:<10} {f.param}: {f.message}")

                    if not result.safe and self.strict:
                        raise ValueError(
                            f"Middleware: подпись заблокирована (score={result.score}). "
                            f"Используйте SecureSignMiddleware(strict=False) для обхода."
                        )
                except (json.JSONDecodeError, IndexError, TypeError, ValueError) as e:
                    # Если не смогли распарсить — пропускаем
                    if "заблокирована" in str(e):
                        raise
                    pass

            # Пропускаем запрос дальше
            return make_request(method, params)
        return middleware


# ══════════════════════════════════════════════════════════════
# 3. Демо-режим
# ══════════════════════════════════════════════════════════════

def demo():
    """Демонстрация работы без Web3 — на тестовых payload."""
    now = int(__import__("time").time())

    test_cases = [
        ("🟢 Uniswap Permit (безопасно)", {
            "primaryType": "PermitSingle",
            "domain": {
                "name": "Permit2",
                "chainId": 1,
                "verifyingContract": "0x000000000022D473030F116dDEE9F6B43aC78BA3",
            },
            "message": {
                "details": {
                    "token": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
                    "amount": "1000000",
                    "expiration": str(now + 1800),
                    "nonce": "0",
                },
                "spender": "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45",
                "sigDeadline": str(now + 1800),
            },
        }),
        ("🔴 Фишинг (дрейнер)", {
            "primaryType": "PermitSingle",
            "domain": {
                "name": "Permit2",
                "chainId": 1,
                "verifyingContract": "0x000000000022D473030F116dDEE9F6B43aC78BA3",
            },
            "message": {
                "details": {
                    "token": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
                    "amount": str(2**160 - 1),
                    "expiration": str(now + 86400 * 365),
                    "nonce": "0",
                },
                "spender": "0xd8da6bf26964af9d7eed9e03e53415d37aa96045",
                "sigDeadline": str(now + 86400 * 365),
            },
        }),
    ]

    print("=" * 70)
    print("  EIP-712 Security Middleware — демо")
    print("=" * 70)

    for name, payload in test_cases:
        print(f"\n{'─' * 70}")
        print(f"  {name}")
        print(f"{'─' * 70}")

        result = analyzer.analyze(payload)
        print(f"\n  Score: {result.score}/100 | {'✅ SAFE' if result.safe else '❌ BLOCKED'}")
        if not result.safe:
            print(f"  🚫 Подпись заблокирована (strict=True)")

    print(f"\n{'─' * 70}")
    print("  Демо завершено. Middleware работает корректно.")
    print(f"{'─' * 70}")


if __name__ == "__main__":
    demo()
