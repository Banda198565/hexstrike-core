#!/usr/bin/env python3
"""
test_eip712_analyzer.py — Юнит-тесты для EIP-712 Permit детектора.

Запуск:
  python3 -m pytest tests/test_eip712_analyzer.py -v
  python3 -m unittest tests/test_eip712_analyzer.py -v
"""

import sys
import time
import unittest

sys.path.insert(0, "scripts/gsm")
from eip712_detector import PermitAnalyzer, Risk

PERMIT2_ADDRESS = "0x000000000022D473030F116dDEE9F6B43aC78BA3"
UNISWAP_ROUTER = "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45"
EOA_ADDRESS = "0xd8da6bf26964af9d7eed9e03e53415d37aa96045"


class TestEIP712Analyzer(unittest.TestCase):
    """Набор тестов для PermitAnalyzer."""

    def setUp(self):
        self.analyzer = PermitAnalyzer()
        self.now = int(time.time())

    # ── безопасные случаи ─────────────────────────────────

    def test_safe_uniswap_permit(self):
        """Легитимный Permit2 для Uniswap — должен быть SAFE."""
        payload = {
            "primaryType": "PermitSingle",
            "domain": {
                "name": "Permit2",
                "chainId": 1,
                "verifyingContract": PERMIT2_ADDRESS,
            },
            "message": {
                "details": {
                    "token": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
                    "amount": "100000000",  # 100 USDC
                    "expiration": str(self.now + 1800),
                    "nonce": "0",
                },
                "spender": UNISWAP_ROUTER,
                "sigDeadline": str(self.now + 1800),
            },
        }
        result = self.analyzer.analyze(payload)
        self.assertTrue(result.safe, f"Ожидался SAFE, получен score={result.score}")
        self.assertLess(result.score, 35, f"Score должен быть < 35, получен {result.score}")

    def test_safe_small_amount_known_contract(self):
        """Маленькая сумма с легитимным контрактом — безопасно."""
        payload = {
            "primaryType": "PermitSingle",
            "domain": {
                "name": "Permit2",
                "chainId": 1,
                "verifyingContract": PERMIT2_ADDRESS,
            },
            "message": {
                "details": {
                    "token": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
                    "amount": "1000",
                    "expiration": str(self.now + 300),
                    "nonce": "0",
                },
                "spender": "0x1111111254fb6c44bac0bed2854e76f90643097d",  # 1inch Router (whitelist)
                "sigDeadline": str(self.now + 300),
            },
        }
        result = self.analyzer.analyze(payload)
        self.assertTrue(result.safe, f"Score={result.score} должен быть safe (<35)")

    # ── критические случаи ────────────────────────────────

    def test_phishing_eoa_spender(self):
        """EOA spender + uint160.max + deadline год — CRITICAL."""
        payload = {
            "primaryType": "PermitSingle",
            "domain": {
                "name": "Permit2",
                "chainId": 1,
                "verifyingContract": PERMIT2_ADDRESS,
            },
            "message": {
                "details": {
                    "token": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
                    "amount": str(2**160 - 1),
                    "expiration": str(self.now + 86400 * 365),
                    "nonce": "0",
                },
                "spender": EOA_ADDRESS,
                "sigDeadline": str(self.now + 86400 * 365),
            },
        }
        result = self.analyzer.analyze(payload)
        self.assertFalse(result.safe, "Должен быть UNSAFE")
        self.assertGreaterEqual(result.score, 35, f"Score минимум 35, получен {result.score}")

        # Проверяем, что флаги содержат критичные предупреждения
        params = {f.param for f in result.findings}
        self.assertIn("spender", params, "Должен быть флаг spender")
        self.assertIn("amount", params, "Должен быть флаг amount")
        self.assertIn("deadline", params, "Должен быть флаг deadline")

    def test_uint160_max_detected(self):
        """Проверка обнаружения бесконечного аппрува."""
        payload = {
            "primaryType": "PermitSingle",
            "domain": {"name": "Permit2", "chainId": 1, "verifyingContract": PERMIT2_ADDRESS},
            "message": {
                "details": {
                    "token": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
                    "amount": str(2**160 - 1),
                    "expiration": str(self.now + 86400),
                    "nonce": "0",
                },
                "spender": UNISWAP_ROUTER,
                "sigDeadline": str(self.now + 86400),
            },
        }
        result = self.analyzer.analyze(payload)
        self.assertFalse(result.safe, "uint160.max должен быть unsafe")
        has_uint160 = any("uint160.max" in f.message for f in result.findings)
        self.assertTrue(has_uint160, "Должен быть флаг uint160.max")

    def test_year_deadline_detected(self):
        """Deadline на год — флаг."""
        payload = {
            "primaryType": "PermitSingle",
            "domain": {"name": "Permit2", "chainId": 1, "verifyingContract": PERMIT2_ADDRESS},
            "message": {
                "details": {
                    "token": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
                    "amount": "1000000",
                    "expiration": str(self.now + 86400 * 365),
                    "nonce": "0",
                },
                "spender": UNISWAP_ROUTER,
                "sigDeadline": str(self.now + 86400 * 365),
            },
        }
        result = self.analyzer.analyze(payload)
        self.assertFalse(result.safe, "Deadline +365 дней должен быть unsafe")

    # ── Batch ────────────────────────────────────────────

    def test_batch_permit_multiple_tokens(self):
        """Batch Permit — одна подпись на много токенов = HIGH risk."""
        payload = {
            "primaryType": "PermitBatch",
            "domain": {"name": "Permit2", "chainId": 1, "verifyingContract": PERMIT2_ADDRESS},
            "message": {
                "details": [
                    {"token": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
                     "amount": str(2**160 - 1),
                     "expiration": str(self.now + 86400),
                     "nonce": "0"},
                ],
                "spender": "0x1234567890123456789012345678901234567890",
                "sigDeadline": str(self.now + 3600),
            },
        }
        result = self.analyzer.analyze(payload)
        self.assertFalse(result.safe, "Batch с бесконечным amount должен быть unsafe")
        has_batch = any("permitbatch" in f.param.lower() for f in result.findings)
        has_batch = has_batch or any("PermitBatch" in f.message for f in result.findings)
        self.assertTrue(has_batch, "Должен быть флаг PermitBatch")

    # ── edge cases ───────────────────────────────────────

    def test_empty_payload(self):
        """Пустой payload — не падает."""
        result = self.analyzer.analyze({})
        self.assertIsNotNone(result)

    def test_missing_fields(self):
        """Payload с пропущенными полями — не падает."""
        payload = {
            "primaryType": "PermitSingle",
            "domain": {},
            "message": {},
        }
        result = self.analyzer.analyze(payload)
        self.assertIsNotNone(result)

    def test_known_safe_spender_in_whitelist(self):
        """Проверка, что whitelist срабатывает для легитимных контрактов."""
        payload = {
            "primaryType": "PermitSingle",
            "domain": {"name": "Permit2", "chainId": 1, "verifyingContract": PERMIT2_ADDRESS},
            "message": {
                "details": {
                    "token": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
                    "amount": "5000000",
                    "expiration": str(self.now + 1800),
                    "nonce": "0",
                },
                "spender": UNISWAP_ROUTER,
                "sigDeadline": str(self.now + 1800),
            },
        }
        result = self.analyzer.analyze(payload)
        self.assertTrue(result.safe, "Uniswap V3 Router в whitelist — должен быть safe")


if __name__ == "__main__":
    unittest.main()
