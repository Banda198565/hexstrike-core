#!/usr/bin/env python3
"""
phishing_sig_generator.py — Генератор фишинговых EIP-712 подписей для тренировки детектора.

Генерирует реалистичные payloads (Permit, Permit2, Batch, eth_sign, SetApprovalForAll)
с разными комбинациями параметров. Результат можно напрямую скормить eip712_detector.

Режимы:
  --generate        Сгенерировать все варианты и показать вердикт детектора
  --export FILE     Экспорт в JSON-файл (для тестов/датасета)
  --cases N         Сколько вариантов генерировать (по умолчанию все)
"""

from __future__ import annotations

import hashlib
import json
import sys
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Any, Generator

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts" / "gsm"))
from eip712_detector import PermitAnalyzer, Risk, Verdict

# ─── конфиг ─────────────────────────────────────────────────
PERMIT2_ADDRESS = "0x000000000022D473030F116dDEE9F6B43aC78BA3"
KNOWN_SPENDER = "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45"      # Uniswap V3
EOA_SPENDER = "0xd8da6bf26964af9d7eed9e03e53415d37aa96045"       # EOA (vitalik.eth)
UNKNOWN_SPENDER = "0x1234567890123456789012345678901234567890"
USDC = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
USDT = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
WETH = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
BAYC = "0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D"

MAX_UINT256 = 2**256 - 1
MAX_UINT160 = 2**160 - 1


class PhishType(Enum):
    EOA_SPENDER_MAX = "eoa_spender_max"
    LEGIT_SPENDER_MAX = "legit_spender_max"
    BATCH_PERMIT = "batch_permit"
    ETH_SIGN_RAW = "eth_sign_raw"
    SET_APPROVAL_ALL = "set_approval_all"
    SHORT_DEADLINE_MAX = "short_deadline_max"
    LEGIT_UNISWAP = "legit_uniswap"
    SMALL_VALUE_UNKNOWN = "small_value_unknown"
    MULTI_CHAIN = "multi_chain"
    NFT_DRAIN = "nft_drain"
    ZERO_DEADLINE = "zero_deadline"
    NO_EXPIRATION = "no_expiration"


@dataclass
class PhishCase:
    name: str
    type: PhishType
    description: str
    payload: dict
    expected_verdict: str  # "SAFE" | "RISK"
    expected_score_min: int
    tags: list[str] = field(default_factory=list)
    expected_max_score: int | None = None


# ══════════════════════════════════════════════════════════════
# Генератор
# ══════════════════════════════════════════════════════════════

class PhishingSigGenerator:
    """Генерирует тестовые EIP-712 payloads."""

    def __init__(self):
        self.now = int(time.time())

    def generate_all(self) -> list[PhishCase]:
        return [
            self._eoa_spender_max(),
            self._legit_spender_max(),
            self._batch_permit(),
            self._set_approval_all(),
            self._short_deadline_max(),
            self._legit_uniswap(),
            self._small_value_unknown(),
            self._multi_chain(),
            self._nft_drain(),
            self._zero_deadline(),
            self._no_expiration(),
        ]

    # ─── 1. EOA Spender + Max Allowance (классический дрейнер) ──
    def _eoa_spender_max(self) -> PhishCase:
        return PhishCase(
            name="EOA Spender + uint160.max",
            type=PhishType.EOA_SPENDER_MAX,
            description="Классический фишинг: spender = EOA, amount = max, deadline = +1 год",
            payload=self._make_payload(
                spender=EOA_SPENDER,
                amount=MAX_UINT160,
                deadline=self.now + 86400 * 365,
                expiration=self.now + 86400 * 365,
            ),
            expected_verdict="RISK",
            expected_score_min=85,
            tags=["critical", "eoa", "max-allowance", "year-deadline"],
        )

    # ─── 2. Легитимный контракт + max allowance (подозрительно) ──
    def _legit_spender_max(self) -> PhishCase:
        return PhishCase(
            name="Known Spender + uint160.max (подозрительно)",
            type=PhishType.LEGIT_SPENDER_MAX,
            description="Spender = Uniswap (легитимный), но amount = max, deadline = +30 дней",
            payload=self._make_payload(
                spender=KNOWN_SPENDER,
                amount=MAX_UINT160,
                deadline=self.now + 86400 * 30,
                expiration=self.now + 86400 * 30,
            ),
            expected_verdict="RISK",
            expected_score_min=50,
            tags=["suspicious", "known-spender", "max-allowance"],
        )

    # ─── 3. Batch Permit — несколько токенов ──
    def _batch_permit(self) -> PhishCase:
        return PhishCase(
            name="Batch Permit — 3 токена max",
            type=PhishType.BATCH_PERMIT,
            description="Batch: USDC + USDT + WETH, каждый uint160.max, deadline +30 дней",
            payload=self._make_batch_payload(
                spender=EOA_SPENDER,
                tokens=[USDC, USDT, WETH],
                amounts=[MAX_UINT160, MAX_UINT160, MAX_UINT160],
                deadline=self.now + 86400 * 30,
                expiration=self.now + 86400 * 30,
            ),
            expected_verdict="RISK",
            expected_score_min=90,
            tags=["critical", "batch", "multi-token", "eoa"],
        )

    # ─── 4. SetApprovalForAll (NFT) ──
    def _set_approval_all(self) -> PhishCase:
        """NFT — SetApprovalForAll через EIP-712 (не ERC-20)."""
        return PhishCase(
            name="SetApprovalForAll NFT",
            type=PhishType.SET_APPROVAL_ALL,
            description="NFT: SetApprovalForAll для BAYC, spender = EOA, все токены",
            payload=self._make_nft_payload(
                nft_contract=BAYC,
                operator=EOA_SPENDER,
                approved=True,
            ),
            expected_verdict="RISK",
            expected_score_min=40,
            tags=["nft", "eoa", "approval-all"],
        )

    # ─── 5. Короткий deadline + max allowance ──
    def _short_deadline_max(self) -> PhishCase:
        return PhishCase(
            name="Short deadline + max (опасно, но deadline мал)",
            type=PhishType.SHORT_DEADLINE_MAX,
            description="Spender = EOA, amount = max, но deadline = 5 минут",
            payload=self._make_payload(
                spender=EOA_SPENDER,
                amount=MAX_UINT160,
                deadline=self.now + 300,
                expiration=self.now + 300,
            ),
            expected_verdict="RISK",
            expected_score_min=40,
            tags=["eoa", "max-allowance", "short-deadline"],
        )

    # ─── 6. Легитимный Uniswap (безопасно) ──
    def _legit_uniswap(self) -> PhishCase:
        return PhishCase(
            name="Legit Uniswap Permit (SAFE)",
            type=PhishType.LEGIT_UNISWAP,
            description="Uniswap V3 Router, 100 USDC, deadline 30 мин — полностью безопасно",
            payload=self._make_payload(
                spender=KNOWN_SPENDER,
                amount=100 * 10**6,
                deadline=self.now + 1800,
                expiration=self.now + 3600,
            ),
            expected_verdict="SAFE",
            expected_score_min=0,
            expected_max_score=0,
            tags=["safe", "uniswap", "small-amount"],
        )

    # ─── 7. Маленькая сумма + неизвестный контракт ──
    def _small_value_unknown(self) -> PhishCase:
        return PhishCase(
            name="Small value + unknown contract (LOW-MEDIUM)",
            type=PhishType.SMALL_VALUE_UNKNOWN,
            description="10 USDC, неизвестный контракт (не в whitelist), deadline 1 час",
            payload=self._make_payload(
                spender="0x000000000022D473030F116dDEE9F6B43aC78BA3",  # Permit2 контракт, но не в whitelist spender
                amount=10 * 10**6,
                deadline=self.now + 3600,
                expiration=self.now + 7200,
            ),
            expected_verdict="SAFE",
            expected_score_min=0,
            expected_max_score=15,
            tags=["unknown-contract", "small-amount"],
        )

    # ─── 8. Multi-chain подпись (chainId = 137 Polygon) ──
    def _multi_chain(self) -> PhishCase:
        return PhishCase(
            name="Multi-chain permit (Polygon)",
            type=PhishType.MULTI_CHAIN,
            description="То же что классический дрейнер, но на Polygon (chainId=137)",
            payload=self._make_payload(
                spender=EOA_SPENDER,
                amount=MAX_UINT160,
                deadline=self.now + 86400 * 365,
                expiration=self.now + 86400 * 365,
                chain_id=137,
            ),
            expected_verdict="RISK",
            expected_score_min=85,
            tags=["critical", "eoa", "polygon", "max-allowance"],
        )

    # ─── 9. NFT Drain (SetApprovalForAll на BAYC, EOA оператор) ──
    def _nft_drain(self) -> PhishCase:
        return PhishCase(
            name="NFT Drain — BAYC + EOA operator",
            type=PhishType.NFT_DRAIN,
            description="SetApprovalForAll на BAYC, оператор = EOA, навсегда",
            payload=self._make_nft_payload(
                nft_contract=BAYC,
                operator=EOA_SPENDER,
                approved=True,
                deadline=self.now + 86400 * 365,
            ),
            expected_verdict="RISK",
            expected_score_min=40,
            tags=["nft", "critical", "eoa", "year-deadline"],
        )

    # ─── 10. Аномалия: deadline = 0 ──
    def _zero_deadline(self) -> PhishCase:
        return PhishCase(
            name="Deadline = 0 (аномалия)",
            type=PhishType.ZERO_DEADLINE,
            description="Deadline = 0 — подпись уже невалидна, но amount = max",
            payload=self._make_payload(
                spender=EOA_SPENDER,
                amount=MAX_UINT160,
                deadline=0,
                expiration=0,
            ),
            expected_verdict="RISK",
            expected_score_min=35,
            tags=["anomaly", "eoa", "max-allowance", "zero-deadline"],
        )

    # ─── 11. Аномалия: нет expiration ──
    def _no_expiration(self) -> PhishCase:
        return PhishCase(
            name="No expiration (Permit только с deadline)",
            type=PhishType.NO_EXPIRATION,
            description="ERC-2612 Permit без expiration, только deadline, spender = EOA",
            payload={
                "primaryType": "Permit",
                "domain": {
                    "name": "USDC",
                    "version": "2",
                    "chainId": 1,
                    "verifyingContract": USDC,
                },
                "message": {
                    "owner": "0x6c2E081071844732CD21189C0EC5E018F576F66A",
                    "spender": EOA_SPENDER,
                    "value": str(MAX_UINT256),
                    "nonce": "0",
                    "deadline": str(self.now + 86400 * 365),
                },
            },
            expected_verdict="RISK",
            expected_score_min=40,
            tags=["erc-2612", "eoa", "max-allowance"],
        )

    # ─── helpers ────────────────────────────────────────────

    def _make_payload(
        self,
        spender: str,
        amount: int,
        deadline: int,
        expiration: int,
        chain_id: int = 1,
        token: str = USDC,
        nonce: int = 0,
    ) -> dict:
        return {
            "primaryType": "PermitSingle",
            "domain": {
                "name": "Permit2",
                "chainId": chain_id,
                "verifyingContract": PERMIT2_ADDRESS,
            },
            "message": {
                "details": {
                    "token": token,
                    "amount": str(amount),
                    "expiration": str(expiration),
                    "nonce": str(nonce),
                },
                "spender": spender,
                "sigDeadline": str(deadline),
            },
        }

    def _make_batch_payload(
        self,
        spender: str,
        tokens: list[str],
        amounts: list[int],
        deadline: int,
        expiration: int,
        chain_id: int = 1,
    ) -> dict:
        details = [
            {
                "token": t,
                "amount": str(a),
                "expiration": str(expiration),
                "nonce": str(i),
            }
            for i, (t, a) in enumerate(zip(tokens, amounts))
        ]
        return {
            "primaryType": "PermitBatch",
            "domain": {
                "name": "Permit2",
                "chainId": chain_id,
                "verifyingContract": PERMIT2_ADDRESS,
            },
            "message": {
                "details": details,
                "spender": spender,
                "sigDeadline": str(deadline),
            },
        }

    def _make_nft_payload(
        self,
        nft_contract: str,
        operator: str,
        approved: bool = True,
        deadline: int | None = None,
    ) -> dict:
        """ERC-721 Permit (EIP-2612 style) или просто SetApprovalForAll."""
        if deadline is None:
            deadline = self.now + 86400 * 365

        return {
            "primaryType": "Permit",
            "domain": {
                "name": "BAYC",
                "chainId": 1,
                "verifyingContract": nft_contract,
            },
            "message": {
                "owner": "0x6c2E081071844732CD21189C0EC5E018F576F66A",
                "spender": operator,
                "tokenId": "0",
                "value": "1" if approved else "0",
                "nonce": "0",
                "deadline": str(deadline),
            },
        }


# ══════════════════════════════════════════════════════════════
# Тестирование
# ══════════════════════════════════════════════════════════════

def run_detector_test(cases: list[PhishCase], verbose: bool = True) -> dict:
    """Прогоняет все кейсы через PermitAnalyzer и возвращает отчёт."""
    analyzer = PermitAnalyzer()
    results = []

    for case in cases:
        result = analyzer.analyze(case.payload)

        verdict_match = (
            (result.safe and case.expected_verdict == "SAFE") or
            (not result.safe and case.expected_verdict == "RISK")
        )

        score_ok = result.score >= case.expected_score_min
        if hasattr(case, 'expected_max_score') and case.expected_max_score is not None:
            score_ok = score_ok and result.score <= case.expected_max_score

        results.append({
            "name": case.name,
            "type": case.type.value,
            "expected": case.expected_verdict,
            "got": "SAFE" if result.safe else "RISK",
            "score": result.score,
            "expected_score_min": case.expected_score_min,
            "expected_score_max": getattr(case, 'expected_max_score', 100),
            "verdict_match": verdict_match,
            "score_ok": score_ok,
            "findings": [
                {"risk": f.risk.value, "param": f.param, "message": f.message}
                for f in result.findings
            ],
        })

    stats = {
        "total": len(results),
        "passed": sum(1 for r in results if r["verdict_match"] and r["score_ok"]),
        "failed": sum(1 for r in results if not (r["verdict_match"] and r["score_ok"])),
    }

    if verbose:
        print("=" * 70)
        print("  PHISHING SIG GENERATOR — тест детектора")
        print("=" * 70)
        print(f"\n  Всего кейсов: {stats['total']}")
        print(f"  Пройдено:     {stats['passed']}")
        print(f"  Провалено:    {stats['failed']}")
        print()

        for r in results:
            status = "✅" if r["verdict_match"] and r["score_ok"] else "❌"
            print(f"  {status} {r['name']:<40} score={r['score']:>3}/100 "
                  f"expected={r['expected_score_min']}-{r['expected_score_max']} "
                  f"got={r['got']}")

        if stats["failed"] > 0:
            print(f"\n  {'─' * 70}")
            print(f"  Детали проваленных:")
            print(f"  {'─' * 70}")
            for r in results:
                if not r["verdict_match"] or not r["score_ok"]:
                    print(f"\n  ❌ {r['name']}")
                    print(f"     Ожидали: {r['expected']} (score {r['expected_score_min']}-{r['expected_score_max']})")
                    print(f"     Получили: {r['got']} (score {r['score']})")
                    for f in r["findings"][:5]:
                        print(f"     {f['risk']:<15} {f['param']:<20} {f['message'][:80]}")

    return {"stats": stats, "results": results}


# ══════════════════════════════════════════════════════════════
# Экспорт
# ══════════════════════════════════════════════════════════════

def export_dataset(cases: list[PhishCase], path: Path, include_analysis: bool = True) -> dict:
    """Экспортирует кейсы в JSON-файл для использования в тестах или датасете."""
    analyzer = PermitAnalyzer() if include_analysis else None
    dataset = []

    for case in cases:
        entry = {
            "name": case.name,
            "type": case.type.value,
            "description": case.description,
            "payload": case.payload,
            "expected_verdict": case.expected_verdict,
            "expected_score_min": case.expected_score_min,
            "tags": case.tags,
        }
        if analyzer:
            result = analyzer.analyze(case.payload)
            entry["actual_verdict"] = "SAFE" if result.safe else "RISK"
            entry["actual_score"] = result.score
            entry["findings"] = [
                {"risk": f.risk.value, "param": f.param, "message": f.message}
                for f in result.findings
            ]
            entry["pass"] = (
                (result.safe and case.expected_verdict == "SAFE") or
                (not result.safe and case.expected_verdict == "RISK")
            ) and result.score >= case.expected_score_min
        dataset.append(entry)

    output = {
        "meta": {
            "generator": "phishing_sig_generator.py",
            "version": "1.0",
            "generated_at": time.time(),
            "total_cases": len(dataset),
        },
        "cases": dataset,
    }

    path.write_text(json.dumps(output, indent=2, ensure_ascii=False))
    return output


# ══════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════

def main():
    import argparse

    parser = argparse.ArgumentParser(description="Phishing Signature Generator")
    parser.add_argument("--generate", action="store_true", help="Сгенерировать и протестировать")
    parser.add_argument("--export", type=Path, help="Экспорт в JSON")
    parser.add_argument("--cases", type=int, default=0, help="Количество кейсов (0 = все)")
    args = parser.parse_args()

    gen = PhishingSigGenerator()
    all_cases = gen.generate_all()

    if args.cases > 0:
        all_cases = all_cases[:args.cases]

    if args.export:
        result = export_dataset(all_cases, args.export)
        print(f"Экспортировано {result['meta']['total_cases']} кейсов в {args.export}")
        return

    if args.generate or True:
        run_detector_test(all_cases)

    # Если нет аргументов — по умолчанию генерация
    if not args.generate and not args.export:
        parser.print_help()


if __name__ == "__main__":
    main()
