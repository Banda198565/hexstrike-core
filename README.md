# HexStrike Core

> Security toolkit — EIP-712 detector, Permit/Permit2 analyzer, SIM800C GSM monitor

[![Test EIP-712 Detector](https://github.com/Banda198565/hexstrike-core/actions/workflows/test.yml/badge.svg)](https://github.com/Banda198565/hexstrike-core/actions/workflows/test.yml)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

---

## Состав

| Модуль | Назначение |
|--------|-----------|
| `eip712_detector.py` | Анализатор EIP-712 Permit payload (риск-скоринг) |
| `phishing_sig_generator.py` | Генератор тестовых фишинг-подписей (11 кейсов) |
| `permit_sim.py` | Симуляция атаки Permit2 от А до Я |
| `mempool_permit_watcher.py` | Мониторинг мемпула на permit-транзакции (WebSocket) |
| `web3_integration.py` | Web3 middleware + функция-обёртка для безопасной подписи |
| `crypto_sms_guard.py` | SMS-монитор для бирж через SIM800C |
| `sim800c_diagnose.py` | Диагностика GSM-модуля SIM800C |

## Тесты

```bash
python3 -m unittest tests/test_eip712_analyzer.py -v
```

## Быстрый старт

```bash
# Анализ EIP-712 payload
python3 scripts/gsm/eip712_detector.py --simulate

# Генерация тестовых подписей
python3 scripts/gsm/phishing_sig_generator.py --generate

# Симуляция атаки Permit2
python3 scripts/gsm/permit_sim.py
```
