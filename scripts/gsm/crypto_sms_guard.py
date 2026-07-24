#!/usr/bin/env python3
"""
crypto_sms_guard.py — SIM800C SMS-монитор для криптобирж.

Фичи:
  • Реалтайм фильтрация SMS от Bybit/OKX/Binance по ключевым словам
  • Telegram-алерты (опционально, через TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID)
  • Звуковой алерт на macOS (say/afplay)
  • Фоновый мониторинг регистрации SIM (CREG) — детект SIM-swap
  • Лог всего в JSONL
  • HTTP webhook (опционально)

Usage:
  python3 scripts/gsm/crypto_sms_guard.py
  python3 scripts/gsm/crypto_sms_guard.py --port /dev/cu.usbserial-1420 --baud 115200 --duration 0 --sound --telegram

Environment:
  TELEGRAM_BOT_TOKEN=...   — токен бота (опц.)
  TELEGRAM_CHAT_ID=...     — чат ID (опц.)
  WEBHOOK_URL=...          — HTTP POST url алертов (опц.)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import serial
except ImportError:
    print("ERROR: pip install pyserial", file=sys.stderr)
    sys.exit(2)

# ── константы ────────────────────────────────────────────────
ROOT = Path(__file__).resolve().parents[2]
ARTIFACT = ROOT / "artifacts" / "gsm"
ARTIFACT.mkdir(parents=True, exist_ok=True)

DEFAULT_PORT = "/dev/cu.usbserial-1420"
DEFAULT_BAUD = 115200

# Ключевые слова для фильтрации SMS от бирж
EXCHANGE_KEYWORDS = [
    # Bybit
    "bybit", "withdrawal", "API key created", "API Key",
    "whitelist", "address added", "login", "verification code",
    # OKX
    "okx", "提币", "API", "withdraw", "绑定",
    # Binance
    "binance", " withdrawal", "API creation", "address",
    # Общие
    "code:", "OTP:", "one-time", "2FA", "MFA",
    "security", "password reset", "recovery",
    # Русский
    "код", "вывод", "апи", "кошелек", "адрес",
]

# Ключевые слова HIGH-priority (требуют немедленного внимания)
CRITICAL_KEYWORDS = [
    "withdrawal", "вывод", "API key created", "API Key",
    "whitelist", "address added", "password reset",
    "recovery", "login", "new device",
]

OTP_RE = re.compile(r"\b(\d{4,8})\b")

LOG_FILE = ARTIFACT / "crypto-sms-guard.jsonl"


# ── утилиты ──────────────────────────────────────────────────
def log(msg: str) -> None:
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] {msg}")


def send_at(ser: serial.Serial, cmd: str, timeout: float = 2.0) -> str:
    ser.reset_input_buffer()
    ser.write((cmd + "\r\n").encode())
    deadline = time.time() + timeout
    chunks: list[str] = []
    while time.time() < deadline:
        waiting = ser.in_waiting
        if waiting:
            chunks.append(ser.read(waiting).decode(errors="replace"))
            if "OK" in chunks[-1] or "ERROR" in chunks[-1]:
                break
        else:
            time.sleep(0.05)
    return "".join(chunks).strip()


# ── алерты ───────────────────────────────────────────────────
def alert_sound(message: str) -> None:
    """macOS звуковой алерт: голос + системный звук."""
    if sys.platform != "darwin":
        return
    try:
        # Системный звук
        subprocess.run(["afplay", "/System/Library/Sounds/Hero.aiff"],
                       timeout=2, stderr=subprocess.DEVNULL)
        # Голосовое оповещение
        say_text = f"Alert: {message[:100]}"
        subprocess.run(["say", "-v", "Daniel", say_text],
                       timeout=5, stderr=subprocess.DEVNULL)
    except Exception:
        pass


def alert_telegram(message: str) -> None:
    """Отправка в Telegram через Bot API."""
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID")
    if not token or not chat_id:
        return  # Telegram не настроен — молча пропускаем
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = json.dumps({
        "chat_id": chat_id,
        "text": f"🚨 SIM800C Crypto Guard\n\n{message[:2000]}",
        "parse_mode": "HTML",
    }).encode()
    try:
        req = urllib.request.Request(url, data=payload,
                                     headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=10)
        log("[telegram] alert sent")
    except urllib.error.URLError as e:
        log(f"[telegram] send failed: {e}")


def alert_webhook(message: str) -> None:
    """Отправка на HTTP webhook."""
    url = os.environ.get("WEBHOOK_URL")
    if not url:
        return
    payload = json.dumps({
        "source": "sim800c-crypto-guard",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "message": message,
    }).encode()
    try:
        req = urllib.request.Request(url, data=payload,
                                     headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=10)
    except urllib.error.URLError as e:
        log(f"[webhook] failed: {e}")


def fire_alerts(entry: dict, sound: bool = False) -> None:
    """Запускает все сконфигурированные алерты."""
    body = entry.get("body", "")
    header = f"SMS от: {entry.get('sender', '?')} | {entry.get('otp_candidate', '')}"
    msg = f"{header}\n{body[:300]}"

    if sound:
        alert_sound(header)
    alert_telegram(msg)
    alert_webhook(msg)


# ── SMS парсинг ──────────────────────────────────────────────
def parse_incoming_sms(lines: list[str]) -> dict[str, Any] | None:
    """Парсит +CMT: URC или +CMTI + CMGR пару."""
    text = "\n".join(lines).replace("\r", "")
    cmt_match = re.search(r'\+CMT:\s*"([^"]*)"', text)
    if cmt_match:
        sender = cmt_match.group(1)
        body_lines = text.split("\n")
        body = ""
        for i, line in enumerate(body_lines):
            if line.startswith("+CMT:"):
                body = "\n".join(body_lines[i+1:]).strip()
                break
        otp = OTP_RE.search(body)
        return {
            "type": "live",
            "sender": sender,
            "body": body,
            "otp_candidate": otp.group(1) if otp else None,
        }
    return None


def classify_sms(body: str) -> tuple[str, bool]:
    """Классифицирует SMS: (категория, is_critical)."""
    lower = body.lower()
    found_keywords = [kw for kw in EXCHANGE_KEYWORDS if kw.lower() in lower]
    is_critical = any(kw.lower() in lower for kw in CRITICAL_KEYWORDS)

    if not found_keywords:
        return "other", False

    if is_critical:
        return "critical", True

    return "exchange", False


# ── SIM-мониторинг ───────────────────────────────────────────
class SimMonitor:
    """Фоновый мониторинг SIM — детект SIM-swap."""

    def __init__(self, ser: serial.Serial):
        self.ser = ser
        self.last_creg: str | None = None
        self.last_operator: str | None = None
        self.fail_count = 0
        self.max_fails = 3  # после 3 провалов подряд — алерт

    def check(self) -> str | None:
        """Проверяет CREG и оператора. Возвращает None или сообщение об аномалии."""
        try:
            creg = send_at(self.ser, "AT+CREG?")
            cops = send_at(self.ser, "AT+COPS?")
        except Exception:
            self.fail_count += 1
            if self.fail_count >= self.max_fails:
                self.fail_count = 0
                return "[SIM-ALERT] Нет ответа от модуля (потеря связи)"
            return None

        self.fail_count = 0  # сброс счётчика при успехе

        # Парс CREG
        creg_match = re.search(r"\+CREG:\s*(\d),(\d)", creg)
        if not creg_match:
            return None

        stat = int(creg_match.group(2))
        creg_val = f"CREG:{stat}"

        # Парс оператора
        cops_match = re.search(r'\+COPS:\s*\d,\d,"([^"]+)"', cops)
        operator = cops_match.group(1) if cops_match else "unknown"

        alerts: list[str] = []

        # Проверка на потерю регистрации
        if stat not in (1, 5):  # 1=registered home, 5=registered roaming
            if self.last_creg and self.last_creg.startswith("CREG:1"):
                alerts.append(f"[SIM-ALERT] Потеря регистрации: было {self.last_creg}, стало {creg_val}")

        # Проверка на смену оператора
        if self.last_operator and operator != self.last_operator and operator != "unknown":
            alerts.append(f"[SIM-ALERT] Смена оператора: было {self.last_operator}, стало {operator}")

        self.last_creg = creg_val
        self.last_operator = operator

        return "\n".join(alerts) if alerts else None


# ── главный цикл ──────────────────────────────────────────────
def main() -> int:
    parser = argparse.ArgumentParser(description="SIM800C Crypto SMS Guard")
    parser.add_argument("--port", default=DEFAULT_PORT)
    parser.add_argument("--baud", type=int, default=DEFAULT_BAUD)
    parser.add_argument("--duration", type=int, default=0,
                        help="Seconds to run (0 = infinite)")
    parser.add_argument("--sound", action="store_true",
                        help="macOS звуковые алерты")
    parser.add_argument("--creg-interval", type=int, default=60,
                        help="Проверка регистрации SIM каждые N сек (0=откл)")
    args = parser.parse_args()

    log(f"Crypto SMS Guard")
    log(f"  port={args.port}  baud={args.baud}")
    log(f"  duration={'infinite' if args.duration == 0 else f'{args.duration}s'}")
    log(f"  sound={'ON' if args.sound else 'OFF'}")
    if os.environ.get("TELEGRAM_BOT_TOKEN"):
        log("  telegram=ON")
    if os.environ.get("WEBHOOK_URL"):
        log("  webhook=ON")
    log(f"  log={LOG_FILE}")
    log(f"  creg_interval={args.creg_interval}s")
    log("─" * 50)
    log("Жду SMS от бирж... Чтобы остановить: Ctrl+C")
    log("")

    try:
        ser = serial.Serial(args.port, baudrate=args.baud, timeout=0.5)
    except serial.SerialException as e:
        log(f"ERROR: не могу открыть {args.port}: {e}")
        return 1

    time.sleep(0.5)

    # ── инициализация SIM800C ──
    init_cmds = [
        "AT",
        "ATE0",
        "AT+CMGF=1",           # text mode
        "AT+CNMI=2,2,0,0,0",   # live push всех SMS
        'AT+CPMS="SM","SM","SM"',
        'AT+CSCS="GSM"',
    ]
    for cmd in init_cmds:
        resp = send_at(ser, cmd, timeout=2.0)
        if "ERROR" in resp and cmd not in ("AT+CPMS",):
            log(f"WARN: {cmd} → {resp[:80]}")

    log("SIM800C инициализирован, режим SMS активен")

    # ── SIM-монитор ──
    sim_mon = SimMonitor(ser)
    last_creg_check: float = 0

    # ── буфер UART ──
    buffer = ""
    cmt_buffer: list[str] = []
    in_cmt = False

    start = time.time()
    sms_count = 0
    alert_count = 0

    try:
        while args.duration == 0 or time.time() - start < args.duration:
            # ── CREG проверка ──
            if args.creg_interval > 0 and time.time() - last_creg_check > args.creg_interval:
                last_creg_check = time.time()
                alert_msg = sim_mon.check()
                if alert_msg:
                    alert_count += 1
                    log(f"\n⚠️  {alert_msg}")
                    fire_alerts({"body": alert_msg, "otp_candidate": None}, args.sound)

            # ── Чтение UART ──
            if ser.in_waiting:
                data = ser.read(ser.in_waiting).decode(errors="replace")
                buffer += data

                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    line = line.replace("\r", "").strip()

                    if not line:
                        continue

                    # Живая SMS (+CMT:)
                    if line.startswith("+CMT:"):
                        cmt_buffer = [line]
                        in_cmt = True
                        continue

                    if in_cmt:
                        cmt_buffer.append(line)
                        parsed = parse_incoming_sms(cmt_buffer)
                        in_cmt = False
                        cmt_buffer = []

                        if parsed:
                            sms_count += 1
                            category, is_critical = classify_sms(parsed["body"])

                            if category != "other" or is_critical:
                                alert_count += 1
                                level = "🔴 CRITICAL" if is_critical else "🟡 EXCHANGE"
                                otp_str = f" | OTP: {parsed['otp_candidate']}" if parsed.get("otp_candidate") else ""
                                log(f"\n{level}{otp_str}")
                                log(f"  От: {parsed['sender']}")
                                log(f"  Текст: {parsed['body'][:200]}")
                                log(f"  Категория: {category}")
                                log(f"  Всего SMS: {sms_count} | Алертов: {alert_count}")

                                # Сохраняем в лог
                                entry = {
                                    "type": "sms_alert",
                                    "category": category,
                                    "critical": is_critical,
                                    "sender": parsed["sender"],
                                    "body": parsed["body"],
                                    "otp": parsed.get("otp_candidate"),
                                }
                                append_log(LOG_FILE, entry)

                                # Алерты
                                fire_alerts(parsed, args.sound)

            time.sleep(0.05)

    except KeyboardInterrupt:
        log("\nGuard остановлен пользователем")
    except serial.SerialException as e:
        log(f"ERROR: потеря связи с SIM800C: {e}")
        fire_alerts({"body": f"Потеря связи с SIM800C: {e}", "otp_candidate": None}, args.sound)
    finally:
        ser.close()

    log(f"\nИтого: SMS={sms_count} Алертов={alert_count}")
    log(f"Лог: {LOG_FILE}")
    return 0


def append_log(path: Path, entry: dict) -> None:
    entry["timestamp"] = datetime.now(timezone.utc).isoformat()
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    sys.exit(main())
