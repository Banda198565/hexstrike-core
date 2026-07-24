#!/usr/bin/env python3
"""
rescue_nonce.py — отзыв скомпрометированной Permit/Permit2 подписи.

Использование:
  python3 rescue_nonce.py --rpc https://... --key PRIVATE_KEY \
    --permit2 0x0000...78BA3 --nonce 0

Механика:
  Permit2.invalidateUnorderedNonces(nonce) — сжигает конкретный nonce.
  После вызова подпись с этим nonce становится невалидной,
  даже если v, r, s у атакующего.
"""

from __future__ import annotations

import sys
from web3 import Web3

PERMIT2_ABI = [
    {
        "type": "function",
        "name": "invalidateUnorderedNonces",
        "inputs": [{"name": "nonce", "type": "uint256"}],
        "outputs": [],
        "stateMutability": "nonpayable",
    },
    {
        "type": "function",
        "name": "nonces",
        "inputs": [{"name": "user", "type": "address"}],
        "outputs": [{"name": "", "type": "uint256"}],
        "stateMutability": "view",
    },
]


PERMIT2_ADDRESS = "0x000000000022D473030F116dDEE9F6B43aC78BA3"

# ERC-2612 Permit — отзыв через перевод токенов
ERC20_ABI_MIN = [
    {
        "type": "function",
        "name": "transfer",
        "inputs": [
            {"name": "to", "type": "address"},
            {"name": "amount", "type": "uint256"},
        ],
        "outputs": [{"name": "", "type": "bool"}],
    },
    {
        "type": "function",
        "name": "balanceOf",
        "inputs": [{"name": "account", "type": "address"}],
        "outputs": [{"name": "", "type": "uint256"}],
    },
]


def invalidate_permit2_nonce(
    w3: Web3,
    private_key: str,
    nonce: int,
    permit2_address: str = PERMIT2_ADDRESS,
) -> str:
    """Отзывает nonce в Permit2."""
    account = w3.eth.account.from_key(private_key)
    contract = w3.eth.contract(address=Web3.to_checksum_address(permit2_address), abi=PERMIT2_ABI)

    tx = contract.functions.invalidateUnorderedNonces(nonce).build_transaction({
        "from": account.address,
        "nonce": w3.eth.get_transaction_count(account.address),
        "gas": 50000,
        "gasPrice": w3.eth.gas_price,
        "chainId": w3.eth.chain_id,
    })

    signed = account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    return receipt.transaction_hash.hex()


def rescue_transfer(
    w3: Web3,
    private_key: str,
    token_address: str,
    safe_address: str,
    amount: int | None = None,
) -> str:
    """Переводит токены на SAFE-адрес (если не успели украсть)."""
    account = w3.eth.account.from_key(private_key)
    contract = w3.eth.contract(address=Web3.to_checksum_address(token_address), abi=ERC20_ABI_MIN)

    if amount is None:
        amount = contract.functions.balanceOf(account.address).call()

    tx = contract.functions.transfer(
        Web3.to_checksum_address(safe_address), amount
    ).build_transaction({
        "from": account.address,
        "nonce": w3.eth.get_transaction_count(account.address),
        "gas": 100000,
        "gasPrice": w3.eth.gas_price,
        "chainId": w3.eth.chain_id,
    })

    signed = account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    return receipt.transaction_hash.hex()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Rescue: отзыв Permit/вывод средств")
    parser.add_argument("--rpc", required=True, help="RPC URL")
    parser.add_argument("--key", required=True, help="Приватный ключ BOT (с ETH на газ)")
    parser.add_argument("--permit2-nonce", type=int, help="Nonce для отзыва в Permit2")
    parser.add_argument("--transfer-token", help="Адрес токена для вывода на SAFE")
    parser.add_argument("--to", help="SAFE-адрес")
    parser.add_argument("--amount", type=int, help="Сумма (0 = весь баланс)")
    args = parser.parse_args()

    w3 = Web3(Web3.HTTPProvider(args.rpc))
    account = w3.eth.account.from_key(args.key)

    print(f"BOT:   {account.address}")
    print(f"Chain: {w3.eth.chain_id}")
    print(f"ETH:   {w3.eth.get_balance(account.address) / 1e18:.4f}")
    print()

    if args.permit2_nonce is not None:
        tx = invalidate_permit2_nonce(w3, args.key, args.permit2_nonce)
        print(f"✅ Nonce {args.permit2_nonce} invalidated: {tx[:66]}...")

    if args.transfer_token and args.to:
        tx = rescue_transfer(w3, args.key, args.transfer_token, args.to, args.amount)
        print(f"✅ Transfer to SAFE: {tx[:66]}...")
