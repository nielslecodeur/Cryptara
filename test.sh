#!/usr/bin/env bash

BYTES_HEX=$(cargo run -q -- generate)

cargo run -- generate
cargo run -- generate --mnemonic
cargo run -- verify --mnemonic "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
cargo run -- verify --mnemonic "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon zoo"
cargo run -- root "$BYTES_HEX"
cargo run -- root --mnemonic "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
cargo run -- root --mnemonic "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" --passphrase TREZOR

ROOT_SEED_HEX=$(cargo run -q -- root --mnemonic "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" --passphrase TREZOR)
cargo run -- master "$ROOT_SEED_HEX"

cargo run -- wallet "$BYTES_HEX"
cargo run -- wallet --mnemonic "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" --passphrase TREZOR

cargo run -- init
cargo run -- init --passphrase TREZOR

WALLET_OUT=$(cargo run -q -- wallet --mnemonic "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" --passphrase TREZOR)
PUBLIC_KEY_HEX=$(echo "$WALLET_OUT" | grep "Master public key" | awk '{print $NF}')
CHAIN_CODE_HEX=$(echo "$WALLET_OUT" | grep "Chain code" | awk '{print $NF}')

cargo run -- child "$PUBLIC_KEY_HEX" "$CHAIN_CODE_HEX" --index 0
cargo run -- derive "$PUBLIC_KEY_HEX" "$CHAIN_CODE_HEX" --index 5 --level 3

cargo run -- root
cargo run -- root "$BYTES_HEX" --mnemonic "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
cargo run -- master abcd
cargo run -- child zzzz "$CHAIN_CODE_HEX" --index 0
