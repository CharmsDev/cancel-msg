# cancel-msg

`cancel-msg` is a command-line utility for generating cancellation messages and signatures used in Charms Cast for canceling orders.

It provides tools to:
- Compute the exact cancellation message from a spell YAML file and a target UTXO ID.
- Sign messages using a BIP32 xpriv key.
- Compute Bitcoin signed message hashes.
- Convert P2WPKH addresses to legacy P2PKH addresses.

## Requirements

- Rust 1.75+ (due to `edition = "2021"` and dependencies)
- Git (for `charms-data` dependency)

## Installation

Clone the repository and install:

```sh
git clone https://github.com/your-org/cancel-msg.git  # or your repo
cd cancel-msg
cargo install --path .
```

Or build for release:

```sh
cargo build --release
./target/release/cancel-msg --help
```

## Usage

```
cancel-msg <SUBCOMMAND>;

SUBCOMMANDS:
    sign      Sign a message with an xpriv key at a derivation path
    p2pkh     Convert a P2WPKH (Bech32) address to legacy P2PKH
    msghash   Compute the Bitcoin signed message hash for a message
    message   Compute the cancellation message for a spell UTXO
```

Use `cancel-msg <SUBCOMMAND> --help` for detailed flags.

### sign
Signs a message using the provided xpriv and derivation path. Outputs the hex signature and instructions for adding to a spell's `private_inputs.$CAST.edit_orders.cancel`.

```sh
cancel-msg sign --message "utxo_hash outputs_hash" --xprv xprv... --path "m/86'/0'/0'/0/0"
```

### message
Computes the cancellation message `<utxo_id> <outputs_hash>` from a spell YAML file, where `outputs_hash` is `sha256d(tx_outs || coin_outs)` for the outputs after the matching input UTXO.

Spell YAML structure (simplified):
- `inputs`: array with `coins` containing `utxo_id` matching `<txid>:<vout>`
- `outs`: map of outputs, including `charms`

```sh
cancel-msg message --spell path/to/spell.yaml --utxo-id txid:vout
```

### msghash
```sh
cancel-msg msghash --message "your message"
```

### p2pkh
```sh
cancel-msg p2pkh --address bc1q...
```

## Workflow Example

1. Compute cancellation message:
   ```
   cancel-msg message --spell spell.yaml --utxo-id abc123def...456:2
   # Output: abc123def...456:2 0123456789abcdef...
   ```

2. Sign it:
   ```
   cancel-msg sign --message "abc123def...456:2 0123456789abcdef..." --xprv xprv... --path "m/..."
   ```

3. Add the signature `0: 304502...` to your spell's `private_inputs.$CAST.edit_orders.cancel`.

## Dependencies

- [bitcoin-rs](https://crates.io/crates/bitcoin) 0.32
- [charms-data](https://github.com/CharmsDev/charms) (git)
- clap, anyhow, serde_yaml, hex

## License

MIT