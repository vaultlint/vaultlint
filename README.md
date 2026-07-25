# vaultlint

Security linter for Solana and Anchor programs. Catches missing signer and owner
checks, unvalidated PDA bumps, unchecked CPIs and unchecked arithmetic — before you deploy.

**Status: early development.** The first usable release is `v0.1.0`.

## Install

```bash
cargo install vaultlint
```

## Usage

```bash
vaultlint scan ./programs
```

## Licence

MIT OR Apache-2.0.
