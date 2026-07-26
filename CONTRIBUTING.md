# Contributing

## Local checks

```bash
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test
```

## Adding a rule

1. Create `src/rules/<name>.rs` with a struct implementing `Rule`.
2. Register it in `rules::all()` in `src/rules/mod.rs`.
3. Add two unit tests: vulnerable code producing exactly one finding, clean code
   producing none. The clean test is the important one.
4. Add an example under `examples/vulnerable/` and extend the expected set in
   `tests/examples.rs`.
5. Make sure `examples/clean/staking.rs` still produces zero findings. A rule that
   fires on it will not be merged.

## Rule quality bar

Precision over recall. If a rule cannot distinguish a real bug from a common safe
pattern, it belongs behind a narrower condition or not at all.
