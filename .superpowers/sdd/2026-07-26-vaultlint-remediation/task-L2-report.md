# Task L2 report — VL001 rewritten as "unproven authority on initialization"

Status: **DONE_WITH_CONCERNS**. One concern, described in full under
[The T5 mismatch](#the-t5-mismatch); it is the reason for the qualifier and it needs a
decision before L3 measures anything.

## What shipped

- `src/rules/signer.rs` deleted; `src/rules/init_authority.rs` created.
- `MissingSignerCheck` → `UnprovenAuthorityOnInit`; title `"missing signer check"` →
  `"unproven authority on initialization"`; severity `High` → `Medium`. Rule id stays
  `VL001`.
- `src/rules/mod.rs`: module list and `linked_all()` updated; `linked_findings_for_files`
  added, and `linked_findings_for` reimplemented in terms of it.
- Carried over from the old file, unchanged: the `MARKERS` constant, `matches_marker`,
  and the whole-identifier field-reference matcher `name_in_seeds` with all of its
  boundary comments.
- Fallout fixed: both `src/lib.rs` scan integration tests, `tests/examples.rs` (expected
  line only), and `examples/vulnerable/missing_signer.rs` (reshaped to the marginfi
  shape, still uncompilable-by-design; `autoexamples = false` untouched).

Triggers T1–T5 and suppressions S1–S4 are implemented as written in the brief, including
the widened form of S2 and the one-hop form of S4. No new dependencies. No changes to
VL002–VL005, `src/usesite.rs`, the README or `docs/`.

### Two implementation notes worth knowing

**`normalised` cannot be used on a whole function body.** It strips *every* space, so
`if authority . is_signer` renders as `ifauthority.is_signer` and the left identifier
boundary that every search in this rule depends on is destroyed. `body_text` renders from
the token stream instead, inserting a space only between two adjacent *words*, so
`if authority.is_signer` keeps its boundary while `ctx.accounts.authority.key()` stays
glued. Rendering from tokens also flattens macro arguments, which is load-bearing: syn
keeps a macro body as an opaque token stream and `require!(x.is_signer, E)` is the
canonical Anchor signer check — test 16 fails without it.

**S4's one-hop uses the AST, not the text.** Argument *positions* are what stop the
suppression leaking between parameters (test 18), and positions do not survive
flattening. `ForwardedTo` visits `ExprCall` and `ExprMethodCall`; the receiver of a
method call is not an argument and `UseSite::params` skips the receiver too, so the
positions line up on both sides of the hop.

## Step 9 — corpus measurement

Release build, `vaultlint scan <repo> --format json --fail-on never`. Both corpora were
present; nothing was substituted.

| Codebase | VL001 | brief's table | file:line |
|---|---|---|---|
| `/tmp/vl-real/liquid-staking-program` | 0 | 0 | — |
| `/tmp/vl-real/marginfi-v2` (HEAD) | 0 | 1, "S2 widening should remove it" | — |
| `/tmp/vl-real/openbook-v2` | 0 | 0 | — |
| `/tmp/vl-real/protocol-v2` (drift) | **2** | 2 | `programs/drift/src/instructions/user.rs:4530`, `:5225` |
| `/tmp/vl-real/squads-mpl` | 0 | 0 | — |
| `/tmp/anchor-check` | **0** | 1 (`CreateAuctionHouse`) | — |

The two drift findings are exactly the pair the brief predicted:
`InitializeSignedMsgUserOrders.authority` (4530) and `InitializeRevenueShare.authority`
(5225). Both are the marginfi shape verbatim — `init` + `seeds = [SEED,
authority.key().as_ref()]` + a bare `pub authority: AccountInfo<'info>` carrying only a
`/// CHECK:` comment.

marginfi-v2 at HEAD gives 0, which agrees with the table's parenthetical: the S2 widening
does remove `TransferToNewAccountPda.new_authority`.

`CreateAuctionHouse.authority` does **not** appear in `/tmp/anchor-check`. That is the
one mismatch, and it is not a tuning question.

### The T5 mismatch

T5 as specified requires the body to contain `<prefix>.<F>.key()` or
`<prefix>.<F>.to_account_info().key()`, where `<prefix>` is `<binding>.accounts` or
`self`. Implemented exactly that way, it does not match a handler that first binds the
field to a local.

metaplex's handler
(`/tmp/anchor-check/tests/auction-house/programs/auction-house/src/lib.rs:46`) does:

```rust
let authority = &ctx.accounts.authority;
…
auction_house.creator = authority.key();
auction_house.authority = authority.key();
```

The brief itself quotes that handler as `auction_house.creator = authority.key();` — the
*aliased* spelling — while specifying T5 in the prefixed form. The two do not meet.

This is not confined to metaplex. **The confirmed true positive has the same shape.**
marginfi's real handler
(`/tmp/vl-real/marginfi-v2/programs/marginfi/src/instructions/marginfi_account/initialize.rs:68`)
destructures:

```rust
let MarginfiAccountInitializePda { authority, marginfi_group, marginfi_account: …, .. } = ctx.accounts;
…
marginfi_account.initialize(marginfi_group.key(), authority.key(), …);
```

So on the actual pre-fix marginfi source — the single bug this rule exists to catch —
T5 as written would not fire either. Brief test 1 passes only because the test handler
the brief specifies uses the direct `ctx.accounts.authority.key()` spelling.

I did **not** change T5. The brief says plainly: *"Do not tune the rule to hit the numbers
in the table above — report what you actually get, including a mismatch."* Widening T5 is
exactly that, it changes the rule's trigger surface across the whole corpus, and L3 is the
task that measures trigger surfaces. So the shipped rule is the spec.

I did measure the alternative, so the decision can be made on data rather than on a
guess. Adding one clause to T5 — also accept `<F>.key()` / `<F>.to_account_info().key()`
as a bare identifier, with the same `contains_access` boundary check that already rejects
`vault.authority.key()` and `mod::authority.key()`:

```rust
reads(&body.text, &body.base(&field.name), "key()") || reads(&body.text, &field.name, "key()")
```

produces, across the same six repos:

| Codebase | VL001, narrow T5 | VL001, alias-tolerant T5 |
|---|---|---|
| liquid-staking-program | 0 | 0 |
| marginfi-v2 (HEAD) | 0 | 0 |
| openbook-v2 | 0 | 0 |
| protocol-v2 | 2 | 2 |
| squads-mpl | 0 | 0 |
| anchor-check | 0 | **1** — `CreateAuctionHouse.authority`, `lib.rs:1098` |

One clause, zero new false positives on this corpus, and it reproduces the brief's table
exactly. My recommendation is to take it in L3 — but it is L3's call, with L3's full
corpus behind it, not mine.

## Tests

`cargo test`: **105 passed, 0 failed** (101 lib + 4 integration). `cargo fmt` clean;
`cargo clippy --all-targets -- -D warnings` clean.

All 19 required cases are present in `src/rules/init_authority.rs`, plus a marker-set
census, a non-marker negative, and two unit tests pinning `body_text` and
`contains_access`.

### Mutation results — every guard is tested

Each mutation was applied to the shipped source, `cargo test --lib init_authority` run,
and the source restored byte-for-byte.

| Guard removed | Tests that then fail |
|---|---|
| T1 raw-account type check | `the_marginfi_fix_silences_the_finding` (**test 2**) |
| T2 marker set | `a_name_that_is_not_an_authority_marker_does_not_fire` |
| T4 name must be in the seeds | `an_authority_absent_from_the_seeds_does_not_fire` (**7**), `a_field_access_in_the_seeds_does_not_satisfy_t4` (**8**) |
| T3 **and** T4 together | `the_textbook_missing_signer_case_is_a_deliberate_documented_miss` (**9**), plus 7 and 8 |
| T5 handler reads the key | `a_struct_with_no_linked_body_never_fires` (**5**), `forwarding_the_account_…_does_not_fire` (**6**) |
| S1 own constraints | `an_own_constraint_silences_the_finding` (**10**) |
| S2 settled-sibling binding | `a_settled_sibling_binding_the_field_silences_the_finding` (**11**), `a_constraint_call_mentioning_the_field_silences_the_finding` (**13**) |
| S2 `init` exclusion | `a_binding_on_an_init_sibling_proves_nothing` (**12**) |
| S3 proven signer authority | `a_proven_signer_authority_in_the_struct_silences_the_finding` (**14**) |
| S3's binding requirement | `an_unbound_signer_does_not_stand_in_for_a_proven_authority` (**15**), and 7 more |
| S4 as a whole | tests **16** and **17** |
| S4 direct read | `an_is_signer_check_in_the_handler_silences_the_finding` (**16**) |
| S4 one hop | `an_is_signer_check_one_call_away_silences_the_finding` (**17**) |
| S4 argument position | `an_is_signer_check_on_a_different_parameter_…` (**18**) |
| `body_text` word separation | test **17**, and the `body_text` unit test |
| `contains_access` left boundary | the `contains_access` unit test |
| test 19's nested `Cargo.toml`s | `a_check_in_another_crate_does_not_silence_this_ones_finding` (**19**) |

The three the brief singled out, in full:

- **Test 12** (`a_binding_on_an_init_sibling_proves_nothing`). Mutation: delete
  `&& !carries_init(sibling)` from `bound_by_settled_sibling`. The `has_one = authority`
  on the `init` sibling then counts as a binding, S2 fires, and the test drops from 1
  finding to 0. It is the exact inverse of test 11, which the same mutation leaves
  passing — so the pair isolates the `init` exclusion and nothing else.

- **Test 15** (`an_unbound_signer_does_not_stand_in_for_a_proven_authority`). Mutation:
  reduce `has_proven_signer_authority` to
  `field.ty == AccountTy::Signer && is_authority_named(&field.name)`, dropping the
  `&& bound_by_settled_sibling(...)`. The bare `pub admin: Signer<'info>` then satisfies
  S3, the struct is skipped, and the test drops from 1 finding to 0. Test 14, its
  inverse, still passes. This mutation also breaks 7 other tests, because `fee_payer:
  Signer` in the marginfi struct is authority-named (`_payer`) and would silence the
  whole shape — which is itself a good measure of how load-bearing the binding
  requirement is.

- **Test 18** (`an_is_signer_check_on_a_different_parameter_does_not_silence_the_finding`).
  Mutation: `site.params.get(position)` → `site.params.first().or(site.params.get(position))`.
  The helper's checked parameter `authority` is then found regardless of which position
  the field was passed in, S4 fires, and the test drops from 1 finding to 0. Test 17, its
  inverse, still passes.

Two notes on the table:

- **T3 has no single-line mutation.** Relaxing only the `init_fields.is_empty()` early
  return changes nothing, because T4 already looks the field up among the `init` fields
  and finds none. T3 is a fast path for a condition T4 enforces anyway. Test 9 needs both
  relaxed before it fails — i.e. the miss is guarded twice over, which is stronger than
  the brief asked for, not weaker.
- **Crate scoping** lives in `src/usesite.rs`, which is out of scope here, so the
  mutation was applied to the test instead: removing the two nested `Cargo.toml` files
  merges the crates and the secure handler's `require!` silences the insecure crate's
  finding. That confirms the test is actually sensitive to crate scoping rather than
  passing for an unrelated reason.

## Deviations and things deliberately not done

- **T5 shipped narrow.** See above. This is the only deviation from the brief's expected
  numbers, and it is a deviation of the numbers from the spec, not of the code from the
  spec.
- `examples/vulnerable/missing_signer.rs` was rewritten rather than patched: the old
  shape (bare `authority` beside a `mut` vault) no longer triggers anything. The new file
  is the marginfi shape minimally reduced — `init` + `seeds = [b"account",
  authority.key().as_ref()]`, an unvalidated `authority: AccountInfo`, and a handler that
  writes `ctx.accounts.authority.key()` into the account being created. Expected line in
  `tests/examples.rs` moved 8 → 27. The file name was left alone; renaming it belongs
  with the docs task.
- `src/lib.rs`'s two scan tests now use a two-file declaration/handler pair, because the
  new rule cannot fire without a linked body. `scans_a_directory_and_skips_unparsable_files`
  consequently expects `files_scanned == 2`.
- VL002 is still `High`, so `the_binary_fails_the_build_on_high_severity_findings` still
  passes with VL001 at `Medium`. No change was needed there.
- README, `docs/`, and `docs/rule-pages.md` are untouched, as instructed — they still
  describe VL001 as "missing signer check" and will be wrong until the docs task lands.
