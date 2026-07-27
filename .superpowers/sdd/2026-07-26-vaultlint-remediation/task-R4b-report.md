# Task R4b — VL002 recall: report

Status: **DONE_WITH_CONCERNS** (the work is complete and green; the concerns are about
what the measurement says, not about the change).

VL002 across the twelve trees: **8 → 44**. VL001 4 → 4, VL003 579 → 579, VL004 66 → 66,
VL005 21 → 21 — no movement in any other rule.

---

## 1. What changed

`src/rules/owner.rs` only, plus one new file `examples/clean/checked_raw_read.rs`.

### Defect 1 — the silencer

`check_body`'s `normalised(block).contains(".owner")` early return is gone. It is
replaced by `has_owner_check(block)`, an `OwnerCheckFinder` visitor with three arms,
exactly as specified:

1. `visit_expr_binary` — `BinOp::Eq` / `BinOp::Ne` where either operand's normalised
   text contains `.owner`.
2. `visit_macro` — final path segment in the new `OWNER_CHECK_MACROS` constant
   (`require_keys_eq`, `require_keys_neq`, `require_eq`, `require_neq`, `require`,
   `assert_eq`, `assert_ne`) **and** the macro's token text contains `.owner`. This arm
   exists because macro tokens are never parsed as expressions, so arm 1 cannot see
   inside them.
3. `visit_expr_call` / `visit_expr_method_call` — final path segment (or method ident),
   lowercased, contains `owner` or `owned`. Matched on the *identifier*, never on the
   whole expression text, so `transfer(…, owner, …)` does not silence.

The compared-against side is deliberately **not** additionally required to look like a
program id. That would be a second narrowing in the same round, and its failure
direction is false negatives on the tool's only High-severity rule.

### Defect 2 — raw-read shapes

*Part A.* New `RAW_READ_SIGNALS` constant with `.data.borrow()`, `.data.borrow_mut()`,
`.try_borrow_data()`, `.try_borrow_mut_data()`; `reads_account_data` now tests an
argument's normalised text against all four.

*Part B.* `collect_raw_read_locals` collects the *names* of `let` bindings whose
initialiser text contains one of the signals, walking the same nested-block shapes as
`cpi.rs`'s `collect_let_bindings_expr` (block, if/else, match arms, loop, while, for,
unsafe, closure, async, try). An argument then also counts as a raw read when its
leading identifier — after stripping `*`, `&`, `&mut`, via `rules::is_ident_char` — is
one of those names, so both `try_from_slice(&data)` and `try_from_slice(&data[8..])`
count.

### On sharing the collector with `cpi.rs` — considered, rejected

I read `collect_let_bindings` / `collect_let_bindings_expr` for the set of block shapes
to walk and reproduced that set, but the two collectors stay separate. `cpi.rs`'s keeps
the whole initialiser *expression* and a source `Pos`, because VL005 has to substitute
the initialiser into the program-id text and resolve a name **as of the call's own
position** (that positional resolution was the entire point of R4a round 3). VL002 needs
a set of names and no position at all: a local holding raw bytes taints any read of it
regardless of where the deserialiser sits, and VL002 never substitutes anything.
Unifying them would give one helper two jobs and force VL002 to carry a `Pos` and a
cloned `syn::Expr` per binding that it would immediately discard — and would couple the
two rules' fix rounds, which is exactly what the previous rounds have been paying to
avoid. The duplication is ~35 lines of a match statement whose arms are dictated by
`syn`, not by either rule.

### Deliberately unchanged — do not "fix" this

`is_deserialiser` still matches only `syn::Expr::Call` with a path callee, so the method
form `account.try_deserialize(&mut data)` is invisible. That is correct and must stay:
`try_deserialize` **as a method on an Anchor typed account** is the safe path — it is
what `Account<'info, T>` does internally, *after* Anchor has already checked the owner.
Matching it would flag the correct pattern. This is now recorded in the module doc
comment at the top of `owner.rs`, so the next reader meets it before the code.

---

## 2. Tests

The four pre-existing tests pass **unchanged**; none needed editing.

Which silencer rule each negative test exercises:

| test | silencer rule |
|---|---|
| `accepts_deserialisation_guarded_by_an_owner_check` (pre-existing) | rule 2 — `require_keys_eq!` macro |
| `a_comparison_against_the_owner_still_silences` (new) | rule 1 — `!=` binary |
| `an_owner_helper_call_still_silences` (new) | rule 3 — `assert_owned_by(…)` call |
| `ignores_typed_anchor_accounts`, `ignores_deserialisation_that_is_not_reading_raw_account_data` | none — they have no raw read at all |
| `the_let_hop_ignores_locals_that_do_not_hold_account_data` (new) | none — it guards the let-hop's initialiser test |
| `examples/clean/checked_raw_read.rs` (new) | rule 2 |

Eight tests added. Every killing mutation below was **applied to the source and run**,
not argued; the file was restored from a byte-for-byte copy after each.

| # | test | mutation applied | result |
|---|---|---|---|
| 1 | `a_bare_owner_read_does_not_silence_the_rule` | `has_owner_check` body → `normalised(block).contains(".owner")` | FAILED (also #3) |
| 2 | `a_comparison_against_the_owner_still_silences` | delete `visit_expr_binary` arm | FAILED (only it) |
| 3 | `an_owner_helper_call_still_silences` | delete `visit_expr_call` arm's body | FAILED (only it) |
| 4 | `flags_an_inline_try_borrow_data_read` | remove `".try_borrow_data()"` from `RAW_READ_SIGNALS` | FAILED (also #6, #8) |
| 5 | `flags_an_inline_mutable_borrow_read` | remove `".data.borrow_mut()"` | FAILED (only it) |
| 6 | `flags_a_read_through_an_intermediate_local` | drop the `leading_ident` branch of `reads_account_data` | FAILED (also #8) |
| 7 | `the_let_hop_ignores_locals_that_do_not_hold_account_data` | record every binding, ignoring the initialiser | FAILED (only it) |
| 8 | `flags_an_intermediate_local_inside_a_nested_block` | delete the `syn::Expr::If` arm of `collect_raw_read_locals_expr` | FAILED (only it) |
| extra | `accepts_deserialisation_guarded_by_an_owner_check` + both clean-example tests | delete the `visit_macro` arm's body | FAILED — the macro rule is covered by the pre-existing unit test *and* by the new clean example |

Test 6 asserts the finding's line is the deserialiser (line 5), not the `let` (line 4);
test 8 asserts line 6 inside the `if` block.

`cargo fmt`, `cargo clippy --all-targets -- -D warnings` clean; `cargo test` green:
**157 lib + 4 integration, 0 failed**. `tests/examples.rs` needed **no change** — the new
clean file adds no findings and `examples/vulnerable/missing_owner.rs` still fires once
at line 5.

---

## 3. The clean-example revert experiment (a measurement, not an argument)

`examples/clean/checked_raw_read.rs` reads raw data through the intermediate-local
`try_borrow_data` form and checks the owner with `require_keys_eq!(*account.owner,
crate::ID);`.

* With the file as committed: `vaultlint scan examples/clean --format json --fail-on
  never` prints `[]`.
* I then **deleted the `require_keys_eq!` line** and re-ran the same command. Output:
  one finding, `VL002`, `examples/clean/checked_raw_read.rs`, **line 15**, snippet
  `let registry = Registry::try_from_slice(&data[8..])?;`.
* I restored the line and re-ran: `[]` again.

So the canary is load-bearing: it is silent because of that one line, and the line it
fires on is the deserialiser, one hop away from the `try_borrow_data`.

---

## 4. Measurement

`cargo build --release`, then `vaultlint scan <tree> --format json --fail-on never` over
all twelve trees.

| tree | VL002 before | VL002 after |
|---|---|---|
| /tmp/anchor-check | 1 | 2 |
| /tmp/vl-wide/program-examples | 7 | 10 |
| /tmp/vl-wide/metaplex-program-library | 0 | 12 |
| /tmp/vl-wide/mango-v4 | 0 | 1 |
| /tmp/vl-wide/helium-program-library | 0 | 3 |
| /tmp/vl-wide/jito-programs | 0 | 0 |
| /tmp/vl-wide/v4 | 0 | 3 |
| /tmp/vl-real/protocol-v2 | 0 | 5 |
| /tmp/vl-real/marginfi-v2 | 0 | 8 |
| /tmp/vl-real/openbook-v2 | 0 | 0 |
| /tmp/vl-real/squads-mpl | 0 | 0 |
| /tmp/vl-real/liquid-staking-program | 0 | 0 |
| **total** | **8** | **44** |

Other rules, before → after: VL001 4 → 4, VL003 579 → 579, VL004 66 → 66, VL005 21 → 21.
Nothing moved.

**Baseline discrepancy worth recording.** The brief states VL003 585 and VL004 68. My
*pre-change* run of the unmodified binary over the same twelve trees measured VL003 579
and VL004 66. The gap therefore predates this task and was not introduced by it; both my
before and after runs used the same script and the same corpus checkouts, and both give
579 / 66. VL001 (4), VL002 (8) and VL005 (21) matched the brief exactly.

---

## 5. Classification of all 44 survivors

Every finding, not a sample. Classes:

* **A — genuinely unvalidated**: nothing in the function verifies the owning program or
  the account's address before the bytes are trusted.
* **B — validated by PDA address, silencer misses it**: the body derives the expected
  address (`create_program_address` / `find_program_address` / `assert_derivation`) with
  the program's own id and compares it to the account key. Address equality with a PDA of
  this program is at least as strong as an owner check, but mentions no `.owner`.
* **C — validated by an Anchor `#[derive(Accounts)]` constraint** (`address = …`, or
  `seeds`/`bump`). VL002 reads function bodies only; it never sees the struct.
* **D — not on-chain program code**: `#[cfg(test)]` unit tests, fuzz harnesses,
  off-chain CLI.
* **E — helper on `&AccountInfo` whose caller validates**: interprocedural, out of reach
  of a single-function rule.

| # | file:line | deserialiser | class |
|---|---|---|---|
| 1 | anchor-check `lang/src/accounts/migration.rs:916` | `AccountV1::try_deserialize(&mut persisted_data)` | D — inside `#[cfg(test)] mod`, data the test itself wrote |
| 2 | anchor-check `tests/auction-house/…/utils.rs:301` | `Metadata::try_deserialize(&mut &**metadata_info.data.borrow())` | A (helper `pay_creator_fees`; metadata owner never checked) |
| 3 | marginfi `p0-cli/src/processor/oracle.rs:66` | `PriceUpdateV2::deserialize(&mut data)` | D — off-chain CLI reading an RPC-fetched account |
| 4–6 | marginfi `programs/marginfi/fuzz/src/bank_accounts.rs:29,51,72` | `PriceUpdateV2::deserialize(&mut &data[8..])` | D — fuzz harness |
| 7–9 | marginfi `programs/marginfi/fuzz/src/lib.rs:1350,1365,1374` | same | D — `#[test]` fns in the fuzz crate |
| 10 | marginfi `programs/marginfi/src/state/price.rs:1525` | `PriceUpdateV2::deserialize(&mut &price_feed_data.as_ref()[8..])` | E — `load_price_update_v2_checked`; checks the discriminator, and its own doc says the oracle key is "checked by the caller" |
| 11 | drift `instructions/pyth_lazer_oracle.rs:31` | `Storage::try_deserialize(&mut &storage_account_data[..])` | C — `#[account(address = PYTH_LAZER_STORAGE_ID)]` |
| 12–13 | drift `state/oracle.rs:419,454` | `PriceUpdateV2::try_deserialize` / `PythLazerOracle::try_deserialize` | E — `get_pyth_price(price_oracle: &AccountInfo, …)`; the oracle key is pinned by the market config at the call site |
| 14–15 | drift `state/perp_market.rs:1679,1692` | same, in `get_pyth_twap` | E — same shape |
| 16–17 | helium `set_entity_active_v0.rs:48,65` | `IotHotspotInfoV0` / `MobileHotspotInfoV0::try_deserialize(&mut info_data.as_ref())` | B — `create_program_address(…, &crate::id())` + `require!(expected_pda == ctx.accounts.info.key())` |
| 18 | helium `relinquish_expired_vote_v0.rs:49` | `PositionV0::try_deserialize(&mut data.as_ref())` | A — `position` is a bare `AccountInfo`, only `require_eq!(position.mint, marker.mint)` afterwards |
| 19 | mango-v4 `instructions/alt_set.rs:10` | `AddressLookupTable::deserialize(&alt_bytes)` | A — admin-gated, and the source carries a commented-out owner check with a `FUTURE:` note |
| 20 | metaplex `auction-house/…/utils.rs:386` | `Metadata::deserialize(&mut data.as_ref())` | A (helper; only a `data[0] == MetadataV1` key-byte test) |
| 21 | metaplex `candy-machine/…/remove_collection.rs:40` | `Metadata::deserialize(&mut data.as_ref())` | A — key-byte + `update_authority` test only |
| 22 | metaplex `candy-machine/…/set_collection.rs:48` | same | A — same |
| 23 | metaplex `candy-machine/…/set_collection.rs:112` | `AnchorDeserialize::deserialize(&mut &*data_ref)` | C — `collection_pda` has `seeds = [CollectionPDA::PREFIX, candy_machine.key()], bump` |
| 24 | metaplex `candy-machine/…/set_collection_during_mint.rs:116` | `Metadata::deserialize(&mut data.as_ref())` | A — the account read is `collection_metadata`; the `cmp_pubkeys(ctx.accounts.metadata.owner, …)` check at line 60 covers a *different* account |
| 25 | metaplex `candy-machine/src/utils.rs:249` | `MasterEditionV2::deserialize(&mut data.as_ref())` | A (helper `assert_master_edition`) |
| 26–27 | metaplex `fixed-price-sale/…/init_selling_resource.rs:51,69` | `Metadata::deserialize` / `MasterEditionV2::deserialize` | B — two `assert_derivation` calls precede both reads |
| 28 | metaplex `fixed-price-sale/…/save_primary_metadata_creators.rs:17` | `Metadata::deserialize(&mut data.as_ref())` | A — key-byte test only |
| 29 | metaplex `hydra/src/utils/mod.rs:77` | `FanoutMint::try_deserialize(&mut fanout_mint_data)` | B — `assert_derivation(&crate::ID, …)` immediately above, and the returned bump is compared to the deserialised bump |
| 30 | metaplex `hydra/src/utils/validation/mod.rs:124` | `Metadata::deserialize(&mut data.as_ref())` | A (helper `assert_valid_metadata`) |
| 31 | metaplex `token-entangler/src/utils.rs:201` | `Metadata::deserialize(&mut data.as_ref())` | A (helper `pay_creator_fees`) |
| 32–33 | program-examples `basics/counter/{mpl-stack,native}/…/lib.rs:59,52` | `Counter::try_from_slice(&counter_account.try_borrow_mut_data()?)` | A — only `assert!(is_writable)` |
| 34 | program-examples `basics/cross-program-invocation/…/lever/src/lib.rs:67` | `PowerStatus::try_from_slice(&power.data.borrow())` | A — nothing checked at all |
| 35 | program-examples `basics/favorites/…/get_pda.rs:25` | `Favorites::try_from_slice(&favorite_account.data.borrow())` | B — `find_program_address` + `if favorite_account.key != &favorite_pda { return Err(…) }` |
| 36 | program-examples `basics/program-derived-addresses/…/increment.rs:13` | `PageVisits::try_from_slice(&page_visits_account.data.borrow())` | A — nothing checked |
| 37 | program-examples `basics/realloc/…/reallocate.rs:21` | `AddressInfo::try_from_slice(&target_account.data.borrow())` | A — nothing checked |
| 38 | program-examples `tokens/escrow/…/take_offer.rs:49` | `Offer::try_from_slice(&offer_info.data.borrow()[..])` | B — `create_program_address(offer_signer_seeds, program_id)` compared to `*offer_info.key` |
| 39 | program-examples `tokens/token-2022/transfer-hook/…/tx_hook.rs:63` | `ABWallet::try_deserialize(&mut &wallet_data[..])` | A — `ab_wallet` is an unconstrained `UncheckedAccount` |
| 40–41 | program-examples `tools/shank-and-solita/…/{pick_up_car,return_car}.rs:37` | `RentalOrder::try_from_slice(&rental_order_account.data.borrow())` | B — `find_program_address` + `assert!(pda == account.key)` |
| 42–44 | squads `v4/…/transaction_accounts_close.rs:77,184,418` | `Proposal::try_deserialize(&mut &**proposal.data.borrow_mut())` | C — `proposal` carries `seeds = […], bump` in the Accounts struct |

Totals: **A 17, B 9, C 5, D 8, E 5**.

Note on class A: five of the seventeen (2, 20, 25, 30, 31) are `&AccountInfo` helpers
whose callers might validate; I did not trace every call site, and they are the shape
Metaplex has historically been exploited through, so I left them in A rather than
promoting them to E.

### Dominant false-positive shape, with two verified examples

The single biggest non-program-code group is **B + C = 14 of 44 (32%)**: the account is
validated by *address*, not by owner. Two verified examples, both read in full:

1. `program-examples/basics/favorites/native/program/src/instructions/get_pda.rs:25` —
   the handler computes `find_program_address(&[b"favorite", user.key.as_ref()],
   program_id)` and returns `ProgramError::IncorrectProgramId` unless
   `favorite_account.key` matches, *before* the `try_from_slice`. Nothing mentions
   `.owner`, so no silencer arm fires.
2. `v4/programs/squads_multisig_program/src/instructions/transaction_accounts_close.rs:77`
   — `proposal` is declared `#[account(mut, seeds = [SEED_PREFIX, multisig.key(),
   SEED_TRANSACTION, …, SEED_PROPOSAL], bump)]`, i.e. Anchor verifies the address before
   the handler runs. The doc comment on the field says so explicitly. VL002 reads only
   function bodies, so it cannot see this.

Class D (8 of 44, 18%) is a second, cheaper group: fuzz harnesses, `#[cfg(test)]`
modules and an off-chain CLI. All eight are in marginfi and anchor-check.

Per the brief I have **not tuned anything** in response to this. 44 is not "the
hundreds", and 17 clean class-A findings is a real improvement over 8. The controller
decides whether a narrowing round is warranted; if it is, the two candidates are a
PDA-derivation silencer arm (would remove 9) and reading `#[derive(Accounts)]`
constraints (would remove 5) — the second one needs the anchor model that
`RuleContext.anchor` already carries.

---

## 6. Concerns

1. **Four of the eight baseline findings look like class B to me, not true positives.**
   The brief states the controller inspected all eight and found every one a true
   positive. Findings 35, 38, 40 and 41 (favorites, escrow, and the two shank-and-solita
   handlers) each derive the expected PDA with the program's own id and compare it to the
   account key before trusting the data. I may be wrong about how much protection that
   gives — writing to an account the program does not own fails at runtime anyway, which
   is part of why these are hard to call — but the disagreement should be settled before
   VL002's precision is quoted anywhere public.
2. **`&mut` in the let-hop is resolved positionally, not syntactically.** `normalised`
   strips whitespace, so `&mut data` arrives as `&mutdata`; `leading_ident` strips a
   `mut` only when it directly follows a `&`. A local genuinely named `mutable` would be
   read as `able` and its read missed. False negative, safe direction, does not occur in
   the corpus, documented at the function. An AST-based extraction would avoid it
   entirely, but the brief explicitly directs `is_ident_char` reuse here.
3. **`OWNER_CHECK_MACROS` includes bare `require`.** `require!(a.owner == b, …)` silences,
   which is intended, but so would `require!(x, MyError::E)` in a body that happens to
   mention `.owner` inside the macro's tokens. That is the generous direction and matches
   the brief's list verbatim.
4. **VL003/VL004 baselines differ from the brief** (579 vs 585, 66 vs 68) — measured
   before touching anything, so not caused by this task. See §4.

---

# Task R4b — fix round 1: report

Status: **DONE_WITH_CONCERNS**. Both silencers are implemented as specified, all six new
tests are killable and every mutation was applied and run. The measurement landed at
**VL002 44 → 32**, not the expected 30, and — more importantly — **one finding I had
classified A was silenced**. Per the instruction I am reporting that rather than
adjusting the rule.

VL001 4, VL003 579, VL004 66, VL005 21 — all unchanged.

---

## 1. What changed

`src/rules/owner.rs` (nearly all of it), plus one shared helper moved in
`src/rules/mod.rs` / `src/rules/cpi.rs`. No other rule touched, no scanning or file
selection touched, version still `0.1.0`.

### `whole_word_match` promoted to `rules::`

It was private to `cpi.rs`. VL002 needs the same identifier-boundary match, and the
findings file directs reuse rather than a hand-rolled `contains`, so it moved verbatim to
`src/rules/mod.rs` next to `find_bounded`, whose empty-needle guard it depends on.
`cpi.rs` now imports it; its behaviour and its `whole_word_match_with_empty_needle_returns_false`
test are unchanged.

### S3 — a PDA address check is an owner check

New `PDA_DERIVATIONS` constant with exactly the three names given. A new
`AddressEvidence` visitor collects, per function body:

* `derives` — true if any call's final path segment is in `PDA_DERIVATIONS`;
* `proofs` — the normalised text of every `==` / `!=` binary, of every
  `OWNER_CHECK_MACROS` macro's tokens, and of every `PDA_DERIVATIONS` call's arguments.

`pda_address_check_covers` silences a read only when `derives` **and** the read's
receiver identifier appears as a whole identifier (via `whole_word_match`) in one of the
proofs. Both halves are load-bearing and each has its own killable test — condition 2 in
particular has the dedicated over-reach test the findings file insisted on.

Ordering is not required, as directed. Named consequence, as directed:
`program-examples/tokens/escrow/native/…/take_offer.rs:49` deserialises at 49 and checks
the address at 65–69, and it is now silent. That is the accepted miss.

### S4 — an Anchor address or seeds constraint

`check_body` now takes the `syn::Signature` as well as the block.
`context_accounts_struct` reads the `Context<S>` parameter with
`usesite::context_struct_name` and looks `S` up in `ctx.anchor.accounts_structs`.
`anchor_address_constraint_covers` then silences a read whose receiver is of the shape
`…​.accounts.<field>` when *that* field carries `Constraint::Seeds(_)` or
`Constraint::Other("address", _)`.

The field name is extracted as the identifier immediately after `.accounts.` and compared
with `==`, never as a substring, so the R4a bug (a bare field name silencing an unrelated
same-named account) is not reintroduced. Only the named field may silence; the over-reach
test pins that.

### Two things the findings file did not mention but the corpus required

Both were discovered by reading the class-C sources, not by tuning to a number.

1. **`Context<Self>`.** Squads-v4 writes every account-closing handler as
   `pub fn …(ctx: Context<Self>)` inside `impl <AccountsStruct>`. `context_struct_name`
   correctly returns `"Self"`, which matches no struct. `FunctionVisitor` now tracks the
   enclosing `impl` block's self type (`visit_item_impl`, saved and restored around the
   recursion) and resolves `Self` through it. Without this, 2 of the 3 squads findings
   would have stayed.
2. **One-hop alias resolution.** The real class-C shape is
   `let proposal = &mut ctx.accounts.proposal;` followed by
   `proposal.data.borrow_mut()`, so the receiver as written is `proposal` and S4 would
   never see `.accounts.`. `collect_raw_read_locals` was therefore generalised into
   `collect_let_bindings` (name + normalised, deref-stripped initialiser text), and a
   read's receiver is now a **list** of candidates: the text as written, plus its one-hop
   expansion through any same-named binding whose initialiser is a plain *alias*.

   "Alias" means the initialiser contains no `(`. That guard matters:
   `fixed-price-sale/…/init_selling_resource.rs` binds `metadata` twice, first to
   `&self.metadata` (an alias) and later to `Metadata::deserialize(…)` (a value).
   Expanding through the second would swap the account for its contents. Keeping *both*
   the written and the expanded form is what lets S3 match the local name the proofs use
   (`assert_derivation(…, metadata, …)`) while S4 matches the qualified path.

   A name bound more than once contributes one candidate per binding. This rule carries
   no source positions — deliberately, per the accepted round-0 decision — so there is no
   basis for choosing which binding is in scope, and every candidate is kept. That is the
   generous direction and it is written down at the type.

### Renames (no behaviour change)

`collect_raw_read_locals*` → `collect_let_bindings*`; `reads_account_data` →
`RawReadFinder::read_receivers`; `leading_ident` split into `strip_derefs` +
`ident_prefix` with `leading_ident` as their composition. The three pre-existing tests
whose killing mutations named the old symbols had their doc comments updated and their
mutations re-run against the new code (below).

---

## 2. Tests

Six added, one per requirement in the findings file, in the file's own order. Every
mutation below was **applied to the source and run**; the file was restored from a
byte-for-byte copy after each and `cmp`-verified at the end.

| # | test | mutation applied | result |
|---|---|---|---|
| 1 | `a_pda_address_check_silences_the_read_it_proves` | `PDA_DERIVATIONS` emptied | FAILED (only it) |
| 2 | `a_pda_address_check_does_not_silence_a_different_account` | `pda_address_check_covers` reduced to `evidence.derives` | FAILED (only it) |
| 3 | `a_comparison_without_a_derivation_does_not_silence` | `evidence.derives &&` dropped | FAILED (only it) |
| 4 | `an_anchor_seeds_constraint_silences_the_read_of_that_field` | `Constraint::Seeds(_)` arm of `proves_address` deleted | FAILED (only it) |
| 5 | `an_anchor_address_constraint_silences_the_read_of_that_field` | `Constraint::Other(key, _)` arm deleted | FAILED (only it) |
| 6 | `an_anchor_constraint_on_another_field_does_not_silence` | `.filter(name == field)` dropped from `is_address_constrained` | FAILED (only it) |

Re-run against the rewritten code, because the symbols they name changed:

| test | mutation applied | result |
|---|---|---|
| `the_let_hop_ignores_locals_that_do_not_hold_account_data` | `raw_read_prefix` guard in `raw_read_locals` replaced by `unwrap_or(&binding.init)` | FAILED (only it) |
| `flags_a_read_through_an_intermediate_local` | `raw_read_locals` branch of `read_receivers` deleted | FAILED (also the nested-block test) |
| `flags_an_intermediate_local_inside_a_nested_block` | `syn::Expr::If` arm of `collect_let_bindings_expr` deleted | FAILED (only it) |

`cargo fmt --check` clean, `cargo clippy --all-targets -- -D warnings` clean,
`cargo test` green: **163 lib + 4 integration, 0 failed**. `tests/examples.rs` needed
**no change** — neither silencer touches `examples/`, which was verified by the
integration tests passing untouched rather than by editing them.

---

## 3. Measurement

Same twelve trees, same script, release build before and after.

| tree | VL002 before | VL002 after |
|---|---|---|
| /tmp/anchor-check | 2 | 2 |
| /tmp/vl-wide/program-examples | 10 | 8 |
| /tmp/vl-wide/metaplex-program-library | 12 | 8 |
| /tmp/vl-wide/mango-v4 | 1 | 1 |
| /tmp/vl-wide/helium-program-library | 3 | 1 |
| /tmp/vl-wide/jito-programs | 0 | 0 |
| /tmp/vl-wide/v4 | 3 | 0 |
| /tmp/vl-real/protocol-v2 | 5 | 4 |
| /tmp/vl-real/marginfi-v2 | 8 | 8 |
| /tmp/vl-real/openbook-v2 | 0 | 0 |
| /tmp/vl-real/squads-mpl | 0 | 0 |
| /tmp/vl-real/liquid-staking-program | 0 | 0 |
| **total** | **44** | **32** |

VL001 4 → 4, VL003 579 → 579, VL004 66 → 66, VL005 21 → 21. No finding appeared that was
not there before (the diff's "new" set is empty).

**Expected 30, got 32.** Twelve silenced, not fourteen — and the twelve are not the
fourteen predicted. Exactly:

*Silenced as predicted (11):* 11 (drift pyth_lazer, C), 16 + 17 (helium
`set_entity_active_v0`, B), 23 (metaplex `set_collection.rs:112`, C), 26 + 27 (metaplex
`init_selling_resource`, B), 35 (favorites `get_pda`, B), 38 (escrow `take_offer`, B —
the accepted miss), 42 + 43 + 44 (squads, C).

*Silenced and should not have been (1):* **24 — metaplex
`candy-machine/…/set_collection_during_mint.rs:116`, which I classified A.** Cause below.

*Not silenced, though class B (3):*

* **29 — `hydra/program/src/utils/mod.rs:77`.** The proof is
  `assert_derivation(&crate::ID, &account_info, …)`, but the read is of
  `fanout_for_mint` and the derivation names `account_info`, a local bound to
  `fanout_for_mint.to_account_info()`. Condition 2 compares identifiers and does not
  follow that hop, and `whole_word_match` correctly refuses the near-misses `fanout`,
  `fanout_mint` and `fanout_for_mint_object` that also appear in the body. The rule
  behaved exactly as written; the specified proof set is simply narrower than this
  file's proof.
* **40 + 41 — `program-examples/tools/shank-and-solita/…/{pick_up_car,return_car}.rs:37`.**
  Both prove the address with
  `assert!(&rental_order_account_pda == rental_order_account.key);`. Plain `assert!` is
  not in `OWNER_CHECK_MACROS` (the list is `require_keys_eq`, `require_keys_neq`,
  `require_eq`, `require_neq`, `require`, `assert_eq`, `assert_ne`), and the `==` lives
  inside macro tokens, which `syn` never parses as an expression, so
  `visit_expr_binary` cannot see it either. Adding `assert` would close this, and it is
  a one-word change — but the findings file gave that constant verbatim and told me not
  to tune, so I have not touched it.

---

## 4. The A-class finding that disappeared — reported, not adjusted

**Finding 24: `metaplex-program-library/candy-machine/program/src/processor/collection/set_collection_during_mint.rs:116`,
`Metadata::deserialize(&mut data.as_ref())?`.** Classified A in round 0 and I still
believe A is right: the account read is `collection_metadata`, declared
`collection_metadata: UncheckedAccount<'info>` with **no** constraints, and the only
owner check in the function (`cmp_pubkeys(ctx.accounts.metadata.owner, …)`, line 60)
covers a *different* account.

It was silenced by S3, and here is precisely why. The findings file defines the receiver
identifier as "**the leading identifier** of the raw-read expression, after `*`/`&`/`&mut`
stripping", with two bare examples (`favorite_account`, `offer_info`). For an Anchor
receiver the leading identifier is `ctx`. So condition 2 asks whether `ctx` appears as a
whole identifier in some comparison — and this body contains
`ctx.accounts.metadata.data_len() == 0`. It matches. Condition 1 holds because the file
calls `assert_derivation` further down. Silenced.

This is the same mechanism that silenced helium 16/17 and metaplex 23: for every
`ctx.accounts.X` receiver in the corpus, condition 2 degenerates to "the body contains
any comparison mentioning `ctx`", which is nearly always true. It happened to give the
right answer four times and the wrong answer once. It is not tying the proof to the
account, which is the exact failure condition 2 exists to prevent.

The one-line remedy, which I have **not** applied: take the receiver's **trailing** path
segment instead of its leading identifier — `collection_metadata` rather than `ctx`. I
checked it against every affected file by hand: helium (`info`), metaplex
`init_selling_resource` (`metadata`, `master_edition_info`), favorites
(`favorite_account`) and escrow (`offer_info`) all still match, because the proofs name
those accounts; `set_collection_during_mint` stops matching, because nothing compares
`collection_metadata`. `whole_word_match` already handles the dotted boundary. The
controller asked to be told and to have me stop rather than adjust, so the decision is
yours.

Note that the failure direction here is a **false negative on the tool's only
High-severity rule**, which is the direction that matters least for CI breakage but most
for the tool's claim to find things.

---

## 5. Re-classification of the 32 survivors

Against the classes established in round 0. Totals move from A 17 / B 9 / C 5 / D 8 / E 5
to **A 16 / B 3 / C 0 / D 8 / E 5**.

* **Class C: 0 of 5 survive.** All five silenced. S4 did exactly its job.
* **Class B: 3 of 9 survive** — 29, 40, 41, for the two reasons in §3. Every other B is
  gone.
* **Class A: 16 of 17 survive.** All sixteen classifications still hold; I re-read the
  diff line by line and none of them changed shape. The seventeenth is finding 24, §4.
* **Class D: 8 of 8 survive** — the fuzz harnesses (marginfi `fuzz/src/bank_accounts.rs`
  ×3, `fuzz/src/lib.rs` ×3), the `#[cfg(test)]` module in anchor-check
  `migration.rs:916`, and the off-chain CLI `p0-cli/…/oracle.rs:66`. Untouched, as
  directed — the fix is tool-wide file selection and belongs in its own task with its own
  full re-measurement.
* **Class E: 5 of 5 survive** — marginfi `price.rs:1525`, drift `oracle.rs:419` and `:454`,
  drift `perp_market.rs:1679` and `:1692`. These are helpers taking `&AccountInfo` whose
  callers validate; interprocedural and out of reach of a single-function rule, and this
  is the shape Metaplex has historically been exploited through, so they stay reported.

No class D or E finding moved, which is the reassuring half of the result: neither
silencer reached into the two classes that were explicitly out of scope.

---

## 6. Concerns

1. **The `ctx` leading-identifier degeneracy — §4.** One class-A finding lost. This is
   the concern; everything else on this list is smaller. The remedy is one line and I am
   holding it pending your decision.
2. **32, not 30.** Three class-B findings survive: one needs `assert` in
   `OWNER_CHECK_MACROS` (one word, deliberately not added), one needs condition 2 to
   follow a `to_account_info()` hop (not one word, and not obviously worth it). Both are
   false *positives* that remain, i.e. the safe direction, and both have their source
   quoted above.
3. **Alias resolution is position-blind.** A name bound twice contributes both bindings
   as receiver candidates and any of them can silence. The `is_alias` no-`(` guard keeps
   the worst case out (a value re-binding cannot be expanded), and VL002 deliberately
   carries no `Pos`, but this is a place where a future false silence could hide. It is
   documented at `receivers_of`.
4. **`&mut data` normalisation** — carried over from round 0 unchanged, as directed: a
   local genuinely named `mutable` would be read as `able` and its read missed. False
   negative, safe direction, does not occur in the corpus, documented at `strip_derefs`.
5. **Ordering is not checked**, by design. `take_offer.rs:49` is the named example and it
   is now silent. If a body ever checks an address only on a path the read cannot reach,
   this rule will not notice.
