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

---

# Fix round 1 — T5, S4 and the forwarding hop widened together

Status: **DONE**. The T5 mismatch above is resolved. The decision was taken: T5 now also
accepts the bare field name, and — the part that mattered — S4 and the forwarding hop were
widened in the *same* change, so the two searches still see the same set of spellings.

## What changed

`src/rules/init_authority.rs` only. One new concept, `LinkedBody::spellings(field)`,
returning the two ways this struct's field can be named in a linked body:

- the fully qualified `<binding>.accounts.<F>` / `self.<F>`;
- the bare `<F>` a handler gets from binding the field to a local first.

`LinkedBody::reads_field(field, member)` runs `reads` over both. Three call sites now go
through it:

| Site | Before | After |
|---|---|---|
| **T5** | `reads(text, base(F), "key()")` | `body.reads_field(F, "key()")` |
| **S4 direct** | `reads(text, base(F), "is_signer")` | `body.reads_field(F, "is_signer")` |
| **forwarding** | 4 spellings off `base(F)` | 8 — the same 4 off each of `spellings(F)` |

The forwarding list therefore gained `authority`, `&authority`,
`authority.to_account_info()` and `&authority.to_account_info()`, so the one-hop
`get_fee_payer` suppression still fires when the handler aliases or destructures first.

The whole-identifier boundary in `contains_access` is untouched and still applies to the
bare spelling: a match preceded by `.` or `:` does not count, so `vault.authority.key()`
does not satisfy T5. There is a test for that.

**Why the looseness is acceptable, recorded on `spellings` in the source:** T5 is a "was
the field actually used" filter, not the discriminator. The narrowness lives in T1–T4 — a
raw `AccountInfo`/`UncheckedAccount`, authority-named, in a struct with an `init` field,
whose name is a whole identifier in that `init` field's `seeds`. Very little reaches T5.
And where the same looseness feeds S4 and the hop, it errs towards *silencing* findings on
code that does check, which is the safe direction.

T3 also gained a one-line comment recording that T4 subsumes it (T4 looks the field up
among the very `init` fields T3 counts, so it cannot succeed on an empty list). It is kept
as a cheap early-out; its redundancy is deliberate and deleting it changes no result. This
is written down so a later reader does not read the redundancy as a bug.

## Tests added

Six, in a new "the field bound to a local first" section. Each trigger case is paired with
its suppression case, because either alone would pass with the asymmetry still present.

| Test | Expect |
|---|---|
| `a_destructured_binding_is_still_a_read_of_the_field` — the marginfi shape, `let MarginfiAccountInitializePda { authority, .. } = ctx.accounts;` then `authority.key()` | **1** |
| `an_is_signer_check_on_a_destructured_binding_silences_the_finding` | 0 |
| `an_aliased_local_is_still_a_read_of_the_field` — metaplex's `let authority = &ctx.accounts.authority;` | **1** |
| `an_is_signer_check_on_an_aliased_local_silences_the_finding` | 0 |
| `an_is_signer_check_one_call_away_from_an_aliased_local_silences_the_finding` — `get_fee_payer(authority, …)` on the alias | 0 |
| `a_field_access_in_the_handler_does_not_satisfy_t5` — the handler only reads `…marginfi_group.vault.authority.key()` | 0 |

`cargo test`: **111 passed, 0 failed** (107 lib + 4 integration), up from 105.
`cargo fmt --check` clean; `cargo clippy --all-targets -- -D warnings` clean.

### Mutations proving the new tests can fail

Each mutation was applied to the shipped source, `cargo test --lib init_authority` run,
and the source restored byte-for-byte from a backup.

| Mutation | Result |
|---|---|
| **S4 asymmetry.** `body.reads_field(field, "is_signer")` → `reads(&body.text, &body.base(field), "is_signer")` in `establishes_signer` — i.e. T5 widened, S4 left narrow, which is exactly the trap | **2 failed**, and precisely the two symmetry suppressions: `an_is_signer_check_on_an_aliased_local_silences_the_finding`, `an_is_signer_check_on_a_destructured_binding_silences_the_finding`. Both trigger tests still passed, so the pair isolates the asymmetry and nothing else. |
| **T5 narrowed back.** `body.reads_field(&field.name, "key()")` → `reads(&body.text, &body.base(&field.name), "key()")` | **2 failed**: `a_destructured_binding_is_still_a_read_of_the_field`, `an_aliased_local_is_still_a_read_of_the_field`. This is the committed rule's behaviour, and it is the proof that it was silent on its own motivating bug. |
| **Forwarding narrowed.** `for base in body.spellings(field)` → `for base in [body.base(field)]` in `forwarded_arguments` | **1 failed**: `an_is_signer_check_one_call_away_from_an_aliased_local_silences_the_finding`. |

The first two mutations are inverses of each other and fail disjoint sets of tests, which
is the point: neither the trigger tests nor the suppression tests alone would have caught
the asymmetry.

## Corpus measurement

Release build, `vaultlint scan <repo> --format json --fail-on never`. Every repo listed was
present; nothing was substituted.

| Codebase | VL001 | previous round | file:line |
|---|---|---|---|
| `/tmp/vl-real/liquid-staking-program` | 0 | 0 | — |
| `/tmp/vl-real/marginfi-v2` (HEAD `1f1f7a6`) | 0 | 0 | — |
| `/tmp/vl-real/openbook-v2` | 0 | 0 | — |
| `/tmp/vl-real/protocol-v2` (drift) | 2 | 2 | `programs/drift/src/instructions/user.rs:4530`, `:5225` |
| `/tmp/vl-real/squads-mpl` | 0 | 0 | — |
| `/tmp/anchor-check` | **1** | 0 | `tests/auction-house/programs/auction-house/src/lib.rs:1098` |
| `/tmp/vl-marginfi-prefix` (marginfi @ `95a4c26^`) | **1** | *not measured* | `programs/marginfi/src/instructions/marginfi_account/initialize.rs:114` |

This reproduces the brief's table exactly and matches the prediction the previous round
measured: **one** new finding, in `anchor-check`, and **zero** new findings anywhere else.
The two drift findings are unchanged and are the same pair as before
(`InitializeSignedMsgUserOrders.authority`, `InitializeRevenueShare.authority`).

`/tmp/anchor-check` line 1098 is `authority: AccountInfo<'info>` in
`pub struct CreateAuctionHouse<'info>` (declared at line 1094) — the finding the brief
named, now present.

### The marginfi before/after pair

This is the evidence the rule exists for, so it is spelled out in full.

No pre-fix worktree existed, so one was created and left in place for later tasks:

```
cd /tmp/vl-real/marginfi-v2 && git worktree add /tmp/vl-marginfi-prefix 95a4c26^
# → detached HEAD 40e16b7 "Asgard cpi key"
```

| Tree | VL001 |
|---|---|
| `/tmp/vl-marginfi-prefix` — `95a4c26^` (`40e16b7`), pre-fix | **1** — `programs/marginfi/src/instructions/marginfi_account/initialize.rs:114`, `pub authority: UncheckedAccount<'info>,` |
| `/tmp/vl-real/marginfi-v2` — HEAD `1f1f7a6`, post-fix | **0** |

Line 114 in the pre-fix tree is exactly the line the fix commit changed. `git show 95a4c26`
touches one file, three insertions and three deletions, and the authority hunk is verbatim:

```
-    pub authority: UncheckedAccount<'info>,
+    pub authority: Signer<'info>,
```

The handler at line 61 of that file destructures —

```rust
let MarginfiAccountInitializePda { authority, marginfi_group, marginfi_account: marginfi_account_loader, .. } = ctx.accounts;
…
marginfi_account.initialize(marginfi_group.key(), authority.key());
```

— which is precisely the shape the committed rule could not see, and is now covered both
by the corpus run and by `a_destructured_binding_is_still_a_read_of_the_field`.

The rule fires on the vulnerable commit, on the exact line the developers fixed, and is
silent on the fixed commit. Nothing was tuned to produce this: the widening was specified
before the pre-fix tree was ever scanned, and the only knob touched was the spelling set.

## Concerns

None blocking. Two things worth knowing:

- **The bare spelling can alias an unrelated local.** A handler with an unrelated
  `let owner = …` would satisfy T5 for a field named `owner`. That is the accepted cost,
  and it is bounded: T1–T4 must all hold first, and on this corpus the widening produced
  exactly one additional finding — the intended one. Not worth chasing with dataflow.
- The `/tmp/vl-marginfi-prefix` worktree is left registered against `/tmp/vl-real/marginfi-v2`.
  If a later task wants the tree clean, `git worktree remove /tmp/vl-marginfi-prefix`.

---

# Fix round 2 — the struct-literal idiom, UTF-8 safety, four untested spec branches

Status: **DONE**. Four review findings addressed; corpus unchanged at the stated baseline.

## Critical 1 — `contains_access` was blind to `set_inner(T { authority: … })`

`contains_access` rejected a match whose left neighbour was `:`. That rule is right for
*attribute* text, where a lone `:` cannot occur and so is always half of a `::`. It is
wrong for *handler body* text, where `:` is also the struct-literal field separator and
`body_text` glues tokens together:

```
ctx.accounts.record.set_inner(Record { authority: ctx.accounts.authority.key() })
→ …set_inner(Record{authority:ctx.accounts.authority.key()})
```

The sole occurrence of the needle was `:`-prefixed, so T5 failed and the whole idiom —
one of the two canonical ways an Anchor handler writes a designated authority into
freshly `init`ed state — was silently missed. (The bare spelling did not rescue it: the
`authority.key()` inside `ctx.accounts.authority.key()` is `.`-prefixed and correctly
rejected.)

**Choice made: shared *walk*, separate *boundaries*.** The reviewer offered a shared
predicate or two functions; neither on its own was right. The bug that mattered was in the
boundary rule, which genuinely differs between the two texts, while the defect in
Important 2 was in the walk, which is identical in both and is the delicate part. So:

- new `find_bounded(text, needle, left, right)` owns the walk and is shared;
- `name_in_seeds` and `contains_access` each keep their own boundary predicates, with
  `no_identifier_or_member_before` (the identifier / `.` rules, which really are common)
  factored out and the `:` rules stated separately in each, each with the reason.

`name_in_seeds` behaviour is byte-for-byte unchanged: it still rejects both a left `:` and
a right `:`. `contains_access` now rejects only `::` on the left (`left` ends in `:` whose
own left neighbour is `:`), and accepts a lone `:`.

`a_longer_receiver_is_not_the_account_we_are_tracking` still passes — the `.` left boundary
is untouched.

## Important 2 — panic on user-supplied source

Both scanners resumed a failed match at `at + 1` and then sliced. Rust identifiers may hold
any XID character (`pub émetteur_authority: UncheckedAccount<'info>` is legal), so a
`.`-prefixed first match of `émetteur_authority` left `start` inside the `é` and the next
slice panicked. Nothing in `src/` catches unwinds, so one exotic file aborted the entire
scan.

`find_bounded` resumes at `at + needle.len()`, which is always a char boundary (it is the
end of a `str::find` match) and is provably equivalent: a later match starting inside this
one has a needle character to its left, and every needle used here begins with an
identifier character, so it would fail `left` anyway. The reasoning is recorded on the
function.

Also fixed there: `haystack.as_bytes()[at - 1] as char` read one byte and cast it, so the
`é` of `caféauthority` was seen as `©` — not an identifier character — and the match was
wrongly accepted as a reference to a field named `authority`. Both predicates now take the
surrounding `&str` and use `chars().next_back()` / `chars().next()`.

## Important 3 — four spec branches now pinned

Added, all expecting zero findings: `own_seeds_silence_the_finding` (S1 `Seeds`),
`an_own_signer_constraint_silences_the_finding` (S1 `signer`),
`an_own_address_constraint_silences_the_finding` (S1 `address`), and
`a_namespaced_constraint_on_a_settled_sibling_silences_the_finding` (S2's
`Constraint::Other(key, value)` arm, `token::authority = authority` on a non-`init`
sibling).

## Minor 4 — the comment on `spellings`

Reworded. It previously said the looseness "errs towards silence … the direction we want".
It now states the trade in both directions, names the false negative concretely
(`let authority = &ctx.accounts.other; require!(authority.is_signer)`), says plainly that a
false negative is the worse of the two in a security linter, and justifies accepting it on
the measurement (one changed finding across seven trees) rather than by calling it safe.

## Tests

`cargo test`: **120 passed, 0 failed** (116 lib + 4 integration), up from 111. Nine new
tests. `cargo fmt --check` clean; `cargo clippy --all-targets -- -D warnings` clean.

All four new-behaviour tests were written first and observed to fail for the right reason:
two boundary assertions failed, and `a_non_ascii_field_name_is_scanned_without_panicking`
failed with `byte index 8 is not a char boundary; it is inside 'é'`.

### The mutation that kills each new test

Each mutation was applied to the shipped source, `cargo test --lib init_authority` run, and
the source restored from a byte-identical backup (`diff` clean afterwards).

| Test | Mutation | Fails |
|---|---|---|
| `a_struct_literal_write_is_still_a_read_of_the_field` | `contains_access` left: `&& !left.strip_suffix(':').is_some_and(\|l\| l.ends_with(':'))` → `&& !left.ends_with(':')` | yes (with the `contains_access` unit test) |
| `an_is_signer_check_beside_a_struct_literal_write_silences_the_finding` | delete `if body.reads_field(field, "is_signer") { return true; }` from `establishes_signer` | yes (with the three round-1 direct-`is_signer` tests) |
| `a_struct_literal_separator_is_not_a_path_separator` | delete the same `::` clause entirely (accept `::` too) | yes |
| `own_seeds_silence_the_finding` | `Constraint::Seeds(_) \| Constraint::Custom(_) => true` → `Constraint::Custom(_) => true` | yes, alone |
| `an_own_signer_constraint_silences_the_finding` | `key == "signer" \|\| key == "address"` → `key == "address"` | yes, alone |
| `an_own_address_constraint_silences_the_finding` | `key == "signer" \|\| key == "address"` → `key == "signer"` | yes, alone |
| `a_namespaced_constraint_on_a_settled_sibling_silences_the_finding` | delete `Constraint::Other(key, value) => key.contains("::") && value == name,` from `bound_by_settled_sibling` | yes, alone |
| `a_non_ascii_field_name_is_scanned_without_panicking` | `start = end;` → `start = at + 1;` in `find_bounded` | yes, alone (panics) |
| `a_multi_byte_left_neighbour_still_continues_an_identifier` | `left.chars().next_back()` → `left.as_bytes().last().map(\|b\| *b as char)` | yes, alone |

**The Critical 1 pair is killed by disjoint mutations**, as required. Row 1's mutation
leaves the suppression test passing (with `:` rejected again, T5 fails, the struct still
reports nothing and zero is what that test expects); row 2's mutation leaves the trigger
test passing (S4 is irrelevant to it). Neither test alone proves the symmetry; together
they do.

## Corpus re-run

Release build, `vaultlint scan <repo> --format json --fail-on never`. Every tree listed was
present; nothing was substituted.

| Codebase | VL001 | baseline | file:line |
|---|---|---|---|
| `/tmp/vl-real/liquid-staking-program` | 0 | 0 | — |
| `/tmp/vl-real/marginfi-v2` (HEAD) | 0 | 0 | — |
| `/tmp/vl-real/openbook-v2` | 0 | 0 | — |
| `/tmp/vl-real/protocol-v2` (drift) | 2 | 2 | `programs/drift/src/instructions/user.rs:4530`, `:5225` |
| `/tmp/vl-real/squads-mpl` | 0 | 0 | — |
| `/tmp/anchor-check` | 1 | 1 | `tests/auction-house/programs/auction-house/src/lib.rs:1098` |
| `/tmp/vl-marginfi-prefix` (marginfi @ `95a4c26^`) | 1 | 1 | `programs/marginfi/src/instructions/marginfi_account/initialize.rs:114` |

**No new findings, and no lost ones.** Nothing was tuned to achieve that; the rule change
was written and its tests fixed before the corpus was scanned.

Why Critical 1 adds nothing here, checked rather than assumed: the struct-literal write
*does* occur in this corpus — `marginfi-v2/programs/mocks/src/instructions/pda_account_creation.rs:73`
is `authority: ctx.accounts.authority.key()` inside a struct literal, and drift's
`user.rs` has a dozen more. None of them reaches T5, because the field is disqualified
earlier: the marginfi mock declares `pub authority: Signer<'info>` (T1), and drift's are
inside events and non-`init` structs. So the fix is exercised against real code and changes
no verdict on it; the idiom it unblocks is simply not the spelling these particular
programs use for the vulnerable shape. The `/tmp/vl-marginfi-prefix` worktree is untouched
and still registered.

## Concerns

None blocking.

- Widening `contains_access` to accept a lone `:` also widens **S4** and the forwarding hop,
  which silence findings — a struct literal such as `Ctx { authority: x.is_signer }` now
  reads as a signer check. That is the same symmetry round 1 established deliberately, it
  is what the added inverse test pins, and it cost zero findings on the corpus.
- The two review items ruled out of scope are untouched: the bare-name aliasing risk (now
  honestly described in the `spellings` comment rather than defended) and
  `linked_findings_for_files` leaking its temp directory on a test panic.
