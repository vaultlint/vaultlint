pub(crate) mod attr;

use proc_macro2::Span;
use syn::spanned::Spanned;

#[derive(Debug)]
pub struct AnchorModel {
    pub accounts_structs: Vec<AccountsStruct>,
}

#[derive(Debug)]
pub struct AccountsStruct {
    pub name: String,
    /// Argument names declared in `#[instruction(name: Type, …)]` on the struct.
    pub instruction_args: Vec<String>,
    pub fields: Vec<AccountField>,
}

#[derive(Debug)]
pub struct AccountField {
    pub name: String,
    pub ty: AccountTy,
    pub constraints: Vec<Constraint>,
    pub(crate) span: Span,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountTy {
    Signer,
    Account(String),
    AccountInfo,
    UncheckedAccount,
    Program,
    SystemAccount,
    Sysvar,
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Constraint {
    Init,
    Mut,
    Seeds(String),
    /// `None` is a bare `bump`; `Some(text)` is `bump = <text>`.
    Bump(Option<String>),
    HasOne(String),
    Custom(String),
    /// An unrecognised key, e.g. `signer`, `address`, `mint::authority`.
    /// Carries (key, value) where value is empty for bare keys.
    Other(String, String),
}

pub fn build(file: &syn::File) -> AnchorModel {
    let mut accounts_structs = Vec::new();
    collect(&file.items, &mut accounts_structs);
    AnchorModel { accounts_structs }
}

fn collect(items: &[syn::Item], out: &mut Vec<AccountsStruct>) {
    for item in items {
        match item {
            syn::Item::Mod(module) => {
                if let Some((_, inner)) = &module.content {
                    collect(inner, out);
                }
            }
            syn::Item::Struct(item) if attr::has_derive(&item.attrs, "Accounts") => {
                out.push(AccountsStruct {
                    name: item.ident.to_string(),
                    instruction_args: instruction_arg_names(&item.attrs),
                    fields: item.fields.iter().map(account_field).collect(),
                });
            }
            _ => {}
        }
    }
}

fn account_field(field: &syn::Field) -> AccountField {
    let span = field
        .ident
        .as_ref()
        .map_or_else(|| field.ty.span(), syn::Ident::span);
    AccountField {
        name: field
            .ident
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_default(),
        ty: account_ty(&field.ty),
        constraints: constraints(&field.attrs),
        span,
    }
}

/// Parse `#[instruction(name: Type, name2: Type2, …)]` and return the argument names.
///
/// Only the argument *names* (the part before the colon) are captured; types are
/// discarded.  If the attribute is absent or malformed the result is an empty vec.
fn instruction_arg_names(attrs: &[syn::Attribute]) -> Vec<String> {
    for attr in attrs {
        if !attr.path().is_ident("instruction") {
            continue;
        }
        let syn::Meta::List(list) = &attr.meta else {
            continue;
        };
        // Parse as a punctuated sequence of `FnArg` (or `PatType`).
        // We use a simpler token-level approach so we don't depend on function
        // syntax: collect everything before the first `:` in each comma-separated
        // chunk — that is the argument name.
        return collect_instruction_arg_names(list.tokens.clone());
    }
    Vec::new()
}

fn collect_instruction_arg_names(tokens: proc_macro2::TokenStream) -> Vec<String> {
    use proc_macro2::TokenTree;
    // In proc_macro2, `Group` wraps an entire balanced delimiter pair as a
    // single token, so top-level commas are always bare `Punct(',')` tokens.
    // We do not need depth tracking here.
    let mut names = Vec::new();
    let mut current: Vec<TokenTree> = Vec::new();

    for tt in tokens {
        match &tt {
            TokenTree::Punct(p) if p.as_char() == ',' => {
                if let Some(name) = arg_name_from_chunk(&current) {
                    names.push(name);
                }
                current.clear();
            }
            _ => current.push(tt),
        }
    }
    if let Some(name) = arg_name_from_chunk(&current) {
        names.push(name);
    }
    names
}

/// Given the token trees for one comma-separated chunk (`name: Type`), return
/// the name portion (everything before the first `:` that is a `Punct`).
fn arg_name_from_chunk(chunk: &[proc_macro2::TokenTree]) -> Option<String> {
    use proc_macro2::TokenTree;
    let colon_pos = chunk
        .iter()
        .position(|tt| matches!(tt, TokenTree::Punct(p) if p.as_char() == ':'));
    let name_tokens = &chunk[..colon_pos.unwrap_or(chunk.len())];
    let name: String = name_tokens
        .iter()
        .map(|tt| tt.to_string())
        .collect::<String>()
        .trim()
        .to_string();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

fn constraints(attrs: &[syn::Attribute]) -> Vec<Constraint> {
    attrs
        .iter()
        .filter(|attr| attr.path().is_ident("account"))
        .filter_map(|attr| match &attr.meta {
            syn::Meta::List(list) => Some(attr::parse_meta_list(list.tokens.clone())),
            _ => None,
        })
        .flatten()
        .map(to_constraint)
        .collect()
}

fn to_constraint(item: attr::MetaItem) -> Constraint {
    let value = item.value.unwrap_or_default();

    // Anchor's legacy syntax `#[account("<expr>")]` is the ancestor of today's
    // `#[account(constraint = <expr>)]`.  A bare string literal parses into the
    // key slot with no value, so recognise it here and normalise it to `Custom`;
    // otherwise the expression — and every field name it references — is lost.
    if value.is_empty()
        && item.key.len() >= 2
        && item.key.starts_with('"')
        && item.key.ends_with('"')
    {
        return Constraint::Custom(item.key[1..item.key.len() - 1].to_string());
    }

    match item.key.as_str() {
        "init" | "init_if_needed" => Constraint::Init,
        "mut" => Constraint::Mut,
        "seeds" => Constraint::Seeds(value),
        "bump" => Constraint::Bump(if value.is_empty() { None } else { Some(value) }),
        "has_one" => Constraint::HasOne(value),
        "constraint" => Constraint::Custom(value),
        other => Constraint::Other(other.to_string(), value),
    }
}

pub(crate) fn account_ty(ty: &syn::Type) -> AccountTy {
    let syn::Type::Path(path) = ty else {
        return AccountTy::Other(String::new());
    };
    let Some(segment) = path.path.segments.last() else {
        return AccountTy::Other(String::new());
    };
    let name = segment.ident.to_string();
    if name == "Box" {
        if let Some(inner) = first_type_argument(segment) {
            return account_ty(inner);
        }
    }
    match name.as_str() {
        "Signer" => AccountTy::Signer,
        "AccountInfo" => AccountTy::AccountInfo,
        "UncheckedAccount" => AccountTy::UncheckedAccount,
        "Program" => AccountTy::Program,
        "SystemAccount" => AccountTy::SystemAccount,
        "Sysvar" => AccountTy::Sysvar,
        "Account" | "InterfaceAccount" => AccountTy::Account(inner_account_name(segment)),
        other => AccountTy::Other(other.to_string()),
    }
}

fn first_type_argument(segment: &syn::PathSegment) -> Option<&syn::Type> {
    let syn::PathArguments::AngleBracketed(args) = &segment.arguments else {
        return None;
    };
    args.args.iter().find_map(|arg| match arg {
        syn::GenericArgument::Type(ty) => Some(ty),
        _ => None,
    })
}

/// `Account<'info, Vault>` -> `"Vault"`. The lifetime is skipped by
/// `first_type_argument`, which only matches type arguments.
fn inner_account_name(segment: &syn::PathSegment) -> String {
    match first_type_argument(segment) {
        Some(syn::Type::Path(path)) => path
            .path
            .segments
            .last()
            .map(|s| s.ident.to_string())
            .unwrap_or_default(),
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn model(source: &str) -> AnchorModel {
        build(&syn::parse_file(source).unwrap())
    }

    const WITHDRAW: &str = r#"
        #[derive(Accounts)]
        pub struct Withdraw<'info> {
            #[account(mut, seeds = [b"vault"], bump = vault.bump)]
            pub vault: Account<'info, Vault>,
            /// CHECK: not validated
            pub authority: AccountInfo<'info>,
            pub payer: Signer<'info>,
            pub config: Box<Account<'info, Config>>,
        }

        pub struct NotAnAccountsStruct {
            pub whatever: AccountInfo<'info>,
        }
    "#;

    #[test]
    fn collects_only_accounts_structs() {
        let model = model(WITHDRAW);

        assert_eq!(model.accounts_structs.len(), 1);
        assert_eq!(model.accounts_structs[0].name, "Withdraw");
        assert_eq!(model.accounts_structs[0].fields.len(), 4);
    }

    #[test]
    fn recognises_field_types_including_boxed_accounts() {
        let model = model(WITHDRAW);
        let fields = &model.accounts_structs[0].fields;

        assert_eq!(fields[0].ty, AccountTy::Account("Vault".to_string()));
        assert_eq!(fields[1].ty, AccountTy::AccountInfo);
        assert_eq!(fields[2].ty, AccountTy::Signer);
        assert_eq!(fields[3].ty, AccountTy::Account("Config".to_string()));
    }

    #[test]
    fn parses_constraints_and_distinguishes_stored_bump() {
        let model = model(WITHDRAW);
        let vault = &model.accounts_structs[0].fields[0];

        assert!(vault.constraints.contains(&Constraint::Mut));
        assert!(vault
            .constraints
            .iter()
            .any(|c| matches!(c, Constraint::Seeds(_))));
        assert!(vault
            .constraints
            .contains(&Constraint::Bump(Some("vault.bump".to_string()))));
    }

    #[test]
    fn finds_accounts_structs_nested_in_modules() {
        let model = model(
            r#"
            pub mod instructions {
                #[derive(Accounts)]
                pub struct Inner<'info> {
                    pub admin: AccountInfo<'info>,
                }
            }
        "#,
        );

        assert_eq!(model.accounts_structs.len(), 1);
        assert_eq!(model.accounts_structs[0].name, "Inner");
    }

    #[test]
    fn records_the_line_of_each_field() {
        let model = model(
            "#[derive(Accounts)]\npub struct A<'info> {\n    pub admin: AccountInfo<'info>,\n}\n",
        );

        assert_eq!(model.accounts_structs[0].fields[0].span.start().line, 3);
    }

    #[test]
    fn parses_legacy_string_constraint_as_custom() {
        // Anchor's legacy syntax `#[account("<expr>")]` is exactly today's
        // `#[account(constraint = <expr>)]`. The bare string literal lands in the
        // *key* slot with no value, so it must be recognised explicitly.
        let model = model(
            r#"
            #[derive(Accounts)]
            pub struct CreateMember<'info> {
                #[account("&balances.spt.owner == member_signer.key")]
                pub balances: BalanceSandboxAccounts<'info>,
                pub member_signer: AccountInfo<'info>,
            }
        "#,
        );

        let balances = &model.accounts_structs[0].fields[0];
        assert_eq!(
            balances.constraints,
            vec![Constraint::Custom(
                "&balances.spt.owner==member_signer.key".to_string()
            )]
        );
    }

    #[test]
    fn parses_instruction_arg_names() {
        let model = model(
            r#"
            #[derive(Accounts)]
            #[instruction(user_bump: u8, amount: u64)]
            pub struct Deposit<'info> {
                pub vault: Account<'info, Vault>,
            }
        "#,
        );

        let args = &model.accounts_structs[0].instruction_args;
        assert_eq!(args, &["user_bump", "amount"]);
    }

    #[test]
    fn instruction_args_empty_when_no_instruction_attr() {
        let model = model(
            r#"
            #[derive(Accounts)]
            pub struct Deposit<'info> {
                pub vault: Account<'info, Vault>,
            }
        "#,
        );

        assert!(model.accounts_structs[0].instruction_args.is_empty());
    }
}
