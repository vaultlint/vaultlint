use proc_macro2::{TokenStream, TokenTree};

/// One `key` or `key = value` item inside `#[account(...)]` or `#[derive(...)]`.
/// Values are normalised token text with all whitespace removed, so
/// `vault . bump` becomes `vault.bump` and comparisons in rules stay simple.
pub struct MetaItem {
    pub key: String,
    pub value: Option<String>,
}

pub fn parse_meta_list(tokens: TokenStream) -> Vec<MetaItem> {
    split_top_level_commas(tokens)
        .into_iter()
        .filter_map(parse_item)
        .collect()
}

pub fn has_derive(attrs: &[syn::Attribute], name: &str) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("derive")
            && matches!(&attr.meta, syn::Meta::List(list)
                if parse_meta_list(list.tokens.clone()).iter().any(|item| item.key == name))
    })
}

fn split_top_level_commas(tokens: TokenStream) -> Vec<Vec<TokenTree>> {
    let mut chunks = Vec::new();
    let mut current: Vec<TokenTree> = Vec::new();
    for token in tokens {
        match &token {
            TokenTree::Punct(punct) if punct.as_char() == ',' => {
                if !current.is_empty() {
                    chunks.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(token),
        }
    }
    if !current.is_empty() {
        chunks.push(current);
    }
    chunks
}

fn parse_item(chunk: Vec<TokenTree>) -> Option<MetaItem> {
    if chunk.is_empty() {
        return None;
    }
    let equals = chunk
        .iter()
        .position(|token| matches!(token, TokenTree::Punct(p) if p.as_char() == '='));
    match equals {
        Some(index) => Some(MetaItem {
            key: render(&chunk[..index]),
            value: Some(render(&chunk[index + 1..])),
        }),
        None => Some(MetaItem {
            key: render(&chunk),
            value: None,
        }),
    }
}

fn render(tokens: &[TokenTree]) -> String {
    tokens
        .iter()
        .map(TokenTree::to_string)
        .collect::<String>()
        .replace(char::is_whitespace, "")
}

#[cfg(test)]
mod tests {
    use super::*;
    use quote::quote;

    fn keys(tokens: proc_macro2::TokenStream) -> Vec<(String, Option<String>)> {
        parse_meta_list(tokens)
            .into_iter()
            .map(|item| (item.key, item.value))
            .collect()
    }

    #[test]
    fn splits_constraints_including_the_mut_keyword() {
        let parsed = keys(quote!(mut, seeds = [b"vault", user.key().as_ref()], bump));

        assert_eq!(parsed[0], ("mut".to_string(), None));
        assert_eq!(parsed[1].0, "seeds");
        assert!(parsed[1].1.as_ref().unwrap().contains("vault"));
        assert_eq!(parsed[2], ("bump".to_string(), None));
    }

    #[test]
    fn keeps_the_value_of_a_stored_bump_and_a_namespaced_key() {
        let parsed = keys(quote!(bump = vault.bump, token::mint = mint));

        assert_eq!(
            parsed[0],
            ("bump".to_string(), Some("vault.bump".to_string()))
        );
        assert_eq!(parsed[1].0, "token::mint");
    }

    #[test]
    fn splits_on_the_first_equals_only() {
        let parsed = keys(quote!(constraint = vault.owner == user.key()));

        assert_eq!(parsed[0].0, "constraint");
        assert_eq!(parsed[0].1.as_deref(), Some("vault.owner==user.key()"));
    }
}
