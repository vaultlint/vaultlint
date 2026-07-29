//! Asks a cluster what is actually deployed at the addresses a tree declares.
//!
//! Everything a linter reads is a statement of intent. This module reads the
//! one thing that is not: the account the program actually occupies, the loader
//! that owns it, and who may replace it. Nothing here runs unless the caller
//! asked for a cluster.
//!
//! Transport is deliberately thin — two `getMultipleAccounts` calls answer a
//! whole repository — and every decision about what an account *means* lives in
//! a pure function below, where it can be tested without a network.

use serde_json::{json, Value};

use crate::programid::{encode_base58, DeclaredId};

const UPGRADEABLE_LOADER: &str = "BPFLoaderUpgradeab1e11111111111111111111111";
const LOADER_V1: &str = "BPFLoader1111111111111111111111111111111111";
const LOADER_V2: &str = "BPFLoader2111111111111111111111111111111111";

/// The public mainnet endpoint. Rate-limited; `--rpc-url` exists because of it.
pub const MAINNET_BETA: &str = "https://api.mainnet-beta.solana.com";

/// Accounts per `getMultipleAccounts` call, which is the RPC's documented cap.
const BATCH: usize = 100;

/// What one declared address turned out to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deployment {
    pub declared: DeclaredId,
    pub state: State,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum State {
    /// No account at this address. The program was never deployed to this
    /// cluster, or lives on another one.
    Absent,
    /// An account exists but no loader owns it, so it is not a program here.
    NotAProgram { owner: String },
    /// A non-upgradeable loader owns it: the code at this address can never be
    /// replaced.
    Immutable,
    /// The upgradeable loader owns it and the upgrade authority was revoked.
    /// Equivalent to `Immutable` in effect, distinguished because it is a
    /// choice someone made rather than a property of the loader.
    Frozen { last_deploy_slot: u64 },
    /// The upgradeable loader owns it and someone can still replace the code.
    Upgradeable {
        authority: String,
        last_deploy_slot: u64,
    },
    /// The cluster could not be asked. Never conflated with `Absent`: not
    /// knowing and knowing there is nothing there are different answers.
    Unavailable { reason: String },
}

/// Looks up every declared id on the cluster at `rpc_url`.
///
/// Returns one `Deployment` per input, in input order. A transport failure
/// marks the ids it covered `Unavailable` rather than failing the scan — an
/// offline finding is still worth reporting when the network is not there.
pub fn resolve(ids: &[DeclaredId], rpc_url: &str) -> Vec<Deployment> {
    if ids.is_empty() {
        return Vec::new();
    }
    let client = Client::new(rpc_url);
    let mut out: Vec<Deployment> = Vec::with_capacity(ids.len());

    for chunk in ids.chunks(BATCH) {
        let addresses: Vec<&str> = chunk.iter().map(|id| id.address.as_str()).collect();
        match client.get_multiple_accounts(&addresses) {
            Err(reason) => out.extend(chunk.iter().cloned().map(|declared| Deployment {
                declared,
                state: State::Unavailable {
                    reason: reason.clone(),
                },
            })),
            Ok(values) => {
                for (declared, value) in chunk.iter().zip(values) {
                    out.push(Deployment {
                        declared: declared.clone(),
                        state: classify_program_account(value.as_ref()),
                    });
                }
            }
        }
    }

    resolve_program_data(&client, &mut out);
    out
}

/// Second pass: every program under the upgradeable loader carries a pointer to
/// a ProgramData account, and the authority and deploy slot live there.
fn resolve_program_data(client: &Client, deployments: &mut [Deployment]) {
    let pending: Vec<(usize, String)> = deployments
        .iter()
        .enumerate()
        .filter_map(|(index, deployment)| match &deployment.state {
            // The first pass parks the ProgramData address in `authority`; this
            // pass replaces it with the real one.
            State::Upgradeable { authority, .. } => Some((index, authority.clone())),
            _ => None,
        })
        .collect();

    for chunk in pending.chunks(BATCH) {
        let addresses: Vec<&str> = chunk.iter().map(|(_, address)| address.as_str()).collect();
        match client.get_multiple_accounts_sliced(&addresses, 45) {
            Err(reason) => {
                for (index, _) in chunk {
                    deployments[*index].state = State::Unavailable {
                        reason: reason.clone(),
                    };
                }
            }
            Ok(values) => {
                for ((index, address), value) in chunk.iter().zip(values) {
                    deployments[*index].state = classify_program_data(address, value.as_ref());
                }
            }
        }
    }
}

/// Reads the program account itself.
///
/// For the upgradeable loader the returned `Upgradeable.authority` is the
/// *ProgramData* address, not an authority — the caller must run the second
/// pass to replace it.
fn classify_program_account(value: Option<&Value>) -> State {
    let Some(account) = value.filter(|v| !v.is_null()) else {
        return State::Absent;
    };
    let owner = account.get("owner").and_then(Value::as_str).unwrap_or("");
    match owner {
        UPGRADEABLE_LOADER => {}
        LOADER_V1 | LOADER_V2 => return State::Immutable,
        other => {
            return State::NotAProgram {
                owner: other.to_string(),
            }
        }
    }

    // Program account layout: 4-byte little-endian enum tag, then the 32-byte
    // ProgramData address.
    let Some(data) = account_data(account) else {
        return State::Unavailable {
            reason: "program account data could not be decoded".to_string(),
        };
    };
    let Some(program_data) = data.get(4..36).and_then(|s| <[u8; 32]>::try_from(s).ok()) else {
        return State::Unavailable {
            reason: "program account is too short to hold a ProgramData address".to_string(),
        };
    };
    State::Upgradeable {
        authority: encode_base58(&program_data),
        last_deploy_slot: 0,
    }
}

/// Reads the ProgramData account: 4-byte enum tag, 8-byte slot, then an
/// `Option<Pubkey>` written as a 1-byte tag and 32 bytes.
fn classify_program_data(address: &str, value: Option<&Value>) -> State {
    let Some(account) = value.filter(|v| !v.is_null()) else {
        return State::Unavailable {
            reason: format!("ProgramData account {address} is missing"),
        };
    };
    let Some(data) = account_data(account) else {
        return State::Unavailable {
            reason: format!("ProgramData account {address} could not be decoded"),
        };
    };
    let Some(header) = data.get(..45) else {
        return State::Unavailable {
            reason: format!("ProgramData account {address} is too short"),
        };
    };
    let last_deploy_slot = u64::from_le_bytes(header[4..12].try_into().expect("eight bytes"));
    if header[12] == 0 {
        return State::Frozen { last_deploy_slot };
    }
    let authority: [u8; 32] = header[13..45].try_into().expect("thirty-two bytes");
    State::Upgradeable {
        authority: encode_base58(&authority),
        last_deploy_slot,
    }
}

/// `{"data": ["<base64>", "base64"], ...}` as returned with `encoding: base64`.
fn account_data(account: &Value) -> Option<Vec<u8>> {
    let encoded = account.get("data")?.get(0)?.as_str()?;
    decode_base64(encoded)
}

fn decode_base64(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    let mut accumulator: u32 = 0;
    let mut bits = 0;
    for byte in text.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => break,
            b'\n' | b'\r' => continue,
            _ => return None,
        };
        accumulator = (accumulator << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((accumulator >> bits) as u8);
        }
    }
    Some(out)
}

struct Client {
    agent: ureq::Agent,
    url: String,
}

impl Client {
    fn new(url: &str) -> Self {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(std::time::Duration::from_secs(30)))
            .user_agent(concat!("vaultlint/", env!("CARGO_PKG_VERSION")))
            .build()
            .into();
        Client {
            agent,
            url: url.to_string(),
        }
    }

    fn get_multiple_accounts(&self, addresses: &[&str]) -> Result<Vec<Option<Value>>, String> {
        self.accounts(addresses, json!({"encoding": "base64"}))
    }

    fn get_multiple_accounts_sliced(
        &self,
        addresses: &[&str],
        length: usize,
    ) -> Result<Vec<Option<Value>>, String> {
        self.accounts(
            addresses,
            json!({"encoding": "base64", "dataSlice": {"offset": 0, "length": length}}),
        )
    }

    fn accounts(&self, addresses: &[&str], config: Value) -> Result<Vec<Option<Value>>, String> {
        let response = self.call("getMultipleAccounts", json!([addresses, config]))?;
        let values = response
            .get("value")
            .and_then(Value::as_array)
            .ok_or_else(|| "getMultipleAccounts returned no value array".to_string())?;
        if values.len() != addresses.len() {
            return Err(format!(
                "getMultipleAccounts returned {} accounts for {} addresses",
                values.len(),
                addresses.len()
            ));
        }
        Ok(values
            .iter()
            .map(|v| if v.is_null() { None } else { Some(v.clone()) })
            .collect())
    }

    /// One JSON-RPC call, retried on the rate limiting the public endpoint
    /// applies to anything that asks more than a few questions in a row.
    fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        let payload = serde_json::to_string(&body).map_err(|e| e.to_string())?;
        let mut last = String::new();

        for attempt in 0..4 {
            if attempt > 0 {
                std::thread::sleep(std::time::Duration::from_millis(500 << attempt));
            }
            let sent = self
                .agent
                .post(&self.url)
                .header("Content-Type", "application/json")
                .send(payload.as_str());
            let mut response = match sent {
                Ok(response) => response,
                Err(error) => {
                    last = error.to_string();
                    continue;
                }
            };
            if response.status().as_u16() != 200 {
                last = format!("{} returned HTTP {}", self.url, response.status());
                continue;
            }
            let text = match response.body_mut().read_to_string() {
                Ok(text) => text,
                Err(error) => {
                    last = error.to_string();
                    continue;
                }
            };
            let parsed: Value = match serde_json::from_str(&text) {
                Ok(parsed) => parsed,
                Err(error) => {
                    last = format!("{} returned unparseable JSON: {error}", self.url);
                    continue;
                }
            };
            if let Some(error) = parsed.get("error") {
                last = format!("{method} failed: {error}");
                continue;
            }
            return parsed
                .get("result")
                .cloned()
                .ok_or_else(|| format!("{method} returned no result"));
        }
        Err(last)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn account(owner: &str, data: &str) -> Value {
        json!({"owner": owner, "data": [data, "base64"], "lamports": 1})
    }

    /// A null in the `getMultipleAccounts` array means no account exists.
    #[test]
    fn a_missing_account_is_absent() {
        assert_eq!(classify_program_account(None), State::Absent);
        assert_eq!(classify_program_account(Some(&Value::Null)), State::Absent);
    }

    /// Loader v1 and v2 hold code that no key can replace. Eight ids in the
    /// measured corpus resolved to neither loader nor upgradeable loader, and
    /// calling those "immutable" would be a flat lie.
    ///
    /// Kill: collapse the `NotAProgram` arm into `Immutable`.
    #[test]
    fn the_loader_decides_what_the_account_is() {
        assert_eq!(
            classify_program_account(Some(&account(LOADER_V2, ""))),
            State::Immutable
        );
        assert_eq!(
            classify_program_account(Some(&account(LOADER_V1, ""))),
            State::Immutable
        );
        assert_eq!(
            classify_program_account(Some(&account(
                "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
                ""
            ))),
            State::NotAProgram {
                owner: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".to_string()
            }
        );
    }

    /// The upgradeable loader's program account is a four-byte tag and the
    /// ProgramData address. The first pass parks that address where the
    /// authority will go; the second pass overwrites it.
    ///
    /// Kill: read the address from offset 0 instead of 4.
    #[test]
    fn an_upgradeable_program_yields_its_program_data_address() {
        // tag 2, then the 32 bytes of the system program address (all zero).
        let data = base64_of(&[&[2, 0, 0, 0][..], &[0u8; 32][..]].concat());
        assert_eq!(
            classify_program_account(Some(&account(UPGRADEABLE_LOADER, &data))),
            State::Upgradeable {
                authority: "11111111111111111111111111111111".to_string(),
                last_deploy_slot: 0,
            }
        );
    }

    /// A revoked authority is written as a zero option tag, and it is the one
    /// state that says nobody can replace this code. Zero of forty-four live
    /// programs in the measured corpus were in it, so the branch has never been
    /// exercised against a real account — the test is the only thing holding it.
    ///
    /// Kill: treat the option tag as always present.
    #[test]
    fn a_revoked_authority_is_frozen() {
        let mut raw = vec![3, 0, 0, 0];
        raw.extend_from_slice(&7_u64.to_le_bytes());
        raw.push(0);
        raw.extend_from_slice(&[9u8; 32]);
        assert_eq!(
            classify_program_data("PD", Some(&account(UPGRADEABLE_LOADER, &base64_of(&raw)))),
            State::Frozen {
                last_deploy_slot: 7
            }
        );
    }

    /// The slot is little-endian at offset 4 and the authority follows the
    /// option tag at offset 13.
    ///
    /// Kill: read the slot big-endian, or start the authority at 12.
    #[test]
    fn a_live_authority_is_read_with_its_deploy_slot() {
        let mut raw = vec![3, 0, 0, 0];
        raw.extend_from_slice(&435_764_727_u64.to_le_bytes());
        raw.push(1);
        raw.extend_from_slice(&[0u8; 32]);
        assert_eq!(
            classify_program_data("PD", Some(&account(UPGRADEABLE_LOADER, &base64_of(&raw)))),
            State::Upgradeable {
                authority: "11111111111111111111111111111111".to_string(),
                last_deploy_slot: 435_764_727,
            }
        );
    }

    /// A ProgramData account that is missing or truncated is not evidence of
    /// anything, so it must not read as `Frozen` or `Absent`.
    #[test]
    fn a_truncated_program_data_account_is_unavailable() {
        assert!(matches!(
            classify_program_data("PD", None),
            State::Unavailable { .. }
        ));
        assert!(matches!(
            classify_program_data("PD", Some(&account(UPGRADEABLE_LOADER, "AAAA"))),
            State::Unavailable { .. }
        ));
    }

    #[test]
    fn base64_decodes_padded_and_unpadded_input() {
        assert_eq!(decode_base64("AAAA").unwrap(), vec![0, 0, 0]);
        assert_eq!(decode_base64("/w==").unwrap(), vec![255]);
        assert_eq!(decode_base64("AgAAAA==").unwrap(), vec![2, 0, 0, 0]);
        assert_eq!(decode_base64("").unwrap(), Vec::<u8>::new());
        assert!(decode_base64("!!!!").is_none());
    }

    fn base64_of(bytes: &[u8]) -> String {
        const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let b = [
                chunk[0],
                chunk.get(1).copied().unwrap_or(0),
                chunk.get(2).copied().unwrap_or(0),
            ];
            let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
            for i in 0..4 {
                if i <= chunk.len() {
                    out.push(char::from(TABLE[((n >> (18 - 6 * i)) & 0x3f) as usize]));
                } else {
                    out.push('=');
                }
            }
        }
        out
    }
}
