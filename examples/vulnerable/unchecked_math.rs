use anchor_lang::prelude::*;

pub fn withdraw(vault: &mut Vault, amount: u64) -> Result<()> {
    vault.balance = vault.balance - amount;
    vault.rewards += amount * 2;
    Ok(())
}
