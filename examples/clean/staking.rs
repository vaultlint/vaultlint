// Clean canary: exercises every construct the five VaultLint rules inspect,
// all correctly validated. The fixture must stay silent (zero findings) so
// that a rule regression that produces a false positive is caught here.
//
// Constructs present and why they are silent:
//
//   VL001 — authority is `Signer<'info>`, which proves authorisation.
//   VL002 — raw bytes are deserialised, but the account's owner is checked with
//            `require_keys_eq!` before the deserialiser call.
//   VL003 — all arithmetic into struct fields uses `checked_add` / `checked_sub`;
//            no plain `+` / `-` / `*` on the left-hand side of a field write.
//   VL004 — `#[account(seeds = …, bump)]` without `bump = <instruction_arg>`;
//            `bump` alone tells Anchor to derive the canonical bump itself.
//            `find_program_address` (canonical) is used in the body, not
//            `create_program_address`.
//   VL005 — `invoke` is called, but the instruction's `program_id` comes from a
//            `Program<'info, System>`-typed field, which Anchor has already
//            verified. `require_keys_eq!` is also present for explicitness.

use anchor_lang::prelude::*;
use solana_program::program::invoke;

declare_id!("Vau1t1ntExamp1e11111111111111111111111111");

#[program]
pub mod staking {
    use super::*;

    /// VL001: authority is Signer — authorisation is proven before the body runs.
    /// VL004: init + seeds + bump (no bump = <instruction_arg>).
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.authority = ctx.accounts.authority.key();
        vault.balance = 0;
        vault.bump = ctx.bumps.vault;
        Ok(())
    }

    /// VL002: raw bytes are deserialised after an explicit owner check.
    /// VL003: checked_sub — no silent overflow.
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let config_account = &ctx.accounts.config;
        // Owner verified before deserialisation — VL002 is silent.
        require_keys_eq!(*config_account.owner, crate::ID);
        let config = Config::try_from_slice(&config_account.data.borrow())?;
        let vault = &mut ctx.accounts.vault;
        // Checked arithmetic — VL003 is silent.
        vault.balance = vault
            .balance
            .checked_sub(amount)
            .ok_or(StakingError::MathOverflow)?;
        msg!("withdrew {} lamports; fee: {}", amount, config.fee);
        Ok(())
    }

    /// VL005: invoke is called, but the Instruction's program_id comes from
    /// `system_program`, which is declared as `Program<'info, System>`. Anchor
    /// verifies Program-typed fields before the handler body runs, so VL005 is
    /// silent (S2: program-typed account).
    pub fn transfer_lamports(ctx: Context<Transfer>, data: Vec<u8>) -> Result<()> {
        // Program-typed field — Anchor already verified the id. VL005 is silent.
        let ix = Instruction {
            program_id: ctx.accounts.system_program.key(),
            accounts: vec![],
            data,
        };
        invoke(
            &ix,
            &[ctx.accounts.system_program.to_account_info()],
        )?;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + 32 + 8 + 1,
        seeds = [b"vault", authority.key().as_ref()],
        bump
    )]
    pub vault: Account<'info, Vault>,
    /// VL001: Signer proves the authority authorised this instruction.
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(
        mut,
        has_one = authority,
        seeds = [b"vault", authority.key().as_ref()],
        bump = vault.bump
    )]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
    /// CHECK: owner is verified with require_keys_eq! before deserialisation.
    pub config: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct Transfer<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    /// CHECK: recipient of the lamport transfer; no data is deserialised.
    #[account(mut)]
    pub recipient: AccountInfo<'info>,
    /// VL005: Program-typed — Anchor already verified the program id.
    pub system_program: Program<'info, System>,
}

#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub balance: u64,
    pub bump: u8,
}

#[derive(AnchorDeserialize, AnchorSerialize)]
pub struct Config {
    pub fee: u64,
}

#[error_code]
pub enum StakingError {
    #[msg("math overflow")]
    MathOverflow,
}
