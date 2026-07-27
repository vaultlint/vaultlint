use anchor_lang::prelude::*;

#[program]
pub mod vault {
    use super::*;

    pub fn initialize_account(ctx: Context<InitializeAccount>) -> Result<()> {
        let account = &mut ctx.accounts.user_account;
        // An attacker-chosen pubkey is written into the account being created,
        // as the account's owning authority — VL001.
        account.authority = ctx.accounts.authority.key();
        Ok(())
    }
}

#[derive(Accounts)]
pub struct InitializeAccount<'info> {
    #[account(
        init,
        payer = fee_payer,
        space = 8 + 32,
        seeds = [b"account", authority.key().as_ref()],
        bump
    )]
    pub user_account: Account<'info, UserAccount>,
    /// CHECK: deliberately unvalidated — VL001
    pub authority: AccountInfo<'info>,
    #[account(mut)]
    pub fee_payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[account]
pub struct UserAccount {
    pub authority: Pubkey,
}
