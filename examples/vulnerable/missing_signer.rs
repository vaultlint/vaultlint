use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// CHECK: deliberately unvalidated for VL001
    pub authority: AccountInfo<'info>,
}
