use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut, seeds = [b"vault", user.key().as_ref()], bump)]
    pub vault: Account<'info, Vault>,
    pub user: Signer<'info>,
}
