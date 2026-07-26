use anchor_lang::prelude::*;

#[derive(Accounts)]
#[instruction(user_bump: u8)]
pub struct Withdraw<'info> {
    #[account(mut, seeds = [b"vault", user.key().as_ref()], bump = user_bump)]
    pub vault: Account<'info, Vault>,
    pub user: Signer<'info>,
}
