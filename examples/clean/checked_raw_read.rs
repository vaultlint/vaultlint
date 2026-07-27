// This handler reads raw account data through the intermediate-local
// `try_borrow_data` form — the shape VL002 learned to recognise — and verifies
// the owning program before it touches a byte. VL002 must be silent here.
//
// The example is a canary, not a decoration: delete the `require_keys_eq!`
// line and the very next statement becomes a VL002 finding.
use anchor_lang::prelude::*;

declare_id!("Vau1t1ntExamp1e11111111111111111111111111");

pub fn read_registry(ctx: Context<ReadRegistry>) -> Result<()> {
    let account = &ctx.accounts.registry;
    require_keys_eq!(*account.owner, crate::ID);

    let data = account.try_borrow_data()?;
    let registry = Registry::try_from_slice(&data[8..])?;
    msg!("entries: {}", registry.entries);

    Ok(())
}

#[derive(Accounts)]
pub struct ReadRegistry<'info> {
    /// CHECK: the owning program is verified by the handler above, which is
    /// why this account may be untyped.
    pub registry: UncheckedAccount<'info>,
}

#[account]
pub struct Registry {
    pub entries: u64,
}
