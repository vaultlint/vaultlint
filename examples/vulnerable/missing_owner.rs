use anchor_lang::prelude::*;

pub fn read_config(ctx: Context<ReadConfig>) -> Result<()> {
    let account = &ctx.accounts.config;
    let config = Config::try_from_slice(&account.data.borrow())?;
    msg!("fee: {}", config.fee);
    Ok(())
}
