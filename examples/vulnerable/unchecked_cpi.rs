use anchor_lang::prelude::*;
use solana_program::program::invoke;

pub fn claim(ctx: Context<Claim>, data: Vec<u8>) -> Result<()> {
    let instruction = Instruction {
        program_id: *ctx.accounts.target_program.key,
        accounts: vec![],
        data,
    };
    invoke(&instruction, &[ctx.accounts.target_program.clone()])?;
    Ok(())
}
