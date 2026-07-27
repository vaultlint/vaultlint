// This handler builds an instruction using an SDK builder function whose
// program id is a constant compiled into the builder. There is nothing for
// the developer to verify, so VL005 must be silent here.
//
// The example deliberately does NOT contain `require_keys_eq!` or `::ID`.
// If it were silent only because S1 fired, the example would prove nothing
// about the T1/T2 fix. It is silent because T1 is not satisfied: the first
// argument to `invoke` is not an `Instruction` struct literal or
// `Instruction::new_with_*` call built in this body.
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    program::invoke,
    pubkey::Pubkey,
    rent::Rent,
    sysvar::Sysvar,
};

pub fn create_address_info(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    account_span: usize,
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let address_info_account = next_account_info(accounts_iter)?;
    let payer = next_account_info(accounts_iter)?;
    let system_program = next_account_info(accounts_iter)?;

    let lamports_required = (Rent::get()?).minimum_balance(account_span);

    invoke(
        &solana_system_interface::instruction::create_account(
            payer.key,
            address_info_account.key,
            lamports_required,
            account_span as u64,
            program_id,
        ),
        &[
            payer.clone(),
            address_info_account.clone(),
            system_program.clone(),
        ],
    )?;

    Ok(())
}
