use hdk::prelude::*;

#[hdk_entry_helper]
pub struct Thing;

#[hdk_entry_types]
#[unit_enum(EntryTypesUnit)]
pub enum EntryTypes {
    Thing(Thing),
}

// Intentional fuel-exhaustion fixture: the_incredible_halt_test expects
// metering to trap this unchanged infinite loop.
#[allow(clippy::empty_loop)]
#[hdk_extern]
fn validate(_op: Op) -> ExternResult<ValidateCallbackResult> {
    loop {}
}
