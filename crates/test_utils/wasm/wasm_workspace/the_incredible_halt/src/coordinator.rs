use crate::integrity::*;
use hdk::prelude::*;

// Intentional fuel-exhaustion fixture: the_incredible_halt_test expects
// metering to trap this unchanged infinite loop.
#[allow(clippy::empty_loop)]
#[hdk_extern]
fn smash(_: ()) -> ExternResult<()> {
    loop {}
}

#[hdk_extern]
fn create_a_thing(_: ()) -> ExternResult<ActionHash> {
    create_entry(&EntryTypes::Thing(Thing))
}
