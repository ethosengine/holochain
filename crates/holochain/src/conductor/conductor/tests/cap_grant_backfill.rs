//! The capability-grant lookup-key backfill and conductor startup.

use crate::conductor::space::CAP_GRANT_BACKFILL_TEST_MODE;
use crate::sweettest::*;
use crate::test_utils::inline_zomes::simple_crud_zome;
use holo_hash::{ActionHash, AgentPubKey};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

async fn conductor_with_app() -> (SweetConductor, SweetCell) {
    let (dna, _, _) = SweetDnaFile::unique_from_inline_zomes(simple_crud_zome()).await;
    let mut conductor = SweetConductor::standard().await;
    let app = conductor.setup_app("app", [&dna]).await.unwrap();
    let (cell,) = app.into_tuple();
    (conductor, cell)
}

fn hosted_agent(n: u8) -> AgentPubKey {
    AgentPubKey::from_raw_36(vec![200 + n; 36])
}

/// The real startup path gives the "cells are running" signal: after a
/// restart the backfill has been started for the app's store, and un-keyed
/// grants left in the file are keyed. So does creating cells at runtime, for
/// an app installed on a conductor that is already up.
#[tokio::test(flavor = "multi_thread")]
async fn cap_grant_backfill_starts_once_startup_has_enabled_the_apps() {
    let (mut conductor, cell) = conductor_with_app().await;
    let dna_hash = cell.dna_hash().clone();

    // Installed on a running conductor: started when its cells were created.
    let spaces = conductor.raw_handle().spaces.clone();
    assert!(spaces.cap_grant_backfill_started(&dna_hash));

    let store = spaces.dht_store(&dna_hash).unwrap();
    store
        .test_insert_unkeyed_cap_grants(&hosted_agent(0), 3)
        .await
        .unwrap();

    conductor.shutdown().await;
    conductor.startup().await;

    let spaces = conductor.raw_handle().spaces.clone();
    assert!(
        spaces.cap_grant_backfill_started(&dna_hash),
        "conductor startup did not give the cells-running signal"
    );
    let store = spaces.dht_store(&dna_hash).unwrap();
    let deadline = Instant::now() + Duration::from_secs(60);
    while store.count_cap_grants_unkeyed().await.unwrap() != 0 {
        assert!(
            Instant::now() < deadline,
            "the conductor started but the un-keyed grants were never keyed"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn median(samples: &[Duration]) -> Duration {
    let mut sorted = samples.to_vec();
    sorted.sort();
    sorted[sorted.len() / 2]
}

/// TIME TO READY, with and without grants to backfill.
///
/// One conductor, one app whose store holds 20 000 capability grants of ten
/// other agents. It is restarted over and over, and each restart is timed from
/// the call to start it to the first zome call that is answered. Four arms,
/// interleaved, five samples each:
///
/// - every grant already keyed (nothing to backfill);
/// - every grant un-keyed, backfill as shipped (deferred until cells run);
/// - every grant un-keyed, backfill switched off;
/// - every grant un-keyed, backfill started the moment the store is opened,
///   with no delay — the worst case of what the deferral replaces.
///
/// Asserted: with the backfill as shipped, 20 000 un-keyed rows do not move
/// the time to ready beyond noise. The other arms are printed for comparison.
///
/// This conductor is tiny — one cell, a few hundred ops, a start measured in
/// hundreds of milliseconds — so it shows whether the backfill touches
/// startup at all, not what it cost on a fleet store whose start takes a
/// minute.
///
/// ```text
/// cargo test -p holochain --lib time_to_ready_with_unkeyed_cap_grants \
///     -- --ignored --nocapture
/// ```
#[tokio::test(flavor = "multi_thread")]
#[ignore = "a measurement, several minutes; run alone with -- --ignored --nocapture"]
async fn time_to_ready_with_unkeyed_cap_grants() {
    const ROWS: u32 = 20_000;
    const SAMPLES: usize = 5;
    // (label, grants un-keyed at start, backfill test mode)
    const ARMS: [(&str, bool, u8); 4] = [
        ("0 un-keyed rows", false, 0),
        (
            "20000 un-keyed rows, backfill deferred (as shipped)",
            true,
            0,
        ),
        ("20000 un-keyed rows, backfill off", true, 1),
        ("20000 un-keyed rows, backfill at open, no delay", true, 2),
    ];

    let (mut conductor, cell) = conductor_with_app().await;
    let dna_hash = cell.dna_hash().clone();
    let zome = cell.zome(SweetInlineZomes::COORDINATOR);
    for _ in 0..300 {
        let _: ActionHash = conductor.call(&zome, "create_unit", ()).await;
    }
    {
        let store = conductor.raw_handle().spaces.dht_store(&dna_hash).unwrap();
        for a in 0..10 {
            store
                .test_insert_unkeyed_cap_grants(&hosted_agent(a), ROWS / 10)
                .await
                .unwrap();
        }
    }

    let mut ready: Vec<Vec<Duration>> = vec![Vec::new(); ARMS.len()];
    let mut started: Vec<Vec<Duration>> = vec![Vec::new(); ARMS.len()];
    for sample in 0..SAMPLES {
        for (arm, (label, unkeyed, mode)) in ARMS.iter().enumerate() {
            // Put the store in the arm's starting state while nothing else is
            // touching it: any backfill from the previous run has finished
            // (waited for below) and no new one can start.
            CAP_GRANT_BACKFILL_TEST_MODE.store(1, Ordering::SeqCst);
            let store = conductor.raw_handle().spaces.dht_store(&dna_hash).unwrap();
            if *unkeyed {
                store.test_forget_cap_grant_lookup_columns().await.unwrap();
                assert_eq!(store.count_cap_grants_unkeyed().await.unwrap(), ROWS as u64);
            } else {
                store.backfill_cap_grant_lookup_keys().await.unwrap();
                assert_eq!(store.count_cap_grants_unkeyed().await.unwrap(), 0);
            }
            conductor.shutdown().await;

            CAP_GRANT_BACKFILL_TEST_MODE.store(*mode, Ordering::SeqCst);
            let begun = Instant::now();
            conductor.startup().await;
            let up = begun.elapsed();
            loop {
                let answered: Result<ActionHash, _> =
                    conductor.call_fallible(&zome, "create_unit", ()).await;
                if answered.is_ok() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            let answered = begun.elapsed();
            eprintln!(
                "time-to-ready sample {sample} [{label}]: startup returned {up:?}, first \
                 answered call {answered:?}"
            );
            started[arm].push(up);
            ready[arm].push(answered);

            // Let whatever backfill this arm started run to its end, so the
            // next arm starts from a quiet store.
            if *unkeyed && *mode != 1 {
                let store = conductor.raw_handle().spaces.dht_store(&dna_hash).unwrap();
                let deadline = Instant::now() + Duration::from_secs(180);
                while store.count_cap_grants_unkeyed().await.unwrap() != 0 {
                    assert!(
                        Instant::now() < deadline,
                        "[{label}] backfill never finished"
                    );
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            }
        }
    }
    CAP_GRANT_BACKFILL_TEST_MODE.store(0, Ordering::SeqCst);

    for (arm, (label, _, _)) in ARMS.iter().enumerate() {
        let r = &ready[arm];
        eprintln!(
            "time-to-ready [{label}]: first answered call median {:?} (min {:?}, max {:?}); \
             startup returned median {:?}; n={}",
            median(r),
            r.iter().min().unwrap(),
            r.iter().max().unwrap(),
            median(&started[arm]),
            r.len()
        );
    }

    // As shipped, rows to backfill do not move time-to-ready beyond noise: the
    // backfill has not started when the first call is answered.
    let (zero, deferred) = (median(&ready[0]), median(&ready[1]));
    let spread = *ready[0].iter().max().unwrap() - *ready[0].iter().min().unwrap();
    assert!(
        deferred <= zero + spread + zero / 4 + Duration::from_millis(100),
        "20000 un-keyed rows moved time-to-ready from {zero:?} to {deferred:?} \
         (spread at 0 rows {spread:?})"
    );
}
