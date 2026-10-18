//! Conductor startup of the enabled apps: each app starts on its own, an app
//! whose startup fails is disabled without holding back the rest, and startup
//! returns only once every attempt has finished.

use crate::conductor::api::error::ConductorApiResult;
use crate::conductor::conductor::app_startup::{
    run_app_startup_attempts, P2pOverrideReservations, APP_STARTUP_CONCURRENCY,
};
use crate::conductor::{error::ConductorError, CellError};
use crate::sweettest::*;
use crate::test_utils::inline_zomes::simple_crud_zome;
use ::fixt::prelude::*;
use futures::future::{self, FutureExt};
use holo_hash::fixt::{AgentPubKeyFixturator, DnaHashFixturator};
use holo_hash::{ActionHash, AgentPubKey, DnaHash};
use holochain_types::app::{
    AppManifest, AppManifestV0, AppRoleAssignment, AppRolePrimary, AppStatus, DisabledAppReason,
    InstalledApp, InstalledAppCommon, InstalledAppId,
};
use holochain_types::prelude::{CellId, DnaFile, Timestamp};
use kitsune2_test_utils::bootstrap::TestBootstrapSrv;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::{mpsc, oneshot};

/// More apps than fit in the startup bound twice over, so queued apps are
/// admitted both after successes and after failures.
const MANY_APPS: usize = 2 * APP_STARTUP_CONCURRENCY + 1;

fn manifest(bootstrap_url: Option<String>, relay_url: Option<String>) -> AppManifest {
    AppManifest::V0(AppManifestV0 {
        allow_deferred_memproofs: false,
        description: None,
        name: "startup".to_string(),
        roles: vec![],
        bootstrap_url,
        relay_url,
    })
}

fn relay_manifest(relay_url: &str) -> AppManifest {
    manifest(None, Some(relay_url.to_string()))
}

async fn unique_dna() -> DnaFile {
    SweetDnaFile::unique_from_inline_zomes(simple_crud_zome())
        .await
        .0
}

/// An app record with one provisioned role per DNA, for `agent`.
fn app_record(
    app_id: &str,
    agent: AgentPubKey,
    dnas: &[&DnaHash],
    manifest: AppManifest,
) -> InstalledAppCommon {
    let roles = dnas.iter().enumerate().map(|(n, dna_hash)| {
        (
            format!("role-{n}"),
            AppRoleAssignment::Primary(AppRolePrimary::new((*dna_hash).clone(), true, 0)),
        )
    });
    InstalledAppCommon::new(app_id.to_string(), agent, roles, manifest, Timestamp::now()).unwrap()
}

/// Record an enabled app whose only cell is `cell_id`, without starting it —
/// an app the conductor will try to start when it next starts up.
async fn add_enabled_app(conductor: &SweetConductor, app_id: &str, cell_id: &CellId) {
    let app = app_record(
        app_id,
        cell_id.agent_pubkey().clone(),
        &[cell_id.dna_hash()],
        manifest(None, None),
    );
    conductor
        .raw_handle()
        .update_state(move |mut state| {
            let app_id = app.id().clone();
            state.add_app(app)?;
            state.get_app_mut(&app_id)?.status = AppStatus::Enabled;
            Ok(state)
        })
        .await
        .unwrap();
}

/// Mark installed apps enabled without starting them, as a conductor finds
/// them when it starts up.
async fn mark_enabled(conductor: &SweetConductor, app_ids: &[&str]) {
    let app_ids: Vec<InstalledAppId> = app_ids.iter().map(|id| id.to_string()).collect();
    conductor
        .raw_handle()
        .update_state(move |mut state| {
            for app_id in &app_ids {
                state.get_app_mut(app_id)?.status = AppStatus::Enabled;
            }
            Ok(state)
        })
        .await
        .unwrap();
}

async fn app_status(conductor: &SweetConductor, app_id: &str) -> AppStatus {
    conductor
        .raw_handle()
        .get_state()
        .await
        .unwrap()
        .get_app(&app_id.to_string())
        .unwrap()
        .status
        .clone()
}

async fn app_cells(conductor: &SweetConductor, app_id: &str) -> Vec<CellId> {
    conductor
        .raw_handle()
        .get_state()
        .await
        .unwrap()
        .get_app(&app_id.to_string())
        .unwrap()
        .all_cells()
        .collect()
}

async fn create_unit(
    conductor: &SweetConductor,
    cell_id: &CellId,
) -> ConductorApiResult<ActionHash> {
    let cell = conductor.get_sweet_cell(cell_id.clone()).unwrap();
    conductor
        .call_fallible(&cell.zome("coordinator"), "create_unit", ())
        .await
}

/// At most [`APP_STARTUP_CONCURRENCY`] attempts run at once; each attempt that
/// finishes — succeeded or failed — admits the next; every failure is
/// recorded; and the run returns only once the last attempt has finished.
#[tokio::test(flavor = "multi_thread")]
async fn startup_attempts_are_bounded_drained_and_awaited() {
    let active = Arc::new(AtomicUsize::new(0));
    let most_active = Arc::new(AtomicUsize::new(0));
    let (started_tx, mut started_rx) = mpsc::unbounded_channel();
    let mut releases = Vec::new();
    let mut attempts = Vec::new();
    for n in 0..MANY_APPS {
        let (release, released) = oneshot::channel::<()>();
        releases.push(Some(release));
        let (active, most_active, started_tx) =
            (active.clone(), most_active.clone(), started_tx.clone());
        let attempt = async move {
            let now_active = active.fetch_add(1, Ordering::SeqCst) + 1;
            most_active.fetch_max(now_active, Ordering::SeqCst);
            started_tx.send(n).unwrap();
            released.await.unwrap();
            active.fetch_sub(1, Ordering::SeqCst);
            if n % 2 == 0 {
                Err(ConductorError::other("injected startup failure"))
            } else {
                Ok(())
            }
        };
        attempts.push((format!("app-{n}"), attempt));
    }

    let recorded = Arc::new(Mutex::new(Vec::new()));
    let startup = tokio::spawn({
        let recorded = recorded.clone();
        run_app_startup_attempts(attempts, move |app_id, _error| {
            recorded.lock().unwrap().push(app_id);
            future::ready(Ok(()))
        })
    });

    // Release the attempts one at a time, in the order they started, and wait
    // for each release to admit the next queued app.
    let mut started = Vec::new();
    for _ in 0..APP_STARTUP_CONCURRENCY {
        started.push(started_rx.recv().await.unwrap());
    }
    for next in 0..MANY_APPS - 1 {
        releases[started[next]].take().unwrap().send(()).unwrap();
        if started.len() < MANY_APPS {
            started.push(started_rx.recv().await.unwrap());
        }
    }

    // Every attempt but one has finished; the run is still waiting on it.
    assert!(!startup.is_finished());
    releases[started[MANY_APPS - 1]]
        .take()
        .unwrap()
        .send(())
        .unwrap();
    startup.await.unwrap().unwrap();

    assert_eq!(most_active.load(Ordering::SeqCst), APP_STARTUP_CONCURRENCY);
    let mut recorded = recorded.lock().unwrap().clone();
    recorded.sort();
    let mut failed: Vec<_> = (0..MANY_APPS)
        .filter(|n| n % 2 == 0)
        .map(|n| format!("app-{n}"))
        .collect();
    failed.sort();
    assert_eq!(recorded, failed);
}

/// A failure that cannot be recorded cancels nothing: every other attempt
/// still runs, and the recording error is what the run returns.
#[tokio::test(flavor = "multi_thread")]
async fn a_failure_that_cannot_be_recorded_is_returned_once_every_attempt_has_finished() {
    let finished = Arc::new(AtomicUsize::new(0));
    let attempts: Vec<_> = (0..MANY_APPS)
        .map(|n| {
            let finished = finished.clone();
            let attempt = async move {
                finished.fetch_add(1, Ordering::SeqCst);
                if n == 0 {
                    Err(ConductorError::other("injected startup failure"))
                } else {
                    Ok(())
                }
            };
            (format!("app-{n}"), attempt)
        })
        .collect();

    let result = run_app_startup_attempts(attempts, |app_id, _error| {
        future::ready(Err(ConductorError::other(format!(
            "could not record the failure of {app_id}"
        ))))
    })
    .await;

    assert_eq!(finished.load(Ordering::SeqCst), MANY_APPS);
    let error = result.unwrap_err();
    assert!(
        error
            .to_string()
            .contains("could not record the failure of app-0"),
        "{error:?}"
    );
}

/// An app's cells are published and serve zome calls as soon as its own
/// startup finishes, while another app's startup is still pending.
#[tokio::test(flavor = "multi_thread")]
async fn an_app_serves_while_another_apps_startup_is_pending() {
    holochain_trace::test_run();
    let dna = unique_dna().await;
    let mut conductor = SweetConductor::standard().await;
    let pending_agent = conductor
        .install_app("pending", None, &[dna.clone()], None)
        .await
        .unwrap();
    let ready_agent = conductor
        .install_app("ready", None, &[dna.clone()], None)
        .await
        .unwrap();
    mark_enabled(&conductor, &["pending", "ready"]).await;
    let pending_cell = CellId::new(dna.dna_hash().clone(), pending_agent);
    let ready_cell = CellId::new(dna.dna_hash().clone(), ready_agent);

    let handle = conductor.raw_handle();
    let state = handle.get_state().await.unwrap();
    let enabled_app = |app_id: &str| state.get_app(&app_id.to_string()).unwrap().clone();

    let (release_pending, pending_released) = oneshot::channel::<()>();
    let (ready_started, ready_has_started) = oneshot::channel::<()>();
    let pending_attempt = {
        let (handle, app) = (handle.clone(), enabled_app("pending"));
        async move {
            pending_released.await.unwrap();
            handle.startup_app(app).await
        }
        .boxed()
    };
    let ready_attempt = {
        let (handle, app) = (handle.clone(), enabled_app("ready"));
        async move {
            handle.startup_app(app).await?;
            ready_started.send(()).unwrap();
            Ok::<_, ConductorError>(())
        }
        .boxed()
    };
    let startup = tokio::spawn(run_app_startup_attempts(
        [
            ("pending".to_string(), pending_attempt),
            ("ready".to_string(), ready_attempt),
        ],
        |_app_id, error| future::ready(Err(error)),
    ));

    ready_has_started.await.unwrap();
    let running = handle.running_cell_ids();
    assert!(running.contains(&ready_cell));
    assert!(!running.contains(&pending_cell));
    create_unit(&conductor, &ready_cell).await.unwrap();
    assert!(!startup.is_finished());

    release_pending.send(()).unwrap();
    startup.await.unwrap().unwrap();
    assert!(handle.running_cell_ids().contains(&pending_cell));
    create_unit(&conductor, &pending_cell).await.unwrap();
}

/// Through a real restart: apps whose startup fails — one whose ribosomes
/// cannot be loaded, one whose cell cannot be created — are disabled with the
/// error, the apps around them start and serve, and by the time startup
/// returns every outcome is already settled. A further restart does not try
/// the failed apps again.
#[tokio::test(flavor = "multi_thread")]
async fn an_app_that_fails_to_start_is_disabled_and_the_others_start() {
    holochain_trace::test_run();
    let dna = unique_dna().await;
    let mut conductor = SweetConductor::standard().await;
    let first = conductor.setup_app("first", [&dna]).await.unwrap();

    // No DNA definition is stored for this cell, so loading its ribosomes fails.
    let missing_dna_def = CellId::new(fixt!(DnaHash), fixt!(AgentPubKey));
    add_enabled_app(&conductor, "missing-dna-def", &missing_dna_def).await;

    // Its DNA definition is stored but genesis never ran, so creating its cell fails.
    let no_genesis = CellId::new(dna.dna_hash().clone(), fixt!(AgentPubKey));
    conductor
        .raw_handle()
        .spaces
        .dna_def_store
        .put(no_genesis.agent_pubkey(), dna.dna_def())
        .await
        .unwrap();
    add_enabled_app(&conductor, "no-genesis", &no_genesis).await;

    let last = conductor.setup_app("last", [&dna]).await.unwrap();
    let serving = [
        first.cells()[0].cell_id().clone(),
        last.cells()[0].cell_id().clone(),
    ];
    let failing = [
        ("missing-dna-def", missing_dna_def),
        ("no-genesis", no_genesis),
    ];

    conductor.shutdown().await;
    conductor.startup().await;

    let running = conductor.raw_handle().running_cell_ids();
    for cell_id in &serving {
        assert!(running.contains(cell_id));
        create_unit(&conductor, cell_id).await.unwrap();
    }
    let mut failed_statuses = Vec::new();
    for (app_id, cell_id) in &failing {
        assert!(!running.contains(cell_id));
        let status = app_status(&conductor, app_id).await;
        assert!(
            matches!(status, AppStatus::Disabled(DisabledAppReason::Error(_))),
            "{app_id}: {status:?}"
        );
        failed_statuses.push(status);
    }

    conductor.shutdown().await;
    conductor.startup().await;

    let running = conductor.raw_handle().running_cell_ids();
    for cell_id in &serving {
        assert!(running.contains(cell_id));
    }
    for ((app_id, cell_id), status) in failing.iter().zip(failed_statuses) {
        assert!(!running.contains(cell_id));
        assert_eq!(app_status(&conductor, app_id).await, status);
    }
}

/// Through a real restart: two enabled apps that run one DNA with different
/// P2P overrides cannot both start. The first in the conductor's order starts;
/// the second is disabled with the conflict.
#[tokio::test(flavor = "multi_thread")]
async fn apps_with_conflicting_overrides_for_one_dna_cannot_both_start() {
    holochain_trace::test_run();
    let dna = unique_dna().await;
    let mut conductor = SweetConductor::standard().await;
    let bootstrap = TestBootstrapSrv::new(false).await;
    let bootstrap_url = Some(bootstrap.addr().to_string());

    conductor
        .install_app_with_manifest(
            "first",
            None,
            [&dna],
            None,
            manifest(bootstrap_url.clone(), None),
        )
        .await
        .unwrap();
    conductor
        .install_app_with_manifest(
            "second",
            None,
            [&dna],
            None,
            manifest(bootstrap_url, Some("wss://different:5678".to_string())),
        )
        .await
        .unwrap();
    mark_enabled(&conductor, &["first", "second"]).await;

    conductor.shutdown().await;
    conductor.startup().await;

    let running = conductor.raw_handle().running_cell_ids();
    for cell_id in app_cells(&conductor, "first").await {
        assert!(running.contains(&cell_id));
    }
    for cell_id in app_cells(&conductor, "second").await {
        assert!(!running.contains(&cell_id));
    }
    let status = app_status(&conductor, "second").await;
    assert!(
        matches!(
            &status,
            AppStatus::Disabled(DisabledAppReason::Error(reason))
                if reason.contains("P2P config overrides")
        ),
        "{status:?}"
    );
}

/// The startup set's overrides are settled per DNA before any app starts: an
/// app that agrees with the reservation is admitted, one that disagrees is
/// refused with the app holding the DNA named, and a refused app reserves
/// none of its DNAs.
#[test]
fn reservations_admit_agreement_and_refuse_conflict_all_or_nothing() {
    let (shared, other) = (fixt!(DnaHash), fixt!(DnaHash));
    let enabled = |app_id: &str, dnas: &[&DnaHash], manifest: AppManifest| {
        InstalledApp::new(
            app_record(app_id, fixt!(AgentPubKey), dnas, manifest),
            AppStatus::Enabled,
        )
    };
    let mut reservations = P2pOverrideReservations::default();

    reservations
        .reserve(&enabled(
            "holder",
            &[&shared],
            relay_manifest("wss://one:1"),
        ))
        .unwrap();
    reservations
        .reserve(&enabled(
            "agrees",
            &[&shared],
            relay_manifest("wss://one:1"),
        ))
        .unwrap();

    let error = reservations
        .reserve(&enabled(
            "refused",
            &[&other, &shared],
            relay_manifest("wss://two:2"),
        ))
        .unwrap_err();
    assert!(
        matches!(
            &error,
            CellError::P2pConfigOverridesConflict { conflicting_app_id: Some(holder), .. }
                if holder.as_str() == "holder"
        ),
        "{error:?}"
    );

    // The refused app did not reserve `other`, so any overrides may still take it.
    reservations
        .reserve(&enabled(
            "takes-other",
            &[&other],
            relay_manifest("wss://three:3"),
        ))
        .unwrap();
}

/// When one of an app's cells cannot be created, none of its cells is
/// published — the sibling that was created is discarded — and the app can be
/// enabled once the cause is gone.
#[tokio::test(flavor = "multi_thread")]
async fn an_app_whose_cell_cannot_be_created_publishes_none_of_its_cells() {
    holochain_trace::test_run();
    let (own_dna, shared_dna) = (unique_dna().await, unique_dna().await);
    let mut conductor = SweetConductor::standard().await;
    let bootstrap = TestBootstrapSrv::new(false).await;

    // `holder` runs the shared DNA with the conductor's network configuration;
    // `pair` asks for its own bootstrap server, which conflicts on that DNA.
    conductor.setup_app("holder", [&shared_dna]).await.unwrap();
    conductor
        .install_app_with_manifest(
            "pair",
            None,
            [&own_dna, &shared_dna],
            None,
            manifest(Some(bootstrap.addr().to_string()), None),
        )
        .await
        .unwrap();
    let pair_cells = app_cells(&conductor, "pair").await;

    let error = conductor.enable_app("pair".to_string()).await.unwrap_err();
    assert!(
        matches!(
            error,
            ConductorError::InternalCellError(CellError::P2pConfigOverridesConflict { .. })
        ),
        "{error:?}"
    );
    let running = conductor.raw_handle().running_cell_ids();
    for cell_id in &pair_cells {
        assert!(!running.contains(cell_id));
    }

    conductor
        .disable_app("holder".to_string(), DisabledAppReason::User)
        .await
        .unwrap();
    conductor.enable_app("pair".to_string()).await.unwrap();
    let running = conductor.raw_handle().running_cell_ids();
    for cell_id in &pair_cells {
        assert!(running.contains(cell_id));
        create_unit(&conductor, cell_id).await.unwrap();
    }
}
