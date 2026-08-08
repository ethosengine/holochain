#![cfg(feature = "test_utils")]

//! Integration coverage for caller-declared zome call deadlines on the app
//! interface.
//!
//! The unit tests next to `ZomeCallAdmission` pin the policy itself. These
//! scenarios drive a real conductor over a real app interface websocket and
//! assert the observable consequences: a deadline actually fires, a refusal
//! actually arrives, and the interface actually frees the slot when a call is
//! abandoned rather than when the abandoned work eventually finishes.

use holochain::sweettest::*;
use holochain_conductor_api::{
    AppRequest, AppResponse, ExternalApiWireError, ZomeCallParamsSigned,
};
use holochain_types::prelude::*;
use holochain_websocket::WebsocketSender;
use matches::assert_matches;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// How long the `slow` zome function occupies the conductor for.
///
/// Long enough that a call bounded by [`DEADLINE`] cannot possibly have
/// completed when the deadline response arrives, so a passing assertion cannot
/// be explained by the call simply having finished.
const SLOW_CALL: Duration = Duration::from_secs(10);

/// The deadline the tests declare. Short enough to keep the suite fast, long
/// enough not to race conductor startup work on a loaded machine.
const DEADLINE: Duration = Duration::from_millis(500);

/// An upper bound on how long a *bounded* call may take to answer. Generous,
/// because the point of the assertion is that the answer arrives on the
/// deadline's timescale rather than the slow call's.
const RESPONSE_BUDGET: Duration = Duration::from_secs(5);

/// An app with a `slow` function that occupies the conductor for [`SLOW_CALL`],
/// and a `fast` function that returns immediately.
///
/// `entered` flips as soon as `slow` begins executing, which is how a test
/// knows the first call is genuinely in flight before it makes a second one.
fn deadline_test_zomes(entered: Arc<AtomicBool>) -> SweetInlineZomes {
    SweetInlineZomes::new(vec![], 0)
        .function("slow", move |_, _: ()| {
            entered.store(true, Ordering::SeqCst);
            // `block_in_place` rather than a bare sleep: this stands in for the
            // real ribosome's `spawn_blocking` WASM body, which the runtime
            // cannot preempt and a deadline cannot interrupt.
            tokio::task::block_in_place(|| std::thread::sleep(SLOW_CALL));
            Ok(())
        })
        .function("fast", |_, _: ()| Ok(()))
}

/// Everything a scenario needs: a running conductor, the installed cell, an
/// authenticated app interface client, and the flag that says whether the slow
/// zome function has started.
struct Fixture {
    conductor: SweetConductor,
    cell: SweetCell,
    tx: WebsocketSender,
    /// Keeps the receive half of the app websocket being polled for as long as
    /// the scenario runs.
    _rx: WsPollRecv,
    entered: Arc<AtomicBool>,
}

/// Set up a conductor with the given tuning and install the deadline test app.
async fn setup(max_concurrent_zome_calls: Option<usize>) -> Fixture {
    holochain_trace::test_run();

    let config = SweetConductorConfig::rendezvous(true).tune_conductor(|tuning| {
        tuning.max_concurrent_zome_calls = max_concurrent_zome_calls;
    });
    let mut conductor =
        SweetConductor::from_config_rendezvous(config, SweetLocalRendezvous::new().await).await;

    let entered = Arc::new(AtomicBool::new(false));
    let (dna, _, _) =
        SweetDnaFile::unique_from_inline_zomes(deadline_test_zomes(entered.clone())).await;
    let app = conductor.setup_app("test-app", &[dna]).await.unwrap();
    let (cell,) = app.into_tuple();

    let (tx, _rx) = conductor
        .app_ws_client::<AppResponse>("test-app".into())
        .await;

    Fixture {
        conductor,
        cell,
        tx,
        _rx,
        entered,
    }
}

/// Sign a call to `fn_name` as the cell's own agent.
async fn signed_call(
    conductor: &SweetConductor,
    cell: &SweetCell,
    fn_name: &str,
) -> ZomeCallParamsSigned {
    let (nonce, expires_at) = holochain_nonce::fresh_nonce(Timestamp::now()).unwrap();
    ZomeCallParamsSigned::try_from_params(
        conductor.raw_handle().keystore(),
        ZomeCallParams {
            cell_id: cell.cell_id().clone(),
            zome_name: SweetInlineZomes::COORDINATOR.into(),
            fn_name: fn_name.into(),
            cap_secret: None,
            provenance: cell.agent_pubkey().clone(),
            payload: ExternIO::encode(()).unwrap(),
            nonce,
            expires_at,
        },
    )
    .await
    .unwrap()
}

/// Wait until the `slow` function has actually started executing.
///
/// The budget is a liveness bound, not a timing assertion: the first call to a
/// freshly installed app also runs `init`.
async fn wait_until_in_flight(entered: &AtomicBool) {
    let deadline = Instant::now() + Duration::from_secs(60);
    while !entered.load(Ordering::SeqCst) {
        assert!(
            Instant::now() < deadline,
            "the slow zome call never started executing"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// A call that overruns its declared deadline is answered with
/// `ZomeCallDeadlineExceeded`, and the interface takes further work straight
/// away rather than waiting for the abandoned call to finish.
#[tokio::test(flavor = "multi_thread")]
async fn a_declared_deadline_bounds_the_response() {
    let fixture = setup(None).await;
    let Fixture {
        conductor,
        cell,
        tx,
        ..
    } = &fixture;

    let call = signed_call(conductor, cell, "slow").await;
    let started = Instant::now();
    let response: AppResponse = tx
        .request(AppRequest::CallZomeWithDeadline {
            call: Box::new(call),
            deadline_ms: DEADLINE.as_millis() as u32,
        })
        .await
        .unwrap();

    assert_matches!(
        response,
        AppResponse::Error(ExternalApiWireError::ZomeCallDeadlineExceeded(_))
    );
    let elapsed = started.elapsed();
    assert!(
        elapsed < RESPONSE_BUDGET,
        "the deadline response took {elapsed:?}, which is not on the deadline's timescale"
    );
    assert!(
        elapsed < SLOW_CALL,
        "the response cannot have been produced by the call completing"
    );

    // The interface is not wedged by the call it abandoned.
    let call = signed_call(conductor, cell, "fast").await;
    let response: AppResponse = tx
        .request(AppRequest::CallZome(Box::new(call)))
        .await
        .unwrap();
    assert_matches!(response, AppResponse::ZomeCalled(_));
}

/// At `max_concurrent_zome_calls`, a call that declares a deadline is refused
/// immediately rather than queued, and is admitted again once the running call
/// has finished.
#[tokio::test(flavor = "multi_thread")]
async fn at_the_ceiling_a_deadlined_call_is_refused_then_admitted_again() {
    let fixture = setup(Some(1)).await;
    let Fixture {
        conductor,
        cell,
        tx,
        entered,
        ..
    } = &fixture;

    // Occupy the only slot. This call declares a deadline longer than the work
    // it is doing, so it is admitted and runs to completion.
    let occupying = signed_call(conductor, cell, "slow").await;
    let occupier = {
        let tx = tx.clone();
        tokio::spawn(async move {
            tx.request::<_, AppResponse>(AppRequest::CallZomeWithDeadline {
                call: Box::new(occupying),
                deadline_ms: (SLOW_CALL + RESPONSE_BUDGET).as_millis() as u32,
            })
            .await
            .unwrap()
        })
    };
    wait_until_in_flight(entered).await;

    // A second call that declares a deadline gets an immediate, actionable
    // refusal rather than a queue slot it could not use.
    let refused = signed_call(conductor, cell, "fast").await;
    let started = Instant::now();
    let response: AppResponse = tx
        .request(AppRequest::CallZomeWithDeadline {
            call: Box::new(refused),
            deadline_ms: DEADLINE.as_millis() as u32,
        })
        .await
        .unwrap();
    assert_matches!(
        response,
        AppResponse::Error(ExternalApiWireError::ZomeCallRefused(_))
    );
    assert!(
        started.elapsed() < DEADLINE,
        "a refusal must arrive without spending the caller's deadline"
    );

    // Once the occupying call finishes, the slot is available again.
    let response = occupier.await.unwrap();
    assert_matches!(response, AppResponse::ZomeCalled(_));

    let admitted = signed_call(conductor, cell, "fast").await;
    let response: AppResponse = tx
        .request(AppRequest::CallZomeWithDeadline {
            call: Box::new(admitted),
            deadline_ms: RESPONSE_BUDGET.as_millis() as u32,
        })
        .await
        .unwrap();
    assert_matches!(response, AppResponse::ZomeCalled(_));
}

/// The ceiling is invisible to a client that declared no deadline: its call is
/// queued as before and eventually succeeds.
#[tokio::test(flavor = "multi_thread")]
async fn at_the_ceiling_a_call_without_a_deadline_is_still_queued() {
    let fixture = setup(Some(1)).await;
    let Fixture {
        conductor,
        cell,
        tx,
        entered,
        ..
    } = &fixture;

    let occupying = signed_call(conductor, cell, "slow").await;
    let occupier = {
        let tx = tx.clone();
        tokio::spawn(async move {
            tx.request::<_, AppResponse>(AppRequest::CallZome(Box::new(occupying)))
                .await
                .unwrap()
        })
    };
    wait_until_in_flight(entered).await;

    // No deadline declared, so no refusal: this is an existing client, and it
    // has no code to handle one.
    let queued = signed_call(conductor, cell, "fast").await;
    let response: AppResponse = tx
        .request(AppRequest::CallZome(Box::new(queued)))
        .await
        .unwrap();
    assert_matches!(response, AppResponse::ZomeCalled(_));

    assert_matches!(occupier.await.unwrap(), AppResponse::ZomeCalled(_));
}

/// Abandoning a call releases its in-flight slot at the moment the deadline
/// fires, not when the abandoned work eventually finishes.
///
/// This is the resource-release property the whole change rests on, observed at
/// the layer the conductor controls: the next caller is admitted while the
/// abandoned call's zome function is demonstrably still running.
#[tokio::test(flavor = "multi_thread")]
async fn an_abandoned_call_releases_its_slot_immediately() {
    let fixture = setup(Some(1)).await;
    let Fixture {
        conductor,
        cell,
        tx,
        entered,
        ..
    } = &fixture;

    let abandoned = signed_call(conductor, cell, "slow").await;
    let response: AppResponse = tx
        .request(AppRequest::CallZomeWithDeadline {
            call: Box::new(abandoned),
            deadline_ms: DEADLINE.as_millis() as u32,
        })
        .await
        .unwrap();
    assert_matches!(
        response,
        AppResponse::Error(ExternalApiWireError::ZomeCallDeadlineExceeded(_))
    );

    // The abandoned call's body is still executing: it was not interrupted, and
    // it cannot have finished, because it sleeps for far longer than this test
    // has been running. If the slot were tied to the work rather than to the
    // wait, the next call would be refused.
    assert!(
        entered.load(Ordering::SeqCst),
        "the abandoned call never started, so this proves nothing"
    );

    let next = signed_call(conductor, cell, "fast").await;
    let started = Instant::now();
    let response: AppResponse = tx
        .request(AppRequest::CallZomeWithDeadline {
            call: Box::new(next),
            deadline_ms: RESPONSE_BUDGET.as_millis() as u32,
        })
        .await
        .unwrap();
    assert_matches!(response, AppResponse::ZomeCalled(_));
    assert!(
        started.elapsed() < SLOW_CALL,
        "the slot was not released until the abandoned work finished"
    );
}
