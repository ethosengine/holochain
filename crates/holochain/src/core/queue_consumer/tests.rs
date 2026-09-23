use super::*;
use crate::core::metrics::create_workflow_run_metrics;
use crate::core::workflow::publish_dht_ops_workflow::publish_dht_ops_workflow;
use ::fixt::*;
use holo_hash::fixt::ActionHashFixturator;
use holo_hash::fixt::AgentPubKeyFixturator;
use holo_hash::fixt::DnaHashFixturator;
use holo_hash::fixt::EntryHashFixturator;
use holochain_conductor_api::conductor::ConductorTuningParams;
use holochain_state::test_utils::test_dht_store;
use std::fs;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::sync::{Barrier, Mutex as StdMutex};
use std::time::Instant as StdInstant;
use tracing_subscriber::fmt::MakeWriter;

#[derive(Clone, Default)]
struct TraceBuffer(Arc<StdMutex<Vec<u8>>>);

struct TraceBufferWriter(Arc<StdMutex<Vec<u8>>>);

impl<'a> MakeWriter<'a> for TraceBuffer {
    type Writer = TraceBufferWriter;

    fn make_writer(&'a self) -> Self::Writer {
        TraceBufferWriter(self.0.clone())
    }
}

impl Write for TraceBufferWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl TraceBuffer {
    fn output(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

fn captured_gate(window: Duration, event_limit: u64) -> (Arc<WorkflowDiagnosticGate>, TraceBuffer) {
    let output = TraceBuffer::default();
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_max_level(tracing::Level::TRACE)
        .with_writer(output.clone())
        .finish();
    let gate = tracing::subscriber::with_default(subscriber, || {
        WorkflowDiagnosticGate::start(window, 1, event_limit).unwrap()
    });
    (gate, output)
}

fn captured_gate_without_native_witnesses() -> (Arc<WorkflowDiagnosticGate>, TraceBuffer) {
    let output = TraceBuffer::default();
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_max_level(tracing::Level::TRACE)
        .with_writer(output.clone())
        .finish();
    let gate = tracing::subscriber::with_default(subscriber, || {
        WorkflowDiagnosticGate::start_with_witnesses(Duration::from_secs(60), 60, 0, None, None)
            .unwrap()
    });
    (gate, output)
}

fn wait_for_trace(output: &TraceBuffer, needle: &str) -> String {
    let deadline = StdInstant::now() + Duration::from_secs(2);
    loop {
        let captured = output.output();
        if captured.contains(needle) {
            return captured;
        }
        assert!(
            StdInstant::now() < deadline,
            "missing trace {needle}: {captured}"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[cfg(unix)]
fn workflow_private_directory(label: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "holochain-workflow-controller-{label}-{}-{:?}",
        std::process::id(),
        SystemTime::now()
    ));
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    path
}

#[test]
fn trigger_classes_are_bounded() {
    assert_eq!(trigger_class("init"), "init");
    assert_eq!(trigger_class("retrigger"), "retrigger");
    assert_eq!(trigger_class("retry after error"), "retry");
    assert_eq!(trigger_class("resume_loop_now"), "resume");
    assert_eq!(trigger_class("a caller-specific context"), "external");
}

#[tokio::test]
async fn wakeup_reports_only_observed_coalescing() {
    let (tx, mut rx) = TriggerSender::new();
    tx.trigger(&"first");
    tx.trigger(&"second");

    let wake = rx.listen_with_reason().await.unwrap();
    assert!(matches!(
        wake,
        TriggerWake::Notification {
            class: "external",
            coalesced: true
        }
    ));
}

#[test]
fn workflow_run_guards_finish_exactly_once_and_balance_inflight() {
    let metrics =
        create_workflow_run_metrics("test_workflow".to_string(), Arc::new(fixt!(DnaHash)));

    metrics.started("external").finish("complete");
    {
        let _dropped = metrics.started("loop");
    }

    assert_eq!(metrics.test_counts(), (2, 2, 0, 1, 1));
}

#[test]
fn cell_trace_token_is_shared_only_while_cell_is_live() {
    let cell_id = CellId::new(fixt!(DnaHash), fixt!(AgentPubKey));
    let (first, first_lease) = cell_trace_token(&cell_id);
    let (second, second_lease) = cell_trace_token(&cell_id);
    assert_eq!(first, second);

    drop(first_lease);
    drop(second_lease);
    let (replacement, _replacement_lease) = cell_trace_token(&cell_id);
    assert_ne!(first, replacement);
}

#[test]
fn workflow_diagnostic_gate_defaults_off_without_a_timer_or_trace_dispatch() {
    assert!(WorkflowDiagnosticGate::start_if_enabled(0, 10, true).is_none());
    assert!(WorkflowDiagnosticGate::start_if_enabled(1, 10, false).is_none());
}

#[cfg(unix)]
#[test]
fn workflow_controller_rearms_privately_and_old_close_cannot_mutate_new_generation() {
    let directory = workflow_private_directory("sequential");
    let controller = Arc::new(WorkflowDiagnosticController::new(&directory).unwrap());
    let request = |nonce: &str| CaptureDiagnosticRequest {
        schema_version: DIAGNOSTIC_CAPTURE_SCHEMA_VERSION,
        nonce: nonce.into(),
        requested_seconds: 60,
    };

    let first = controller.admit(request("first"), true);
    assert_eq!(first.outcome, CaptureAdmissionOutcome::Admitted);
    assert_eq!(first.generation, Some(1));
    let first_gate = controller.active().unwrap();
    assert_eq!(
        controller.admit(request("second"), true).outcome,
        CaptureAdmissionOutcome::RefusedBusy
    );
    first_gate.close("test_close", 0);
    assert_eq!(
        controller.admit(request("first"), true).outcome,
        CaptureAdmissionOutcome::RefusedDuplicateNonce
    );

    let second = controller.admit(request("second"), true);
    assert_eq!(second.outcome, CaptureAdmissionOutcome::Admitted);
    assert_eq!(second.generation, Some(2));
    first_gate.close("late_old_timer", 0);
    assert_eq!(controller.active().unwrap().generation, 2);
    controller.active().unwrap().close("test_close", 0);

    for response in [first, second] {
        let basename = response.output_basename.unwrap();
        let path = directory.join(&basename);
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let rows: Vec<serde_json::Value> = fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(rows.len(), 2);
        assert_eq!(
            rows[0]["fields"]["event"],
            "workflow.diagnostics.window_started"
        );
        assert_eq!(
            rows[1]["fields"]["event"],
            "workflow.diagnostics.window_closed"
        );
        assert_eq!(rows[0]["fields"]["output_basename"], basename);
    }
    fs::remove_dir_all(directory).unwrap();
}

#[cfg(unix)]
#[test]
fn workflow_controller_refuses_missing_trace_and_strict_caps_without_artifacts() {
    let directory = workflow_private_directory("refusals");
    let controller = Arc::new(WorkflowDiagnosticController::new(&directory).unwrap());
    let response = controller.admit(
        CaptureDiagnosticRequest {
            schema_version: DIAGNOSTIC_CAPTURE_SCHEMA_VERSION,
            nonce: "no-trace".into(),
            requested_seconds: 1,
        },
        false,
    );
    assert_eq!(
        response.outcome,
        CaptureAdmissionOutcome::RefusedTraceUnavailable
    );
    assert!(response.output_basename.is_none());
    for request in [
        CaptureDiagnosticRequest {
            schema_version: 0,
            nonce: "bad-version".into(),
            requested_seconds: 1,
        },
        CaptureDiagnosticRequest {
            schema_version: DIAGNOSTIC_CAPTURE_SCHEMA_VERSION,
            nonce: "../path".into(),
            requested_seconds: 1,
        },
        CaptureDiagnosticRequest {
            schema_version: DIAGNOSTIC_CAPTURE_SCHEMA_VERSION,
            nonce: "too-long".into(),
            requested_seconds: 901,
        },
    ] {
        let response = controller.admit(request, true);
        assert_eq!(
            response.outcome,
            CaptureAdmissionOutcome::RefusedInvalidRequest
        );
        assert!(response.nonce.len() <= 64);
    }
    assert_eq!(fs::read_dir(&directory).unwrap().count(), 0);

    controller.state.lock().unwrap().generations = WORKFLOW_DIAGNOSTIC_MAX_GENERATIONS;
    assert_eq!(
        controller
            .admit(
                CaptureDiagnosticRequest {
                    schema_version: DIAGNOSTIC_CAPTURE_SCHEMA_VERSION,
                    nonce: "budget".into(),
                    requested_seconds: 1,
                },
                true,
            )
            .outcome,
        CaptureAdmissionOutcome::RefusedGenerationBudget
    );
    fs::remove_dir_all(directory).unwrap();
}

#[cfg(unix)]
#[test]
fn workflow_startup_refusal_is_not_installed_as_enabled() {
    let directory = workflow_private_directory("startup-refusal");
    let slot = configured_workflow_slot(&directory, Some(1), false);
    assert!(matches!(
        slot,
        WorkflowControllerSlot::Failed(CaptureAdmissionOutcome::RefusedTraceUnavailable)
    ));
    assert_eq!(fs::read_dir(&directory).unwrap().count(), 0);
    fs::remove_dir_all(directory).unwrap();
}

#[cfg(unix)]
#[test]
fn workflow_private_writer_latches_caps_and_counts_successful_bytes() {
    let directory = workflow_private_directory("writer-latch");
    let path = directory.join("writer.jsonl");
    let output = Arc::new(StdMutex::new(WorkflowPrivateOutput {
        file: File::create(&path).unwrap(),
        bytes_written: 0,
        failed: false,
    }));
    let mut writer = WorkflowPrivateWriter {
        output: Arc::clone(&output),
    };
    assert_eq!(writer.write(b"ok").unwrap(), 2);
    assert_eq!(output.lock().unwrap().bytes_written, 2);

    output.lock().unwrap().bytes_written = WORKFLOW_DIAGNOSTIC_MAX_OUTPUT_BYTES;
    assert!(writer.write(b"overflow").is_err());
    assert!(output.lock().unwrap().failed);
    assert!(writer.write(b"later").is_err());
    assert_eq!(fs::read(&path).unwrap(), b"ok");
    fs::remove_dir_all(directory).unwrap();
}

#[cfg(unix)]
#[test]
fn workflow_output_failure_cannot_serialize_a_green_terminal() {
    let directory = workflow_private_directory("terminal-latch");
    let controller = Arc::new(WorkflowDiagnosticController::new(&directory).unwrap());
    let admission = controller.admit(
        CaptureDiagnosticRequest {
            schema_version: DIAGNOSTIC_CAPTURE_SCHEMA_VERSION,
            nonce: "terminal-latch".into(),
            requested_seconds: 60,
        },
        true,
    );
    assert_eq!(admission.outcome, CaptureAdmissionOutcome::Admitted);
    let gate = controller.active().unwrap();
    gate.private_output.as_ref().unwrap().lock().unwrap().failed = true;
    gate.close("test_close", 0);

    let output = fs::read_to_string(directory.join(admission.output_basename.unwrap())).unwrap();
    assert!(output.contains("workflow.diagnostics.window_started"));
    assert!(!output.contains("workflow.diagnostics.window_closed"));
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn workflow_diagnostic_quiet_expiry_uses_the_captured_subscriber() {
    let (gate, output) = captured_gate(Duration::from_millis(30), 10);
    let captured = wait_for_trace(&output, "workflow.diagnostics.window_closed");

    assert_eq!(
        captured
            .matches("workflow.diagnostics.window_started")
            .count(),
        1
    );
    assert_eq!(
        captured
            .matches("workflow.diagnostics.window_closed")
            .count(),
        1
    );
    assert!(captured.contains("diagnostic_schema=1"));
    assert!(captured.contains("telemetry_version=1"));
    assert!(captured.contains("closure_reason=\"expiry\""));
    assert!(captured.contains("reserved_detail_events=0"));
    assert!(captured.contains("emitted_detail_events=0"));
    assert!(captured.contains("remaining_detail_events=10"));
    assert_eq!(gate.test_counts(), (0, 0, 10, 0, 0, true));

    #[cfg(target_os = "linux")]
    {
        let (started, ended) = gate.test_monotonic_times();
        let (started, ended) = (started.unwrap(), ended.unwrap());
        assert!(ended >= started);
        assert!(ended <= started + 30.0);
        let identity = gate.native_process.as_ref().unwrap();
        assert_eq!(captured.matches("native_process_schema=1").count(), 2);
        assert_eq!(
            captured
                .matches(&format!(
                    "process_start_ticks={}",
                    identity.process_start_ticks
                ))
                .count(),
            2
        );
        assert_eq!(captured.matches("boot_id=").count(), 2);
        assert_eq!(captured.matches("executable=").count(), 2);
        assert_eq!(
            captured
                .matches("monotonic_clock=\"CLOCK_MONOTONIC\"")
                .count(),
            2
        );
        assert_eq!(captured.matches("started_monotonic_ms=").count(), 2);
        assert_eq!(captured.matches("ended_monotonic_ms=").count(), 1);
    }
}

#[test]
fn workflow_diagnostic_omits_unavailable_native_witnesses() {
    let (gate, output) = captured_gate_without_native_witnesses();
    let captured = output.output();

    assert_eq!(gate.test_monotonic_times(), (None, None));
    for absent in [
        "native_process_schema=",
        "process_start_ticks=",
        "boot_id=",
        "executable=",
        "monotonic_clock=",
        "started_monotonic_ms=",
        "ended_monotonic_ms=",
    ] {
        assert!(!captured.contains(absent), "unexpected field {absent}");
    }
}

#[test]
fn workflow_diagnostic_event_cap_closes_once_and_cancels_expiry() {
    let (gate, output) = captured_gate(Duration::from_millis(200), 1);
    gate.emit_wakeup("integrate", &fixt!(DnaHash), Some(7), TriggerWake::Loop);
    std::thread::sleep(Duration::from_millis(300));
    let captured = output.output();

    assert_eq!(
        captured
            .matches("workflow.diagnostics.window_closed")
            .count(),
        1
    );
    assert!(captured.contains("closure_reason=\"event_limit\""));
    assert!(captured.contains("reserved_detail_events=1"));
    assert!(captured.contains("emitted_detail_events=1"));
    assert!(captured.contains("remaining_detail_events=0"));
    assert_eq!(gate.test_counts(), (1, 1, 0, 0, 0, true));
    #[cfg(target_os = "linux")]
    {
        let (started, ended) = gate.test_monotonic_times();
        let (started, ended) = (started.unwrap(), ended.unwrap());
        assert!(ended >= started);
        assert!(ended <= started + 200.0);
    }
}

#[test]
fn workflow_run_admission_rejection_preserves_unused_capacity() {
    let (gate, output) = captured_gate(Duration::from_secs(60), 1);
    assert!(gate
        .start_run("integrate", &fixt!(DnaHash), Some(7), TriggerWake::Loop)
        .is_none());
    let captured = output.output();

    assert_eq!(
        captured
            .matches("workflow.diagnostics.window_closed")
            .count(),
        1
    );
    assert!(captured.contains("closure_reason=\"event_limit\""));
    assert!(captured.contains("reserved_detail_events=0"));
    assert!(captured.contains("emitted_detail_events=0"));
    assert!(captured.contains("remaining_detail_events=1"));
    assert!(captured.contains("rejected_detail_events_at_close=2"));
    assert_eq!(gate.test_counts(), (0, 0, 1, 0, 0, true));
}

#[test]
fn workflow_run_trace_pairs_terminal_outcomes_exactly_once() {
    let (gate, output) = captured_gate(Duration::from_secs(60), 4);
    let dna_hash = fixt!(DnaHash);
    let run_ids = Arc::new(StdMutex::new(Vec::new()));
    let captured_run_ids = run_ids.clone();
    tracing::dispatcher::with_default(&gate.dispatch, || {
        let mut completed = gate
            .start_run("integrate", &dna_hash, Some(7), TriggerWake::Loop)
            .unwrap();
        captured_run_ids.lock().unwrap().push(completed.run_id);
        completed.finish("complete");
        drop(completed);

        let dropped = gate
            .start_run("integrate", &dna_hash, Some(7), TriggerWake::Loop)
            .unwrap();
        captured_run_ids.lock().unwrap().push(dropped.run_id);
        drop(dropped);
    });
    let output = output.output();

    assert_eq!(output.matches("workflow.run.start").count(), 2);
    assert_eq!(output.matches("workflow.run.finish").count(), 2);
    assert_eq!(output.matches("outcome=\"complete\"").count(), 1);
    assert_eq!(output.matches("outcome=\"dropped\"").count(), 1);
    for run_id in run_ids.lock().unwrap().iter() {
        assert_eq!(output.matches(&format!("run_id={run_id}")).count(), 2);
    }
    assert_eq!(gate.test_counts(), (4, 4, 0, 2, 2, true));
    assert!(output.contains("admitted_runs=2"));
    assert!(output.contains("finished_runs_before_close=2"));
    assert!(output.contains("in_flight_runs_at_close=0"));
    assert!(output.contains("censored_in_flight_runs=0"));
}

#[test]
fn workflow_run_trace_expiry_censors_inflight_and_late_finish_cannot_mutate_close() {
    let (gate, output) = captured_gate(Duration::from_millis(100), 2);
    let dna_hash = fixt!(DnaHash);
    let trace = gate
        .start_run("integrate", &dna_hash, Some(7), TriggerWake::Loop)
        .unwrap();
    let closed = wait_for_trace(&output, "workflow.diagnostics.window_closed");
    let counts_at_close = gate.test_counts();
    drop(trace);
    let output = output.output();

    assert_eq!(output.matches("workflow.run.start").count(), 1);
    assert_eq!(output.matches("workflow.run.finish").count(), 0);
    assert_eq!(
        output.matches("workflow.diagnostics.window_closed").count(),
        1
    );
    assert!(closed.contains("reserved_detail_events=2"));
    assert!(closed.contains("emitted_detail_events=1"));
    assert!(closed.contains("remaining_detail_events=0"));
    assert!(closed.contains("admitted_runs=1"));
    assert!(closed.contains("finished_runs_before_close=0"));
    assert!(closed.contains("in_flight_runs_at_close=1"));
    assert!(closed.contains("censored_in_flight_runs=1"));
    assert_eq!(counts_at_close, (2, 1, 0, 1, 0, true));
    assert_eq!(gate.test_counts(), counts_at_close);
}

#[test]
fn workflow_finish_and_close_race_is_serialized() {
    let (gate, output) = captured_gate(Duration::from_secs(60), 2);
    let trace = gate
        .start_run("integrate", &fixt!(DnaHash), Some(7), TriggerWake::Loop)
        .unwrap();
    let barrier = Arc::new(Barrier::new(3));
    let close_gate = gate.clone();
    let close_barrier = barrier.clone();
    let closer = std::thread::spawn(move || {
        close_barrier.wait();
        close_gate.close("expiry", 0);
    });
    let finish_barrier = barrier.clone();
    let finisher = std::thread::spawn(move || {
        finish_barrier.wait();
        drop(trace);
    });
    barrier.wait();
    closer.join().unwrap();
    finisher.join().unwrap();

    let captured = output.output();
    let counts = gate.test_counts();
    assert_eq!(
        captured
            .matches("workflow.diagnostics.window_closed")
            .count(),
        1
    );
    assert_eq!(counts.0 + counts.2, 2);
    assert_eq!(counts.0, counts.1 + (counts.3 - counts.4));
    assert_eq!(counts.3, counts.4 + (counts.3 - counts.4));
    let close_at = captured.find("workflow.diagnostics.window_closed").unwrap();
    assert!(!captured[close_at..].contains("workflow.run.finish"));
}

#[tokio::test]
async fn test_trigger_receiver_waits_for_sender() {
    let (_tx, mut rx) = TriggerSender::new();
    let jh = tokio::spawn(async move { rx.listen().await.unwrap() });

    // This should timeout because the trigger was not called.
    let r = tokio::time::timeout(Duration::from_millis(10), jh).await;
    assert!(r.is_err());
}

#[tokio::test]
async fn test_trigger_send() {
    let (tx, mut rx) = TriggerSender::new();
    let jh = tokio::spawn(async move { rx.listen().await.unwrap() });
    tx.trigger(&"");

    // This should be joined because the trigger was called.
    let r = jh.await;
    assert!(r.is_ok());
}

#[tokio::test]
async fn test_trigger_only_permits_single_trigger() {
    holochain_trace::test_run();

    let (tx, mut rx) = TriggerSender::new();
    let jh = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        rx.listen().await.unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
        rx.listen().await.unwrap()
    });
    // Calling trigger twice before a listen should only
    // cause one listen to progress.
    tx.trigger(&"");
    tx.trigger(&"");

    // This should timeout because the second listen should not pass.
    let r = tokio::time::timeout(Duration::from_millis(100), jh).await;
    assert!(r.is_err());
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn test_trigger_back_off() {
    let (tx, mut rx) =
        TriggerSender::new_with_loop(Duration::from_secs(60)..Duration::from_secs(60 * 5), false);

    // After 1m there should be one trigger.
    let timer = tokio::time::Instant::now();
    rx.listen().await.unwrap();
    assert!(
        timer.elapsed() >= Duration::from_secs(60) && timer.elapsed() < Duration::from_secs(61)
    );

    // After 2m there should be one trigger.
    let timer = tokio::time::Instant::now();
    rx.listen().await.unwrap();
    assert!(
        timer.elapsed() >= Duration::from_secs(60 * 2)
            && timer.elapsed() < Duration::from_secs(60 * 2 + 1)
    );

    // After 4m there should be one trigger.
    let timer = tokio::time::Instant::now();
    rx.listen().await.unwrap();
    assert!(
        timer.elapsed() >= Duration::from_secs(60 * 4)
            && timer.elapsed() < Duration::from_secs(60 * 4 + 1)
    );

    // After 5m there should be one trigger.
    let timer = tokio::time::Instant::now();
    rx.listen().await.unwrap();
    assert!(
        timer.elapsed() >= Duration::from_secs(60 * 5)
            && timer.elapsed() < Duration::from_secs(60 * 5 + 1)
    );

    // After 5m there should be another trigger.
    let timer = tokio::time::Instant::now();
    rx.listen().await.unwrap();
    assert!(
        timer.elapsed() >= Duration::from_secs(60 * 5)
            && timer.elapsed() < Duration::from_secs(60 * 5 + 1)
    );

    tx.reset_back_off();

    // After 1m there should be one trigger.
    let timer = tokio::time::Instant::now();
    rx.listen().await.unwrap();
    assert!(
        timer.elapsed() >= Duration::from_secs(60) && timer.elapsed() < Duration::from_secs(61)
    );
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn test_trigger_loop() {
    let (_tx, mut rx) =
        TriggerSender::new_with_loop(Duration::from_secs(60)..Duration::from_secs(60), false);

    for _ in 0..100 {
        // After 1m there should be one trigger.
        let timer = tokio::time::Instant::now();
        rx.listen().await.unwrap();
        assert!(
            timer.elapsed() >= Duration::from_secs(60) && timer.elapsed() < Duration::from_secs(61)
        );
    }
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn test_reset_on_trigger() {
    let (tx, mut rx) =
        TriggerSender::new_with_loop(Duration::from_secs(60)..Duration::from_secs(60 * 5), true);

    // After 1m there should be one trigger.
    let timer = tokio::time::Instant::now();
    rx.listen().await.unwrap();
    assert!(
        timer.elapsed() >= Duration::from_secs(60) && timer.elapsed() < Duration::from_secs(61)
    );

    // After 2m there should be one trigger.
    let timer = tokio::time::Instant::now();
    rx.listen().await.unwrap();
    assert!(
        timer.elapsed() >= Duration::from_secs(60 * 2)
            && timer.elapsed() < Duration::from_secs(60 * 2 + 1)
    );

    tx.trigger(&"");

    // There should be one trigger immediately.
    let timer = tokio::time::Instant::now();
    rx.listen().await.unwrap();
    assert!(timer.elapsed() < Duration::from_secs(1));

    // After 1m there should be one trigger.
    let timer = tokio::time::Instant::now();
    rx.listen().await.unwrap();
    assert!(
        timer.elapsed() >= Duration::from_secs(60) && timer.elapsed() < Duration::from_secs(61)
    );
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn test_pause_resume() {
    let (tx, mut rx) =
        TriggerSender::new_with_loop(Duration::from_secs(60)..Duration::from_secs(60), false);

    for _ in 0..10 {
        // After 1m there should be one trigger.
        let timer = tokio::time::Instant::now();
        rx.listen().await.unwrap();
        assert!(
            timer.elapsed() >= Duration::from_secs(60) && timer.elapsed() < Duration::from_secs(61)
        );
    }

    tx.pause_loop();

    // After 1hr there should be no trigger.
    let r = tokio::time::timeout(Duration::from_secs(60 * 60), rx.listen()).await;
    assert!(r.is_err());

    tx.resume_loop();

    // After 1m there should be one trigger.
    let timer = tokio::time::Instant::now();
    rx.listen().await.unwrap();
    assert!(
        timer.elapsed() >= Duration::from_secs(60) && timer.elapsed() < Duration::from_secs(61)
    );
}

#[tokio::test]
#[ignore = "flaky due to dependence on timing"]
async fn test_concurrency() {
    // - Trigger overrides already waiting listen.
    let (tx, mut rx) =
        TriggerSender::new_with_loop(Duration::from_millis(60)..Duration::from_millis(60), false);
    let timer = tokio::time::Instant::now();
    let jh = tokio::spawn(async move { rx.listen().await.unwrap() });
    // - Make sure listen has been called already.
    tokio::time::sleep(Duration::from_millis(10)).await;
    tx.trigger(&"");
    jh.await.unwrap();
    assert!(timer.elapsed() < Duration::from_millis(20));

    // - Calling resume_loop_now doesn't override waiting listen when loop is running.
    let (tx, mut rx) =
        TriggerSender::new_with_loop(Duration::from_millis(60)..Duration::from_millis(60), false);
    let timer = tokio::time::Instant::now();
    let jh = tokio::spawn(async move { rx.listen().await.unwrap() });
    // - Make sure listen has been called already.
    tokio::time::sleep(Duration::from_millis(10)).await;
    tx.resume_loop_now();
    jh.await.unwrap();
    assert!(timer.elapsed() >= Duration::from_millis(60));

    // - Calling resume_loop_now does override waiting listen when loop is paused.
    let (tx, mut rx) =
        TriggerSender::new_with_loop(Duration::from_millis(60)..Duration::from_millis(60), false);
    tx.pause_loop();
    let timer = tokio::time::Instant::now();
    let jh = tokio::spawn(async move { rx.listen().await.unwrap() });
    // - Make sure listen has been called already.
    tokio::time::sleep(Duration::from_millis(10)).await;
    tx.resume_loop_now();
    jh.await.unwrap();
    assert!(timer.elapsed() < Duration::from_millis(20));
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn publish_loop() {
    let action = Action {
        header: ActionHeader {
            author: fixt!(AgentPubKey),
            timestamp: Timestamp::now(),
            action_seq: 5,
            prev_action: Some(fixt!(ActionHash)),
        },
        data: ActionData::Create(CreateData {
            entry_type: EntryType::App(AppEntryDef::new(
                0.into(),
                0.into(),
                EntryVisibility::Public,
            )),
            entry_hash: fixt!(EntryHash),
        }),
    };
    let author = action.author().clone();
    let signature = Signature(vec![3; SIGNATURE_BYTES].try_into().unwrap());
    let signed = SignedAction::new(action, signature);
    let op = DhtOpHashed::from_content_sync(DhtOp::from(ChainOp::AgentActivity(signed)));
    let op_hash = op.to_hash();

    // The DhtStore's sqlx pool has an acquire_timeout driven by tokio time.
    // With start_paused = true the auto-advance fires that timer before the
    // `spawn_blocking` connection setup finishes, so resume real time around
    // every DHT store operation (creation, seeding, and each workflow call).
    tokio::time::resume();
    let dht_store = test_dht_store(fixt!(DnaHash)).await;
    // Seed the op as an integrated, self-authored op ready to publish.
    dht_store
        .test_insert_authored_chain_op(op, None, None, None)
        .await
        .unwrap();
    tokio::time::pause();

    // The minimum publish interval, expressed as the "published this long ago"
    // timestamp that makes an op eligible to publish again.
    let interval = ConductorTuningParams::default().min_publish_interval();
    let published_long_ago = Timestamp::from_micros(
        Timestamp::now().as_micros() - interval.as_micros() as i64 - 1_000_000,
    );

    let mut dna_network = MockHolochainP2pDnaT::new();
    let (tx, mut op_published) = tokio::sync::mpsc::channel(100);
    dna_network.expect_publish().returning(move |_, _, _, _| {
        tx.try_send(()).unwrap();
        Ok(())
    });
    let dna_network = Arc::new(dna_network);

    let (ts, mut trigger_recv) =
        TriggerSender::new_with_loop(Duration::from_secs(60)..Duration::from_secs(60 * 5), true);

    let run_workflow = || async {
        tokio::time::resume();
        publish_dht_ops_workflow(
            dht_store.clone(),
            dna_network.clone(),
            ts.clone(),
            author.clone(),
            ConductorTuningParams::default().min_publish_interval(),
        )
        .await
        .unwrap();
        tokio::time::pause();
    };

    let timer = tokio::time::Instant::now();
    trigger_recv.listen().await.unwrap();
    // - Publish runs after a 1m.
    assert!(
        timer.elapsed() >= Duration::from_secs(60) && timer.elapsed() < Duration::from_secs(61)
    );

    run_workflow().await;

    // - Op was published.
    op_published.recv().await.unwrap();

    let timer = tokio::time::Instant::now();
    trigger_recv.listen().await.unwrap();
    // - Publish runs again after 2m.
    assert!(
        timer.elapsed() >= Duration::from_secs(60 * 2)
            && timer.elapsed() < Duration::from_secs(60 * 2 + 1)
    );
    run_workflow().await;

    // - But the op isn't published because it was published in the last five minutes.
    assert_eq!(
        op_published.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    );

    // - Triggering publish causes it to run again.
    ts.trigger(&"");

    let timer = tokio::time::Instant::now();
    trigger_recv.listen().await.unwrap();
    assert!(timer.elapsed() < Duration::from_secs(1));
    run_workflow().await;

    // - But still no op is published.
    assert_eq!(
        op_published.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    );

    // - Set the op's last publish time to longer ago than the interval, so it
    //   becomes eligible to publish again.
    tokio::time::resume();
    dht_store
        .test_set_chain_op_publish(&op_hash, Some(published_long_ago), None, None)
        .await
        .unwrap();
    tokio::time::pause();

    let timer = tokio::time::Instant::now();
    trigger_recv.listen().await.unwrap();
    // - Publish runs after a 1m because the trigger reset the back off.
    assert!(
        timer.elapsed() >= Duration::from_secs(60) && timer.elapsed() < Duration::from_secs(61)
    );

    run_workflow().await;

    // - The data is published because of the last publish time being greater then the interval.
    op_published.recv().await.unwrap();

    // - Set receipts complete.
    tokio::time::resume();
    dht_store
        .mark_chain_op_receipts_complete(&op_hash)
        .await
        .unwrap();
    tokio::time::pause();

    let timer = tokio::time::Instant::now();
    trigger_recv.listen().await.unwrap();
    // - Publish runs after another 2ms.
    assert!(
        timer.elapsed() >= Duration::from_secs(60 * 2)
            && timer.elapsed() < Duration::from_secs(60 * 2 + 1)
    );
    run_workflow().await;

    // - But no op is published because receipts are complete.
    assert_eq!(
        op_published.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    );

    // - Confirm the publish loop doesn't run again.
    let r = tokio::time::timeout(Duration::from_secs(60 * 100), trigger_recv.listen()).await;
    assert!(r.is_err());
    assert_eq!(
        op_published.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    );

    // - Set the op's last publish time to longer ago than the interval and
    //   mark receipts as not complete, so it becomes eligible again.
    tokio::time::resume();
    dht_store
        .test_set_chain_op_publish(&op_hash, Some(published_long_ago), None, None)
        .await
        .unwrap();
    tokio::time::pause();

    // - Publish runs due to a trigger.
    ts.trigger(&"");
    let timer = tokio::time::Instant::now();
    trigger_recv.listen().await.unwrap();
    assert!(timer.elapsed() < Duration::from_secs(1));
    run_workflow().await;

    // - Op was published.
    op_published.recv().await.unwrap();

    let timer = tokio::time::Instant::now();
    trigger_recv.listen().await.unwrap();
    // - Publish is looping again starting at 1m.
    assert!(
        timer.elapsed() >= Duration::from_secs(60) && timer.elapsed() < Duration::from_secs(61)
    );

    run_workflow().await;
    // - The op is not published because of the time interval.
    assert_eq!(
        op_published.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    );
}
