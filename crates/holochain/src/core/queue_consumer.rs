//! Manages the spawning of tasks which process the various work queues in
//! the system, as well as notifying subsequent queue processors to pick up the
//! work that was left off.
//!
//! The following table lays out the queues and the workflows that consume them,
//! as well as the follow-up workflows. A "source" queue is a database which
//! feeds data to the workflow, and a "destination" queue is a database which
//! said workflow writes to as part of its processing of its source queue.
//!
//! | workflow       | source queue     | dest. queue      | notifies       |
//! |----------------|------------------|------------------|----------------|
//! |                        **gossip path**                                |
//! | HandleGossip   | *n/a*            | ValidationQueue  | SysValidation  |
//! | SysValidation  | ValidationQueue  | ValidationQueue  | AppValidation  |
//! | AppValidation  | ValidationQueue  | ValidationQueue  | DhtOpIntegr.   |
//! |                       **authoring path**                              |
//! | CallZome       | *n/a*            | ChainSequence    | ProduceDhtOps  |
//! | ProduceDhtOps  | ChainSequence    | Auth'd + IntQ †  | DhtOpIntegr.   |
//! |                 **integration, common to both paths**                 |
//! | DhtOpIntegr.   | IntegrationLimbo | IntegratedDhtOps | SysVal + VR    |
//! | ValReceipt.    | IntegratedDhtOps | IntegratedDhtOps | *n/a           |
//! | Publish        | AuthoredDhtOps   | *n/a*            | *n/a*          |
//!
//! († Auth'd + IntQ is short for: AuthoredDhtOps + IntegrationLimbo)
//!
//! Implicitly, every workflow also writes to its own source queue, i.e. to
//! remove the item it has just processed.

use super::metrics::create_workflow_run_metrics;
use super::workflow::app_validation_workflow::AppValidationWorkspace;
use super::workflow::sys_validation_workflow::SysValidationWorkspace;
use super::workflow::{WorkflowError, WorkflowResult};
use crate::conductor::conductor::{RwShare, StopReceiver};
use crate::conductor::manager::TaskManagerClient;
use crate::conductor::space::Space;
use crate::conductor::ConductorHandle;
use crate::conductor::{error::ConductorError, manager::ManagedTaskResult};
use derive_more::Display;
use futures::future::Either;
use futures::{Future, Stream, StreamExt};
use holochain_conductor_api::{
    CaptureAdmissionCounters, CaptureAdmissionOutcome, CaptureDiagnosticRequest,
    CaptureDiagnosticResponse, CaptureWindowState, DiagnosticCaptureFamily, DiagnosticWindowStatus,
    DIAGNOSTIC_CAPTURE_SCHEMA_VERSION,
};
use holochain_p2p::*;
use holochain_trace::diagnostic_identity::{kernel_monotonic_ms, DiagnosticProcessIdentity};
use holochain_trace::private_capture::{valid_capture_nonce, PrivateCaptureDirectory};
use holochain_types::prelude::*;
use publish_dht_ops_consumer::*;
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Write};
use std::ops::Range;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex, OnceLock, TryLockError, Weak};
use std::thread;
use std::time::{Duration, Instant};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast;
use tracing::Dispatch;
use tracing_subscriber::{filter::filter_fn, fmt::MakeWriter, prelude::*};

static NEXT_CELL_TRACE_TOKEN: AtomicU64 = AtomicU64::new(1);
static NEXT_WORKFLOW_RUN_ID: AtomicU64 = AtomicU64::new(1);
static CELL_TRACE_TOKENS: OnceLock<Mutex<HashMap<CellId, (u64, Weak<()>)>>> = OnceLock::new();
const WORKFLOW_TELEMETRY_VERSION: u8 = 1;
const WORKFLOW_DIAGNOSTIC_MAX_SECONDS: u64 = 15 * 60;
const WORKFLOW_DIAGNOSTIC_MAX_EVENTS: u64 = 10_000;
const WORKFLOW_DIAGNOSTIC_ENV: &str = "HOLOCHAIN_WORKFLOW_DIAGNOSTICS_SECONDS";
const WORKFLOW_DIAGNOSTIC_DIRECTORY_ENV: &str = "HOLOCHAIN_WORKFLOW_DIAGNOSTICS_DIR";
const WORKFLOW_DIAGNOSTIC_MAX_GENERATIONS: u8 = 16;
const WORKFLOW_DIAGNOSTIC_MAX_OUTPUT_BYTES: usize = 2 * 1024 * 1024;
const WORKFLOW_DIAGNOSTIC_TARGET: &str = "holochain::diagnostics::workflow";
const WORKFLOW_DIAGNOSTIC_SCOPE: &str = "queue_consumer_workflow_tracing_attempts";
const WORKFLOW_DIAGNOSTIC_LIMITATIONS: &str =
    "not_persisted_proof;not_cpu_coverage;not_full_workflow_coverage";
static WORKFLOW_DIAGNOSTICS: OnceLock<WorkflowControllerSlot> = OnceLock::new();
static WORKFLOW_ADMISSION_COUNTERS: WorkflowAdmissionCounterAtoms =
    WorkflowAdmissionCounterAtoms::new();

enum WorkflowControllerSlot {
    Disabled,
    Failed(CaptureAdmissionOutcome),
    Enabled(Arc<WorkflowDiagnosticController>),
}

struct WorkflowDiagnosticController {
    directory: PrivateCaptureDirectory,
    producer_id: String,
    state: Mutex<WorkflowControllerState>,
}

#[derive(Default)]
struct WorkflowControllerState {
    generations: u8,
    retained_nonces: std::collections::BTreeSet<String>,
    active: Option<Arc<WorkflowDiagnosticGate>>,
}

struct WorkflowAdmissionCounterAtoms {
    admitted: AtomicU64,
    refused_disabled: AtomicU64,
    refused_busy: AtomicU64,
    refused_duplicate_nonce: AtomicU64,
    refused_generation_budget: AtomicU64,
    refused_invalid_request: AtomicU64,
    refused_trace_unavailable: AtomicU64,
    refused_io: AtomicU64,
}

impl WorkflowAdmissionCounterAtoms {
    const fn new() -> Self {
        Self {
            admitted: AtomicU64::new(0),
            refused_disabled: AtomicU64::new(0),
            refused_busy: AtomicU64::new(0),
            refused_duplicate_nonce: AtomicU64::new(0),
            refused_generation_budget: AtomicU64::new(0),
            refused_invalid_request: AtomicU64::new(0),
            refused_trace_unavailable: AtomicU64::new(0),
            refused_io: AtomicU64::new(0),
        }
    }

    fn increment(&self, outcome: CaptureAdmissionOutcome) {
        let counter = match outcome {
            CaptureAdmissionOutcome::Admitted => &self.admitted,
            CaptureAdmissionOutcome::RefusedDisabled => &self.refused_disabled,
            CaptureAdmissionOutcome::RefusedBusy => &self.refused_busy,
            CaptureAdmissionOutcome::RefusedDuplicateNonce => &self.refused_duplicate_nonce,
            CaptureAdmissionOutcome::RefusedGenerationBudget => &self.refused_generation_budget,
            CaptureAdmissionOutcome::RefusedInvalidRequest => &self.refused_invalid_request,
            CaptureAdmissionOutcome::RefusedTraceUnavailable => &self.refused_trace_unavailable,
            CaptureAdmissionOutcome::RefusedIo => &self.refused_io,
        };
        let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            Some(value.saturating_add(1))
        });
    }

    fn snapshot(&self) -> CaptureAdmissionCounters {
        let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        CaptureAdmissionCounters {
            admitted: load(&self.admitted),
            refused_disabled: load(&self.refused_disabled),
            refused_busy: load(&self.refused_busy),
            refused_duplicate_nonce: load(&self.refused_duplicate_nonce),
            refused_generation_budget: load(&self.refused_generation_budget),
            refused_invalid_request: load(&self.refused_invalid_request),
            refused_trace_unavailable: load(&self.refused_trace_unavailable),
            refused_io: load(&self.refused_io),
        }
    }
}

#[derive(Clone)]
struct WorkflowPrivateMakeWriter {
    output: Arc<Mutex<WorkflowPrivateOutput>>,
}

struct WorkflowPrivateOutput {
    file: File,
    bytes_written: usize,
    failed: bool,
}

struct WorkflowPrivateWriter {
    output: Arc<Mutex<WorkflowPrivateOutput>>,
}

impl<'writer> MakeWriter<'writer> for WorkflowPrivateMakeWriter {
    type Writer = WorkflowPrivateWriter;

    fn make_writer(&'writer self) -> Self::Writer {
        WorkflowPrivateWriter {
            output: Arc::clone(&self.output),
        }
    }
}

impl Write for WorkflowPrivateWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut output = self
            .output
            .lock()
            .map_err(|_| io::Error::other("private diagnostic output lock poisoned"))?;
        if output.failed {
            return Err(io::Error::other("private diagnostic output already failed"));
        }
        let remaining = WORKFLOW_DIAGNOSTIC_MAX_OUTPUT_BYTES.saturating_sub(output.bytes_written);
        if bytes.len() > remaining {
            output.failed = true;
            return Err(io::Error::other(
                "private diagnostic output byte cap reached",
            ));
        }
        let mut written = 0;
        while written < bytes.len() {
            match output.file.write(&bytes[written..]) {
                Ok(0) => {
                    output.failed = true;
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "private diagnostic output made no progress",
                    ));
                }
                Ok(count) => {
                    output.bytes_written = output.bytes_written.saturating_add(count);
                    written += count;
                }
                Err(error) => {
                    output.failed = true;
                    return Err(error);
                }
            }
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut output = self
            .output
            .lock()
            .map_err(|_| io::Error::other("private diagnostic output lock poisoned"))?;
        if output.failed {
            return Err(io::Error::other("private diagnostic output already failed"));
        }
        if let Err(error) = output.file.flush() {
            output.failed = true;
            return Err(error);
        }
        Ok(())
    }
}

struct WorkflowDiagnosticGate {
    generation: u8,
    nonce: String,
    output_basename: String,
    owner: Weak<WorkflowDiagnosticController>,
    process_id: u32,
    producer_id: String,
    started: Instant,
    started_unix_ms: u64,
    requested_seconds: u64,
    window: Duration,
    event_limit: u64,
    native_process: Option<DiagnosticProcessIdentity>,
    started_monotonic_ms: Option<f64>,
    dispatch: Dispatch,
    private_output: Option<Arc<Mutex<WorkflowPrivateOutput>>>,
    state: Mutex<WorkflowDiagnosticState>,
}

struct PreparedWorkflowDiagnostic {
    gate: Arc<WorkflowDiagnosticGate>,
    arm_timer: mpsc::Sender<()>,
    timer: mpsc::Receiver<()>,
}

struct WorkflowDiagnosticState {
    remaining_detail_events: u64,
    reserved_detail_events: u64,
    emitted_detail_events: u64,
    admitted_runs: u64,
    finished_runs: u64,
    closed: bool,
    ended_monotonic_ms: Option<f64>,
    timer_cancel: Option<mpsc::Sender<()>>,
}

impl PreparedWorkflowDiagnostic {
    fn arm(self) -> Option<Arc<WorkflowDiagnosticGate>> {
        let Self {
            gate,
            arm_timer,
            timer,
        } = self;
        let weak_gate = Arc::downgrade(&gate);
        if thread::Builder::new()
            .name("workflow-diagnostics-expiry".to_string())
            .spawn(move || {
                // The timer starts only after the lifecycle start record is
                // serialized and, for admin admission, after the controller
                // publishes this exact generation as active.
                if timer.recv().is_err() {
                    return;
                }
                let Some(remaining) = weak_gate
                    .upgrade()
                    .map(|gate| gate.window.saturating_sub(gate.started.elapsed()))
                else {
                    return;
                };
                if matches!(
                    timer.recv_timeout(remaining),
                    Err(mpsc::RecvTimeoutError::Timeout)
                ) {
                    if let Some(gate) = weak_gate.upgrade() {
                        gate.close("expiry", 0);
                    }
                }
            })
            .is_err()
        {
            tracing::dispatcher::with_default(&gate.dispatch, || {
                tracing::warn!(
                    target: WORKFLOW_DIAGNOSTIC_TARGET,
                    event = "workflow.diagnostics.unavailable",
                    diagnostic_schema = 1_u8,
                    telemetry_version = WORKFLOW_TELEMETRY_VERSION,
                    process_id = gate.process_id,
                    producer_id = %gate.producer_id,
                    started_unix_ms = gate.started_unix_ms,
                    requested_seconds = gate.requested_seconds,
                    event_limit = gate.event_limit,
                    scope = WORKFLOW_DIAGNOSTIC_SCOPE,
                    limitations = WORKFLOW_DIAGNOSTIC_LIMITATIONS,
                    unavailable_reason = "timer_spawn_failed",
                    "bounded workflow diagnostics unavailable"
                );
            });
            return None;
        }

        if !gate.emit_started() {
            return None;
        }
        if arm_timer.send(()).is_err() {
            gate.close("timer_error", 0);
            return None;
        }
        if gate.event_limit == 0 {
            gate.close("event_limit", 0);
        }
        Some(gate)
    }
}

impl WorkflowDiagnosticGate {
    #[cfg(test)]
    fn start_if_enabled(
        requested_seconds: u64,
        event_limit: u64,
        trace_enabled: bool,
    ) -> Option<Arc<Self>> {
        if requested_seconds == 0 || !trace_enabled {
            return None;
        }
        Self::start(
            Duration::from_secs(requested_seconds),
            requested_seconds,
            event_limit,
        )
    }

    #[cfg(test)]
    fn start(window: Duration, requested_seconds: u64, event_limit: u64) -> Option<Arc<Self>> {
        Self::start_with_witnesses(
            window,
            requested_seconds,
            event_limit,
            DiagnosticProcessIdentity::capture().ok(),
            kernel_monotonic_ms().ok(),
        )
    }

    #[cfg(test)]
    fn start_with_witnesses(
        window: Duration,
        requested_seconds: u64,
        event_limit: u64,
        native_process: Option<DiagnosticProcessIdentity>,
        started_monotonic_ms: Option<f64>,
    ) -> Option<Arc<Self>> {
        let process_id = std::process::id();
        let initialized = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let initialized_nanos = initialized.as_nanos();
        let dispatch = tracing::dispatcher::get_default(Clone::clone);
        Self::start_with_dispatch(
            window,
            requested_seconds,
            event_limit,
            native_process,
            started_monotonic_ms,
            dispatch,
            Weak::new(),
            0,
            "test".into(),
            "test.jsonl".into(),
            format!("{process_id:x}-{initialized_nanos:x}"),
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    #[cfg(test)]
    fn start_with_dispatch(
        window: Duration,
        requested_seconds: u64,
        event_limit: u64,
        native_process: Option<DiagnosticProcessIdentity>,
        started_monotonic_ms: Option<f64>,
        dispatch: Dispatch,
        owner: Weak<WorkflowDiagnosticController>,
        generation: u8,
        nonce: String,
        output_basename: String,
        producer_id: String,
        private_output: Option<Arc<Mutex<WorkflowPrivateOutput>>>,
    ) -> Option<Arc<Self>> {
        Self::prepare_with_dispatch(
            window,
            requested_seconds,
            event_limit,
            native_process,
            started_monotonic_ms,
            dispatch,
            owner,
            generation,
            nonce,
            output_basename,
            producer_id,
            private_output,
        )
        .arm()
    }

    #[allow(clippy::too_many_arguments)]
    fn prepare_with_dispatch(
        window: Duration,
        requested_seconds: u64,
        event_limit: u64,
        native_process: Option<DiagnosticProcessIdentity>,
        started_monotonic_ms: Option<f64>,
        dispatch: Dispatch,
        owner: Weak<WorkflowDiagnosticController>,
        generation: u8,
        nonce: String,
        output_basename: String,
        producer_id: String,
        private_output: Option<Arc<Mutex<WorkflowPrivateOutput>>>,
    ) -> PreparedWorkflowDiagnostic {
        let process_id = std::process::id();
        let initialized = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let started_unix_ms = u64::try_from(initialized.as_millis()).unwrap_or(u64::MAX);
        let (timer_cancel, timer) = mpsc::channel();
        let gate = Arc::new(Self {
            generation,
            nonce,
            output_basename,
            owner,
            process_id,
            producer_id,
            started: Instant::now(),
            started_unix_ms,
            requested_seconds,
            window,
            event_limit,
            native_process,
            started_monotonic_ms,
            dispatch,
            private_output,
            state: Mutex::new(WorkflowDiagnosticState {
                remaining_detail_events: event_limit,
                reserved_detail_events: 0,
                emitted_detail_events: 0,
                admitted_runs: 0,
                finished_runs: 0,
                closed: false,
                ended_monotonic_ms: None,
                timer_cancel: Some(timer_cancel.clone()),
            }),
        });

        PreparedWorkflowDiagnostic {
            gate,
            arm_timer: timer_cancel,
            timer,
        }
    }

    fn prepare_private(
        owner: &Arc<WorkflowDiagnosticController>,
        generation: u8,
        nonce: String,
        output_basename: String,
        requested_seconds: u64,
        file: File,
    ) -> PreparedWorkflowDiagnostic {
        let output = Arc::new(Mutex::new(WorkflowPrivateOutput {
            file,
            bytes_written: 0,
            failed: false,
        }));
        let writer = WorkflowPrivateMakeWriter {
            output: Arc::clone(&output),
        };
        let private_layer = tracing_subscriber::fmt::layer()
            .json()
            .with_ansi(false)
            .with_writer(writer)
            .with_filter(filter_fn(|metadata| {
                metadata.target() == WORKFLOW_DIAGNOSTIC_TARGET
            }));
        let subscriber = tracing_subscriber::registry().with(private_layer);
        Self::prepare_with_dispatch(
            Duration::from_secs(requested_seconds),
            requested_seconds,
            WORKFLOW_DIAGNOSTIC_MAX_EVENTS,
            DiagnosticProcessIdentity::capture().ok(),
            kernel_monotonic_ms().ok(),
            Dispatch::new(subscriber),
            Arc::downgrade(owner),
            generation,
            nonce,
            output_basename,
            owner.producer_id.clone(),
            Some(output),
        )
    }

    fn emit_started(&self) -> bool {
        let _state = self
            .state
            .lock()
            .expect("workflow diagnostics lock poisoned");
        let native_process_schema = self.native_process.as_ref().map(|_| 1_u8);
        let process_start_ticks = self
            .native_process
            .as_ref()
            .map(|identity| identity.process_start_ticks);
        let boot_id = self
            .native_process
            .as_ref()
            .map(|identity| identity.boot_id.as_str());
        let executable = self
            .native_process
            .as_ref()
            .map(|identity| identity.executable.as_str());
        let monotonic_clock = self.started_monotonic_ms.map(|_| "CLOCK_MONOTONIC");
        tracing::dispatcher::with_default(&self.dispatch, || {
            tracing::info!(
                target: WORKFLOW_DIAGNOSTIC_TARGET,
                event = "workflow.diagnostics.window_started",
                diagnostic_schema = 1_u8,
                telemetry_version = WORKFLOW_TELEMETRY_VERSION,
                generation = self.generation,
                nonce = %self.nonce,
                output_basename = %self.output_basename,
                process_id = self.process_id,
                producer_id = %self.producer_id,
                native_process_schema,
                process_start_ticks,
                boot_id,
                executable,
                monotonic_clock,
                started_unix_ms = self.started_unix_ms,
                started_monotonic_ms = self.started_monotonic_ms,
                requested_seconds = self.requested_seconds,
                event_limit = self.event_limit,
                scope = WORKFLOW_DIAGNOSTIC_SCOPE,
                limitations = WORKFLOW_DIAGNOSTIC_LIMITATIONS,
                "bounded workflow diagnostics started"
            );
        });
        self.flush_private_output()
    }

    fn flush_private_output(&self) -> bool {
        let Some(output) = &self.private_output else {
            return true;
        };
        let Ok(mut output) = output.lock() else {
            return false;
        };
        if output.failed || output.bytes_written == 0 {
            return false;
        }
        if output.file.flush().is_err() {
            output.failed = true;
            return false;
        }
        true
    }

    fn private_output_failed(&self) -> bool {
        self.private_output
            .as_ref()
            .is_some_and(|output| output.lock().map(|output| output.failed).unwrap_or(true))
    }

    fn admit_locked(&self, state: &mut WorkflowDiagnosticState, count: u64) -> bool {
        if state.closed {
            return false;
        }
        if self.private_output_failed() {
            self.close_locked(state, "io_error", count);
            return false;
        }
        if self.started.elapsed() >= self.window {
            self.close_locked(state, "expiry", count);
            return false;
        }
        if state.remaining_detail_events < count {
            self.close_locked(state, "event_limit", count);
            return false;
        }
        state.remaining_detail_events -= count;
        state.reserved_detail_events += count;
        true
    }

    fn close(&self, closure_reason: &'static str, rejected_detail_events_at_close: u64) {
        let mut state = self
            .state
            .lock()
            .expect("workflow diagnostics lock poisoned");
        self.close_locked(&mut state, closure_reason, rejected_detail_events_at_close);
    }

    fn close_locked(
        &self,
        state: &mut WorkflowDiagnosticState,
        closure_reason: &'static str,
        rejected_detail_events_at_close: u64,
    ) {
        if state.closed {
            return;
        }
        state.ended_monotonic_ms = self.started_monotonic_ms.and_then(|started| {
            let deadline = started + self.window.as_secs_f64() * 1000.0;
            kernel_monotonic_ms()
                .ok()
                .filter(|observed| *observed >= started)
                .map(|observed| observed.min(deadline))
        });
        state.closed = true;
        if let Some(cancel) = state.timer_cancel.take() {
            let _ = cancel.send(());
        }

        let in_flight_runs = state.admitted_runs - state.finished_runs;
        let censored_in_flight_runs = in_flight_runs;
        debug_assert_eq!(
            state.reserved_detail_events + state.remaining_detail_events,
            self.event_limit
        );
        debug_assert_eq!(
            state.reserved_detail_events,
            state.emitted_detail_events + censored_in_flight_runs
        );
        debug_assert_eq!(state.admitted_runs, state.finished_runs + in_flight_runs);
        let ended = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let ended_unix_ms = u64::try_from(ended.as_millis()).unwrap_or(u64::MAX);
        let native_process_schema = self.native_process.as_ref().map(|_| 1_u8);
        let process_start_ticks = self
            .native_process
            .as_ref()
            .map(|identity| identity.process_start_ticks);
        let boot_id = self
            .native_process
            .as_ref()
            .map(|identity| identity.boot_id.as_str());
        let executable = self
            .native_process
            .as_ref()
            .map(|identity| identity.executable.as_str());
        let monotonic_clock = self.started_monotonic_ms.map(|_| "CLOCK_MONOTONIC");
        if !self.private_output_failed() {
            tracing::dispatcher::with_default(&self.dispatch, || {
                tracing::info!(
                    target: WORKFLOW_DIAGNOSTIC_TARGET,
                    event = "workflow.diagnostics.window_closed",
                    diagnostic_schema = 1_u8,
                    telemetry_version = WORKFLOW_TELEMETRY_VERSION,
                    generation = self.generation,
                    nonce = %self.nonce,
                    output_basename = %self.output_basename,
                    process_id = self.process_id,
                    producer_id = %self.producer_id,
                    native_process_schema,
                    process_start_ticks,
                    boot_id,
                    executable,
                    monotonic_clock,
                    started_unix_ms = self.started_unix_ms,
                    started_monotonic_ms = self.started_monotonic_ms,
                    requested_seconds = self.requested_seconds,
                    event_limit = self.event_limit,
                    scope = WORKFLOW_DIAGNOSTIC_SCOPE,
                    limitations = WORKFLOW_DIAGNOSTIC_LIMITATIONS,
                    ended_unix_ms,
                    ended_monotonic_ms = state.ended_monotonic_ms,
                    observed_seconds = self.started.elapsed().as_secs_f64(),
                    closure_reason,
                    reserved_detail_events = state.reserved_detail_events,
                    emitted_detail_events = state.emitted_detail_events,
                    remaining_detail_events = state.remaining_detail_events,
                    rejected_detail_events_at_close,
                    admitted_runs = state.admitted_runs,
                    finished_runs_before_close = state.finished_runs,
                    in_flight_runs_at_close = in_flight_runs,
                    censored_in_flight_runs,
                    "bounded workflow diagnostics closed"
                );
            });
            if !self.flush_private_output() {
                eprintln!("workflow diagnostic terminal output failed");
            }
        } else {
            eprintln!("workflow diagnostic output failed before terminal serialization");
        }
        if let Some(owner) = self.owner.upgrade() {
            owner.finish(self.generation);
        }
    }

    fn close_if_exhausted_locked(&self, state: &mut WorkflowDiagnosticState) {
        if state.remaining_detail_events == 0 && state.admitted_runs == state.finished_runs {
            self.close_locked(state, "event_limit", 0);
        }
    }

    fn emit_notification(
        &self,
        telemetry: &TriggerTelemetry,
        context: &'static str,
        delivered: bool,
    ) {
        let mut state = self
            .state
            .lock()
            .expect("workflow diagnostics lock poisoned");
        if !self.admit_locked(&mut state, 1) {
            return;
        }
        tracing::dispatcher::with_default(&self.dispatch, || {
            tracing::trace!(
                target: WORKFLOW_DIAGNOSTIC_TARGET,
                event = "workflow.trigger.notification",
                telemetry_version = WORKFLOW_TELEMETRY_VERSION,
                process_id = self.process_id,
                producer_id = %self.producer_id,
                workflow = %telemetry.workflow,
                dna_hash = %telemetry.dna_hash,
                cell_token = telemetry.cell_token,
                trigger_class = trigger_class(context),
                delivered,
                "workflow trigger notification"
            );
        });
        state.emitted_detail_events += 1;
        if self.private_output_failed() {
            self.close_locked(&mut state, "io_error", 0);
        } else {
            self.close_if_exhausted_locked(&mut state);
        }
    }

    fn emit_wakeup(
        &self,
        workflow: &str,
        dna_hash: &DnaHash,
        cell_token: Option<u64>,
        wake: TriggerWake,
    ) {
        let mut state = self
            .state
            .lock()
            .expect("workflow diagnostics lock poisoned");
        if !self.admit_locked(&mut state, 1) {
            return;
        }
        let (wake_source, trigger_class, coalesced_observed) = match wake {
            TriggerWake::Notification { class, coalesced } => ("notification", class, coalesced),
            TriggerWake::Loop => ("loop", "loop", false),
        };
        tracing::dispatcher::with_default(&self.dispatch, || {
            tracing::trace!(
                target: WORKFLOW_DIAGNOSTIC_TARGET,
                event = "workflow.trigger.wakeup",
                telemetry_version = WORKFLOW_TELEMETRY_VERSION,
                process_id = self.process_id,
                producer_id = %self.producer_id,
                workflow,
                dna_hash = %dna_hash,
                cell_token,
                wake_source,
                trigger_class,
                coalesced_observed,
                "workflow trigger wakeup"
            );
        });
        state.emitted_detail_events += 1;
        if self.private_output_failed() {
            self.close_locked(&mut state, "io_error", 0);
        } else {
            self.close_if_exhausted_locked(&mut state);
        }
    }

    fn start_run(
        self: &Arc<Self>,
        workflow: &str,
        dna_hash: &DnaHash,
        cell_token: Option<u64>,
        wake: TriggerWake,
    ) -> Option<WorkflowRunTrace> {
        let mut state = self
            .state
            .lock()
            .expect("workflow diagnostics lock poisoned");
        if !self.admit_locked(&mut state, 2) {
            return None;
        }
        let (wake_source, trigger_class) = match wake {
            TriggerWake::Notification { class, .. } => ("notification", class),
            TriggerWake::Loop => ("loop", "loop"),
        };
        let run_id = NEXT_WORKFLOW_RUN_ID.fetch_add(1, Ordering::Relaxed);
        state.admitted_runs += 1;
        tracing::dispatcher::with_default(&self.dispatch, || {
            tracing::trace!(
                target: WORKFLOW_DIAGNOSTIC_TARGET,
                event = "workflow.run.start",
                telemetry_version = WORKFLOW_TELEMETRY_VERSION,
                process_id = self.process_id,
                producer_id = %self.producer_id,
                run_id,
                workflow,
                dna_hash = %dna_hash,
                cell_token,
                wake_source,
                trigger_class,
                "workflow run started"
            );
        });
        state.emitted_detail_events += 1;
        if self.private_output_failed() {
            self.close_locked(&mut state, "io_error", 0);
            return None;
        }
        Some(WorkflowRunTrace {
            gate: self.clone(),
            run_id,
            workflow: workflow.to_string(),
            dna_hash: dna_hash.to_string(),
            cell_token,
            trigger_class,
            wake_source,
            started: Instant::now(),
            outcome: "dropped",
        })
    }

    fn finish_run(&self, run: &WorkflowRunTrace) {
        let mut state = self
            .state
            .lock()
            .expect("workflow diagnostics lock poisoned");
        if state.closed {
            return;
        }
        if self.started.elapsed() >= self.window {
            self.close_locked(&mut state, "expiry", 0);
            return;
        }
        tracing::dispatcher::with_default(&self.dispatch, || {
            tracing::trace!(
                target: WORKFLOW_DIAGNOSTIC_TARGET,
                event = "workflow.run.finish",
                telemetry_version = WORKFLOW_TELEMETRY_VERSION,
                process_id = self.process_id,
                producer_id = %self.producer_id,
                run_id = run.run_id,
                workflow = %run.workflow,
                dna_hash = %run.dna_hash,
                cell_token = run.cell_token,
                trigger_class = run.trigger_class,
                wake_source = run.wake_source,
                outcome = run.outcome,
                duration_seconds = run.started.elapsed().as_secs_f64(),
                "workflow run finished"
            );
        });
        state.emitted_detail_events += 1;
        state.finished_runs += 1;
        if self.private_output_failed() {
            self.close_locked(&mut state, "io_error", 0);
        } else {
            self.close_if_exhausted_locked(&mut state);
        }
    }

    #[cfg(test)]
    fn test_counts(&self) -> (u64, u64, u64, u64, u64, bool) {
        let state = self
            .state
            .lock()
            .expect("workflow diagnostics lock poisoned");
        (
            state.reserved_detail_events,
            state.emitted_detail_events,
            state.remaining_detail_events,
            state.admitted_runs,
            state.finished_runs,
            state.closed,
        )
    }

    #[cfg(test)]
    fn test_monotonic_times(&self) -> (Option<f64>, Option<f64>) {
        let state = self
            .state
            .lock()
            .expect("workflow diagnostics lock poisoned");
        (self.started_monotonic_ms, state.ended_monotonic_ms)
    }
}

impl WorkflowDiagnosticController {
    fn new(path: &Path) -> io::Result<Self> {
        let directory = PrivateCaptureDirectory::open(path)?;
        let initialized = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        Ok(Self {
            directory,
            producer_id: format!(
                "workflow-{:x}-{:x}",
                std::process::id(),
                initialized.as_nanos()
            ),
            state: Mutex::new(WorkflowControllerState::default()),
        })
    }

    fn response(
        &self,
        nonce: String,
        requested_seconds: u64,
        outcome: CaptureAdmissionOutcome,
        gate: Option<&WorkflowDiagnosticGate>,
    ) -> CaptureDiagnosticResponse {
        WORKFLOW_ADMISSION_COUNTERS.increment(outcome);
        CaptureDiagnosticResponse {
            schema_version: DIAGNOSTIC_CAPTURE_SCHEMA_VERSION,
            family: DiagnosticCaptureFamily::Workflow,
            nonce: bounded_response_nonce(nonce),
            outcome,
            producer_id: gate.map(|_| self.producer_id.clone()),
            generation: gate.map(|gate| gate.generation),
            output_basename: gate.map(|gate| gate.output_basename.clone()),
            window: gate.map(|_| DiagnosticWindowStatus {
                requested_seconds,
                event_limit: WORKFLOW_DIAGNOSTIC_MAX_EVENTS,
                state: CaptureWindowState::Active,
            }),
            counters: WORKFLOW_ADMISSION_COUNTERS.snapshot(),
        }
    }

    fn admit(
        self: &Arc<Self>,
        request: CaptureDiagnosticRequest,
        trace_enabled: bool,
    ) -> CaptureDiagnosticResponse {
        let CaptureDiagnosticRequest {
            schema_version,
            nonce,
            requested_seconds,
        } = request;
        if schema_version != DIAGNOSTIC_CAPTURE_SCHEMA_VERSION
            || !valid_capture_nonce(&nonce)
            || !(1..=WORKFLOW_DIAGNOSTIC_MAX_SECONDS).contains(&requested_seconds)
        {
            return self.response(
                nonce,
                requested_seconds,
                CaptureAdmissionOutcome::RefusedInvalidRequest,
                None,
            );
        }
        if !trace_enabled {
            return self.response(
                nonce,
                requested_seconds,
                CaptureAdmissionOutcome::RefusedTraceUnavailable,
                None,
            );
        }
        let mut controller = match self.state.try_lock() {
            Ok(controller) => controller,
            Err(TryLockError::WouldBlock) | Err(TryLockError::Poisoned(_)) => {
                return self.response(
                    nonce,
                    requested_seconds,
                    CaptureAdmissionOutcome::RefusedBusy,
                    None,
                )
            }
        };
        if controller.active.is_some() {
            return self.response(
                nonce,
                requested_seconds,
                CaptureAdmissionOutcome::RefusedBusy,
                None,
            );
        }
        if controller.retained_nonces.contains(&nonce) {
            return self.response(
                nonce,
                requested_seconds,
                CaptureAdmissionOutcome::RefusedDuplicateNonce,
                None,
            );
        }
        let Some(generation) = controller.generations.checked_add(1) else {
            return self.response(
                nonce,
                requested_seconds,
                CaptureAdmissionOutcome::RefusedGenerationBudget,
                None,
            );
        };
        if generation > WORKFLOW_DIAGNOSTIC_MAX_GENERATIONS {
            return self.response(
                nonce,
                requested_seconds,
                CaptureAdmissionOutcome::RefusedGenerationBudget,
                None,
            );
        }
        let output_basename = format!("workflow-g{generation:02}-{nonce}.jsonl");
        let file = match self.directory.create_new(&output_basename) {
            Ok(file) => file,
            Err(_) => {
                return self.response(
                    nonce,
                    requested_seconds,
                    CaptureAdmissionOutcome::RefusedIo,
                    None,
                )
            }
        };
        controller.generations = generation;
        controller.retained_nonces.insert(nonce.clone());
        let prepared = WorkflowDiagnosticGate::prepare_private(
            self,
            generation,
            nonce.clone(),
            output_basename,
            requested_seconds,
            file,
        );
        controller.active = Some(Arc::clone(&prepared.gate));
        let Some(gate) = prepared.arm() else {
            drop(controller);
            self.finish(generation);
            return self.response(
                nonce,
                requested_seconds,
                CaptureAdmissionOutcome::RefusedIo,
                None,
            );
        };
        drop(controller);
        self.response(
            nonce,
            requested_seconds,
            CaptureAdmissionOutcome::Admitted,
            Some(&gate),
        )
    }

    fn active(&self) -> Option<Arc<WorkflowDiagnosticGate>> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .active
            .clone()
    }

    fn finish(self: &Arc<Self>, generation: u8) {
        match self.state.try_lock() {
            Ok(mut controller) => {
                if controller
                    .active
                    .as_ref()
                    .is_some_and(|active| active.generation == generation)
                {
                    controller.active = None;
                }
            }
            Err(TryLockError::WouldBlock) => {
                let controller = Arc::clone(self);
                let _ = thread::Builder::new()
                    .name("workflow-diagnostics-terminal".into())
                    .spawn(move || {
                        let mut state = controller
                            .state
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                        if state
                            .active
                            .as_ref()
                            .is_some_and(|active| active.generation == generation)
                        {
                            state.active = None;
                        }
                    });
            }
            Err(TryLockError::Poisoned(_)) => {}
        }
    }
}

fn workflow_controller_slot() -> &'static WorkflowControllerSlot {
    WORKFLOW_DIAGNOSTICS.get_or_init(|| {
        let directory =
            std::env::var_os(WORKFLOW_DIAGNOSTIC_DIRECTORY_ENV).filter(|value| !value.is_empty());
        let startup_seconds = match std::env::var(WORKFLOW_DIAGNOSTIC_ENV) {
            Ok(raw) => match raw.parse::<u64>() {
                Ok(0) => None,
                Ok(value) if value <= WORKFLOW_DIAGNOSTIC_MAX_SECONDS => Some(value),
                _ => {
                    return WorkflowControllerSlot::Failed(
                        CaptureAdmissionOutcome::RefusedInvalidRequest,
                    )
                }
            },
            Err(std::env::VarError::NotPresent) => None,
            Err(std::env::VarError::NotUnicode(_)) => {
                return WorkflowControllerSlot::Failed(
                    CaptureAdmissionOutcome::RefusedInvalidRequest,
                )
            }
        };
        let Some(directory) = directory else {
            return if startup_seconds.is_some() {
                WorkflowControllerSlot::Failed(CaptureAdmissionOutcome::RefusedInvalidRequest)
            } else {
                WorkflowControllerSlot::Disabled
            };
        };
        configured_workflow_slot(
            Path::new(&directory),
            startup_seconds,
            tracing::enabled!(
                target: WORKFLOW_DIAGNOSTIC_TARGET,
                tracing::Level::TRACE
            ),
        )
    })
}

fn configured_workflow_slot(
    directory: &Path,
    startup_seconds: Option<u64>,
    trace_enabled: bool,
) -> WorkflowControllerSlot {
    let controller = match WorkflowDiagnosticController::new(directory) {
        Ok(controller) => Arc::new(controller),
        Err(_) => return WorkflowControllerSlot::Failed(CaptureAdmissionOutcome::RefusedIo),
    };
    if let Some(requested_seconds) = startup_seconds {
        let admission = controller.admit(
            CaptureDiagnosticRequest {
                schema_version: DIAGNOSTIC_CAPTURE_SCHEMA_VERSION,
                nonce: "startup".into(),
                requested_seconds,
            },
            trace_enabled,
        );
        if admission.outcome != CaptureAdmissionOutcome::Admitted {
            return WorkflowControllerSlot::Failed(admission.outcome);
        }
    }
    WorkflowControllerSlot::Enabled(controller)
}

/// Pin workflow-diagnostic startup authorization after tracing is initialized.
pub fn initialize_workflow_diagnostics() -> Result<(), CaptureAdmissionOutcome> {
    match workflow_controller_slot() {
        WorkflowControllerSlot::Disabled | WorkflowControllerSlot::Enabled(_) => Ok(()),
        WorkflowControllerSlot::Failed(outcome) => Err(*outcome),
    }
}

pub(crate) fn capture_workflow_diagnostics(
    request: CaptureDiagnosticRequest,
) -> CaptureDiagnosticResponse {
    match workflow_controller_slot() {
        WorkflowControllerSlot::Enabled(controller) => controller.admit(
            request,
            tracing::enabled!(
                target: WORKFLOW_DIAGNOSTIC_TARGET,
                tracing::Level::TRACE
            ),
        ),
        WorkflowControllerSlot::Disabled => {
            workflow_refusal_response(request, CaptureAdmissionOutcome::RefusedDisabled)
        }
        WorkflowControllerSlot::Failed(outcome) => workflow_refusal_response(request, *outcome),
    }
}

fn workflow_refusal_response(
    request: CaptureDiagnosticRequest,
    outcome: CaptureAdmissionOutcome,
) -> CaptureDiagnosticResponse {
    WORKFLOW_ADMISSION_COUNTERS.increment(outcome);
    CaptureDiagnosticResponse {
        schema_version: DIAGNOSTIC_CAPTURE_SCHEMA_VERSION,
        family: DiagnosticCaptureFamily::Workflow,
        nonce: bounded_response_nonce(request.nonce),
        outcome,
        producer_id: None,
        generation: None,
        output_basename: None,
        window: None,
        counters: WORKFLOW_ADMISSION_COUNTERS.snapshot(),
    }
}

fn bounded_response_nonce(nonce: String) -> String {
    if valid_capture_nonce(&nonce) {
        nonce
    } else {
        "invalid".to_owned()
    }
}

fn workflow_diagnostics() -> Option<Arc<WorkflowDiagnosticGate>> {
    match workflow_controller_slot() {
        WorkflowControllerSlot::Enabled(controller) => controller.active(),
        WorkflowControllerSlot::Disabled | WorkflowControllerSlot::Failed(_) => None,
    }
}

fn cell_trace_token(cell_id: &CellId) -> (u64, Arc<()>) {
    let tokens = CELL_TRACE_TOKENS.get_or_init(Default::default);
    let mut tokens = tokens.lock().expect("cell trace token lock poisoned");
    tokens.retain(|_, (_, lease)| lease.strong_count() > 0);
    if let Some((token, lease)) = tokens.get(cell_id) {
        if let Some(lease) = lease.upgrade() {
            return (*token, lease);
        }
    }
    let token = NEXT_CELL_TRACE_TOKEN.fetch_add(1, Ordering::Relaxed);
    let lease = Arc::new(());
    tokens.insert(cell_id.clone(), (token, Arc::downgrade(&lease)));
    (token, lease)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum TriggerWake {
    Notification {
        class: &'static str,
        coalesced: bool,
    },
    Loop,
}

fn trigger_class(context: &str) -> &'static str {
    match context {
        "init" => "init",
        "retrigger" => "retrigger",
        "retry after error" => "retry",
        "resume_loop_now" => "resume",
        _ => "external",
    }
}

#[derive(Debug)]
struct TriggerTelemetry {
    workflow: String,
    dna_hash: String,
    cell_token: Option<u64>,
}
use witnessing_consumer::*;

// MAYBE: move these to workflow mod
mod integrate_dht_ops_consumer;
use integrate_dht_ops_consumer::*;
mod sys_validation_consumer;
use sys_validation_consumer::*;
mod app_validation_consumer;
use app_validation_consumer::*;

mod publish_dht_ops_consumer;
use crate::conductor::error::ConductorResult;
use crate::core::queue_consumer::countersigning_consumer::spawn_countersigning_consumer;
use crate::core::workflow::countersigning_workflow::CountersigningWorkspace;
use validation_receipt_consumer::*;

mod countersigning_consumer;
mod validation_receipt_consumer;

mod witnessing_consumer;

#[cfg(test)]
mod tests;

/// Spawns several long-running tasks which are responsible for processing work
/// which shows up on various databases.
///
/// Waits for the initial loop to complete before returning, to prevent causing
/// a race condition by trying to run a workflow too soon after cell creation.
#[allow(clippy::too_many_arguments)]
pub async fn spawn_queue_consumer_tasks(
    cell_id: CellId,
    network: DynHolochainP2pDna,
    space: &Space,
    conductor: ConductorHandle,
) -> ConductorResult<(QueueTriggers, InitialQueueTriggers)> {
    let keystore = conductor.keystore().clone();
    let dna_hash = Arc::new(cell_id.dna_hash().clone());
    let queue_consumer_map = conductor.get_queue_consumer_workflows();

    // Publish
    let tx_publish = spawn_publish_dht_ops_consumer(
        cell_id.clone(),
        space.dht_store.clone(),
        conductor.clone(),
        network.clone(),
    );

    // Validation Receipt
    // One per space.

    let tx_receipt = queue_consumer_map.spawn_once_validation_receipt(dna_hash.clone(), || {
        spawn_validation_receipt_consumer(
            dna_hash.clone(),
            space.dht_store.clone(),
            conductor.clone(),
            network.clone(),
        )
    });

    // Integration
    // One per space.
    let tx_integration = queue_consumer_map.spawn_once_integration(dna_hash.clone(), || {
        spawn_integrate_dht_ops_consumer(
            dna_hash.clone(),
            space.dht_store.clone(),
            conductor.task_manager(),
            tx_receipt.clone(),
            network.clone(),
        )
    });

    // App validation
    // One per space.
    let tx_app = queue_consumer_map.spawn_once_app_validation(dna_hash.clone(), || {
        spawn_app_validation_consumer(
            dna_hash.clone(),
            AppValidationWorkspace::new(space.dht_store.clone(), keystore.clone()),
            conductor.clone(),
            tx_integration.clone(),
            tx_publish.clone(),
            network.clone(),
        )
    });

    // Sys validation
    // One per space.
    let tx_sys = queue_consumer_map.spawn_once_sys_validation(dna_hash.clone(), || {
        spawn_sys_validation_consumer(
            SysValidationWorkspace::new(
                space.dht_store.clone(),
                cell_id.dna_hash().clone(),
                conductor
                    .get_config()
                    .conductor_tuning_params()
                    .sys_validation_retry_delay(),
            ),
            space.clone(),
            conductor.clone(),
            tx_app.clone(),
            tx_integration.clone(),
            tx_publish.clone(),
            network.clone(),
            conductor.keystore().clone(),
        )
    });

    let workspace = {
        let mut guard = space.countersigning_workspaces.lock();
        guard
            .entry(cell_id.clone())
            .or_insert_with(|| {
                Arc::new(CountersigningWorkspace::new(
                    conductor
                        .config
                        .conductor_tuning_params()
                        .countersigning_resolution_retry_delay(),
                    conductor
                        .config
                        .conductor_tuning_params()
                        .countersigning_resolution_retry_limit,
                ))
            })
            .clone()
    };
    let tx_countersigning = spawn_countersigning_consumer(
        space.clone(),
        workspace,
        cell_id,
        conductor.clone(),
        tx_integration.clone(),
        tx_publish.clone(),
    );

    let tx_witnessing = queue_consumer_map.spawn_once_witnessing(dna_hash, || {
        spawn_witnessing_consumer(
            space.clone(),
            conductor.task_manager(),
            network.clone(),
            tx_sys.clone(),
        )
    });

    Ok((
        QueueTriggers {
            sys_validation: tx_sys.clone(),
            publish_dht_ops: tx_publish.clone(),
            countersigning: tx_countersigning.clone(),
            witnessing: tx_witnessing,
            integrate_dht_ops: tx_integration.clone(),
        },
        InitialQueueTriggers::new(
            tx_sys,
            tx_publish,
            tx_app,
            tx_integration,
            tx_receipt,
            tx_countersigning,
        ),
    ))
}

/// Map of running queue consumers workflows per dna space.
#[derive(Clone)]
pub struct QueueConsumerMap {
    map: RwShare<HashMap<QueueEntry, TriggerSender>>,
}

impl Default for QueueConsumerMap {
    fn default() -> Self {
        Self::new()
    }
}

impl QueueConsumerMap {
    /// Create a new queue consumer map.
    pub fn new() -> Self {
        Self {
            map: RwShare::new(HashMap::new()),
        }
    }

    fn spawn_once_validation_receipt<S>(&self, dna_hash: Arc<DnaHash>, spawn: S) -> TriggerSender
    where
        S: FnOnce() -> TriggerSender,
    {
        self.spawn_once(QueueEntry(dna_hash, QueueType::Receipt), spawn)
    }

    fn spawn_once_integration<S>(&self, dna_hash: Arc<DnaHash>, spawn: S) -> TriggerSender
    where
        S: FnOnce() -> TriggerSender,
    {
        self.spawn_once(QueueEntry(dna_hash, QueueType::Integration), spawn)
    }

    fn spawn_once_sys_validation<S>(&self, dna_hash: Arc<DnaHash>, spawn: S) -> TriggerSender
    where
        S: FnOnce() -> TriggerSender,
    {
        self.spawn_once(QueueEntry(dna_hash, QueueType::SysValidation), spawn)
    }

    fn spawn_once_app_validation<S>(&self, dna_hash: Arc<DnaHash>, spawn: S) -> TriggerSender
    where
        S: FnOnce() -> TriggerSender,
    {
        self.spawn_once(QueueEntry(dna_hash, QueueType::AppValidation), spawn)
    }

    fn spawn_once_witnessing<S>(&self, dna_hash: Arc<DnaHash>, spawn: S) -> TriggerSender
    where
        S: FnOnce() -> TriggerSender,
    {
        self.spawn_once(QueueEntry(dna_hash, QueueType::Witnessing), spawn)
    }

    /// Get the validation receipt trigger for this dna hash.
    pub fn validation_receipt_trigger(&self, dna_hash: Arc<DnaHash>) -> Option<TriggerSender> {
        self.get_trigger(&QueueEntry(dna_hash, QueueType::Receipt))
    }

    /// Get the integration trigger for this dna hash.
    pub fn integration_trigger(&self, dna_hash: Arc<DnaHash>) -> Option<TriggerSender> {
        self.get_trigger(&QueueEntry(dna_hash, QueueType::Integration))
    }

    /// Get the sys validation trigger for this dna hash.
    pub fn sys_validation_trigger(&self, dna_hash: Arc<DnaHash>) -> Option<TriggerSender> {
        self.get_trigger(&QueueEntry(dna_hash, QueueType::SysValidation))
    }

    /// Get the app validation trigger for this dna hash.
    pub fn app_validation_trigger(&self, dna_hash: Arc<DnaHash>) -> Option<TriggerSender> {
        self.get_trigger(&QueueEntry(dna_hash, QueueType::AppValidation))
    }

    /// Get the countersigning trigger for this dna hash.
    pub fn countersigning_trigger(&self, dna_hash: Arc<DnaHash>) -> Option<TriggerSender> {
        self.get_trigger(&QueueEntry(dna_hash, QueueType::Countersigning))
    }

    /// Get the witnessing trigger for this dna hash.
    pub fn witnessing_trigger(&self, dna_hash: Arc<DnaHash>) -> Option<TriggerSender> {
        self.get_trigger(&QueueEntry(dna_hash, QueueType::Witnessing))
    }

    fn get_trigger(&self, key: &QueueEntry) -> Option<TriggerSender> {
        self.map.share_ref(|map| map.get(key).cloned())
    }

    fn spawn_once<S>(&self, key: QueueEntry, spawn: S) -> TriggerSender
    where
        S: FnOnce() -> TriggerSender,
    {
        self.map.share_mut(|map| match map.entry(key) {
            std::collections::hash_map::Entry::Occupied(o) => o.get().clone(),
            std::collections::hash_map::Entry::Vacant(v) => {
                let ts = spawn();
                v.insert(ts).clone()
            }
        })
    }

    /// Drop this map's trigger senders for every queue of the given DNA.
    ///
    /// Once the removed cells have also dropped their copies, the consumer
    /// workflows terminate. Used when a DNA's space is torn down so that a
    /// later reinstall re-spawns fresh consumers bound to the new databases.
    pub fn remove_all_for_dna(&self, dna_hash: &DnaHash) {
        self.map
            .share_mut(|map| map.retain(|QueueEntry(dna, _), _| dna.as_ref() != dna_hash));
    }
}

#[derive(Hash, Eq, PartialEq, Clone, Debug)]
struct QueueEntry(Arc<DnaHash>, QueueType);

#[derive(Hash, Eq, PartialEq, Clone, Debug)]
enum QueueType {
    Receipt,
    Integration,
    AppValidation,
    SysValidation,
    Countersigning,
    Witnessing,
}

/// The entry points for kicking off a chain reaction of queue activity
#[derive(Clone)]
pub struct QueueTriggers {
    /// Notify the SysValidation workflow to run, i.e. after handling gossip
    pub sys_validation: TriggerSender,
    /// Notify the ProduceDhtOps workflow to run, i.e. after InvokeCallZome
    pub publish_dht_ops: TriggerSender,
    /// Notify the countersigning workflow to run and manage sessions state.
    pub countersigning: TriggerSender,
    /// Notify the witnessing workflow to run and check for complete signature sets for sessions.
    pub witnessing: TriggerSender,
    /// Notify the IntegrateDhtOps workflow to run, i.e. after InvokeCallZome
    pub integrate_dht_ops: TriggerSender,
}

/// The triggers to run once at the start of a cell
#[derive(Clone)]
pub struct InitialQueueTriggers {
    /// These triggers can only be run once
    /// so they are private
    sys_validation: TriggerSender,
    publish_dht_ops: TriggerSender,
    app_validation: TriggerSender,
    integrate_dht_ops: TriggerSender,
    validation_receipt: TriggerSender,
    countersigning: TriggerSender,
}

impl InitialQueueTriggers {
    fn new(
        sys_validation: TriggerSender,
        publish_dht_ops: TriggerSender,
        app_validation: TriggerSender,
        integrate_dht_ops: TriggerSender,
        validation_receipt: TriggerSender,
        countersigning: TriggerSender,
    ) -> Self {
        Self {
            sys_validation,
            publish_dht_ops,
            app_validation,
            integrate_dht_ops,
            validation_receipt,
            countersigning,
        }
    }

    /// Initialize all the workflows once.
    pub fn initialize_workflows(self) {
        self.sys_validation.trigger(&"init");
        self.app_validation.trigger(&"init");
        self.integrate_dht_ops.trigger(&"init");
        self.publish_dht_ops.trigger(&"init");
        self.validation_receipt.trigger(&"init");
        self.countersigning.trigger(&"init");
    }
}

/// The means of nudging a queue consumer to tell it to look for more work
#[derive(Clone)]
pub struct TriggerSender {
    /// The actual trigger sender.
    trigger: broadcast::Sender<&'static &'static str>,
    /// Reset the back off loop if there is one.
    reset_back_off: Option<Arc<AtomicBool>>,
    /// Pause / resume the back off loop if there is one.
    pause_back_off: Option<Arc<AtomicBool>>,
    telemetry: Arc<OnceLock<TriggerTelemetry>>,
}

/// The receiving end of a queue trigger channel
pub struct TriggerReceiver {
    /// The actual trigger.
    rx: broadcast::Receiver<&'static &'static str>,
    /// If there is a back off loop, should
    /// the trigger reset the back off.
    reset_on_trigger: bool,
    /// The optional back off loop.
    back_off: Option<BackOff>,
}

/// A loop that can optionally back off, pause and resume.
struct BackOff {
    /// The starting duration for the back off.
    /// This allows resetting the range.
    start: Duration,
    /// The range of duration for the back off.
    range: Range<Duration>,
    /// If we should reset the range on next iteration.
    reset_back_off: Arc<AtomicBool>,
    /// If we should pause the loop on next iteration.
    paused: Arc<AtomicBool>,
}

impl TriggerSender {
    /// Create a new channel for waking a consumer
    pub fn new() -> (TriggerSender, TriggerReceiver) {
        let (tx, rx) = broadcast::channel(1);
        (
            TriggerSender {
                trigger: tx,
                reset_back_off: None,
                pause_back_off: None,
                telemetry: Arc::new(OnceLock::new()),
            },
            TriggerReceiver {
                rx,
                back_off: None,
                reset_on_trigger: false,
            },
        )
    }

    /// Create a new channel trigger that will also trigger
    /// on a loop.
    /// The duration takes a range so that the loop  can
    /// be set to back off from the lowest to the highest duration.
    /// If you do not want a back off, set the duration range
    /// to the same value like: `Duration::from_millis(10)..Duration::from_millis(10)`
    /// If reset_on_trigger is true, the back off will be reset whenever a
    /// trigger is received.
    pub fn new_with_loop(
        range: Range<Duration>,
        reset_on_trigger: bool,
    ) -> (TriggerSender, TriggerReceiver) {
        let (tx, rx) = broadcast::channel(1);
        let reset_back_off = Arc::new(AtomicBool::new(false));
        let pause_back_off = Arc::new(AtomicBool::new(false));
        (
            TriggerSender {
                trigger: tx,
                reset_back_off: Some(reset_back_off.clone()),
                pause_back_off: Some(pause_back_off.clone()),
                telemetry: Arc::new(OnceLock::new()),
            },
            TriggerReceiver {
                rx,
                reset_on_trigger,
                back_off: Some(BackOff::new(range, reset_back_off, pause_back_off)),
            },
        )
    }

    /// Lazily nudge the consumer task, ignoring the case where the consumer
    /// already has a pending trigger signal
    pub fn trigger(&self, context: &'static &'static str) {
        let delivered = self.trigger.send(context).is_ok();
        if let Some(telemetry) = self.telemetry.get() {
            if let Some(gate) = workflow_diagnostics() {
                gate.emit_notification(telemetry, context, delivered);
            }
        }
        if !delivered {
            tracing::warn!(
                "Queue consumer trigger was sent while Cell is shutting down: ignoring."
            );
        };
    }

    fn configure_telemetry(&self, workflow: &str, dna_hash: &DnaHash, cell_token: Option<u64>) {
        let _ = self.telemetry.set(TriggerTelemetry {
            workflow: workflow.to_string(),
            dna_hash: dna_hash.to_string(),
            cell_token,
        });
    }

    /// Reset the back off to the lowest duration.
    /// If no back off is set this is a no-op.
    pub fn reset_back_off(&self) {
        if let Some(tx) = &self.reset_back_off {
            tx.store(true, Ordering::Relaxed);
        }
    }

    /// Pause the trigger loop if there is one.
    pub fn pause_loop(&self) {
        if let Some(pause) = &self.pause_back_off {
            pause.store(true, Ordering::Relaxed);
        }
    }

    /// Resume the trigger loop now if there is one.
    ///
    /// This will resume the loop even if it is currently
    /// listening (the workflow is not running).
    /// The downside to this call is that if the workflow
    /// is running it will immediately run a second time.
    ///
    /// This call is a no-op if the loop is not paused.
    pub fn resume_loop_now(&self) {
        if let Some(pause) = &self.pause_back_off {
            if pause.fetch_and(false, Ordering::AcqRel) {
                self.trigger(&"resume_loop_now");
            }
        }
    }

    /// Resume the trigger loop if there is one.
    ///
    /// This will cause the loop to resume after the
    /// next trigger (or if the workflow is currently in progress).
    /// It will not cause the loop to resume immediately.
    /// If the loop is currently listening (the workflow is not running)
    /// then nothing will happen until the next trigger.
    /// See `resume_loop_now` for a version that will resume immediately.
    ///
    /// This call is a no-op if the loop is not paused.
    pub fn resume_loop(&self) {
        if let Some(pause) = &self.pause_back_off {
            pause.store(false, Ordering::Release);
        }
    }
}

impl TriggerReceiver {
    /// Listen for one or more items to come through, draining the channel
    /// each time. Bubble up errors on empty channel.
    pub async fn listen(&mut self) -> Result<(), QueueTriggerClosedError> {
        self.listen_with_reason().await.map(|_| ())
    }

    async fn listen_with_reason(&mut self) -> Result<TriggerWake, QueueTriggerClosedError> {
        let Self {
            back_off,
            rx,
            reset_on_trigger,
        } = self;

        let mut wake: TriggerWake;
        {
            // Create the trigger future
            let trigger_fut = rx_fut(rx);
            match back_off {
                // We have a back off loop that is running.
                Some(back_off) if !back_off.is_paused() => {
                    let paused = back_off.paused.clone();
                    {
                        // Get the back off future.
                        let back_off_fut = back_off.wait();
                        futures::pin_mut!(back_off_fut, trigger_fut);

                        // Race between either a trigger or the loop.
                        match futures::future::select(trigger_fut, back_off_fut).await {
                            Either::Left((result, _)) => {
                                // We got a trigger, check the result and drop the wait future.
                                let context = result?;
                                wake = TriggerWake::Notification {
                                    class: trigger_class(context),
                                    coalesced: context == "coalesced",
                                };
                            }
                            Either::Right((_, trigger_fut)) => {
                                // We got the loop future.
                                if paused.load(Ordering::Acquire) {
                                    // If we are now paused then we should wait for a trigger.
                                    let context = trigger_fut.await?;
                                    wake = TriggerWake::Notification {
                                        class: trigger_class(context),
                                        coalesced: context == "coalesced",
                                    };
                                } else {
                                    wake = TriggerWake::Loop;
                                }
                            }
                        }
                    }
                }
                _ => {
                    // We either have no back off loop or it's paused
                    // so wait for a trigger.
                    let context = trigger_fut.await?;
                    wake = TriggerWake::Notification {
                        class: trigger_class(context),
                        coalesced: context == "coalesced",
                    };
                }
            }
        }
        // We want to flush the buffer if a trigger
        // that woke the listen.
        if matches!(wake, TriggerWake::Notification { .. }) {
            // Do one try recv to empty the buffer.
            // This is needed as we can't have an empty buffer
            // but we don't want a second trigger to be stored in
            // the buffer and cause the workflow to run twice.
            let coalesced = self.rx.try_recv().is_ok();
            if coalesced {
                if let TriggerWake::Notification { coalesced, .. } = &mut wake {
                    *coalesced = true;
                }
            }

            // If we have a back off loop and got a trigger then
            // we should reset the back off if that flag is on.
            if *reset_on_trigger {
                if let Some(back_off) = back_off {
                    back_off.reset();
                }
            }
        }
        Ok(wake)
    }

    /// Check whether the backoff loop is paused. Will always return false if there is no backoff for this receiver.
    pub fn is_paused(&self) -> bool {
        self.back_off.as_ref().is_some_and(|b| b.is_paused())
    }

    /// Try to receive a trigger without blocking.
    #[cfg(test)]
    pub fn try_recv(&mut self) -> Option<&'static &'static str> {
        self.rx.try_recv().ok()
    }
}

/// Create a future that will be ok with either a recv or a lagged.
async fn rx_fut(
    rx: &mut broadcast::Receiver<&'static &'static str>,
) -> Result<&'static str, QueueTriggerClosedError> {
    match rx.recv().await {
        Ok(context) => {
            tracing::trace!(msg = "trigger received", ?context);
            Ok(*context)
        }
        Err(broadcast::error::RecvError::Closed) => Err(QueueTriggerClosedError),
        Err(broadcast::error::RecvError::Lagged(_)) => Ok("coalesced"),
    }
}

impl BackOff {
    fn new(
        range: Range<Duration>,
        reset_back_off: Arc<AtomicBool>,
        pause_back_off: Arc<AtomicBool>,
    ) -> Self {
        Self {
            start: range.start,
            range,
            reset_back_off,
            paused: pause_back_off,
        }
    }

    async fn wait(&mut self) {
        // Check if we should reset the back off.
        if self.reset_back_off.fetch_and(false, Ordering::Relaxed) {
            self.reset();
        }
        // If the range is empty we are just looping.
        let dur = if self.range.is_empty() {
            self.range.end
        } else {
            // If not we take the current start value.
            self.range.start
        };
        // Sleep this task for the chosen duration.
        // This future may be cancelled during this await,
        // and any code following will not be executed.
        tokio::time::sleep(dur).await;
        // If the sleep completes then we bump the start of the range
        // or take the end if we have reached the end.
        self.range.start = std::cmp::min(self.range.start * 2, self.range.end);
    }

    fn reset(&mut self) {
        self.range.start = self.start;
    }

    fn is_paused(&self) -> bool {
        self.paused.load(Ordering::Acquire)
    }
}

/// Declares whether a workflow has exhausted the queue or not
#[derive(Clone, Debug, PartialEq)]
pub enum WorkComplete {
    /// The queue has been exhausted
    Complete,
    /// Items still remain on the queue. Optionally specify a delay in ms before retriggering.
    Incomplete(Option<Duration>),
}

/// The only error possible when attempting to trigger: the channel is closed
#[derive(Debug, Display, thiserror::Error)]
pub struct QueueTriggerClosedError;

/// Get a stream of triggers which can be terminated by a received Stop
pub(super) fn trigger_stream(
    rx: TriggerReceiver,
    stop: StopReceiver,
) -> impl Stream<Item = TriggerWake> {
    stop.fuse_with(Box::pin(futures::stream::unfold(rx, |mut rx| async move {
        match rx.listen_with_reason().await {
            Ok(wake) => Some((wake, rx)),
            Err(_) => None,
        }
    })))
}

struct WorkflowRunTrace {
    gate: Arc<WorkflowDiagnosticGate>,
    run_id: u64,
    workflow: String,
    dna_hash: String,
    cell_token: Option<u64>,
    trigger_class: &'static str,
    wake_source: &'static str,
    started: Instant,
    outcome: &'static str,
}

impl WorkflowRunTrace {
    fn finish(&mut self, outcome: &'static str) {
        self.outcome = outcome;
    }
}

impl Drop for WorkflowRunTrace {
    fn drop(&mut self) {
        let gate = self.gate.clone();
        gate.finish_run(self);
    }
}

/// How long to wait before re-running a workflow that failed with a non-fatal
/// error.
const WORKFLOW_ERROR_RETRY_DELAY: Duration = Duration::from_secs(1);

async fn queue_consumer_main_task_impl<
    Fut: 'static + Send + Future<Output = WorkflowResult<WorkComplete>>,
>(
    name: String,
    dna_hash: Arc<DnaHash>,
    _agent: Option<AgentPubKey>,
    cell_token: Option<u64>,
    (tx, rx): (TriggerSender, TriggerReceiver),
    stop: StopReceiver,
    mut fut: impl 'static + Send + FnMut() -> Fut,
) -> ManagedTaskResult {
    let mut triggers = trigger_stream(rx, stop);
    let run_metrics = create_workflow_run_metrics(name.clone(), dna_hash.clone());
    loop {
        if let Some(wake) = triggers.next().await {
            let trigger = match wake {
                TriggerWake::Notification { class, .. } => class,
                TriggerWake::Loop => "loop",
            };
            let metric_guard = run_metrics.started(trigger);
            let diagnostic_gate = workflow_diagnostics();
            if let Some(gate) = diagnostic_gate.as_ref() {
                gate.emit_wakeup(&name, &dna_hash, cell_token, wake);
            }
            // Reserve the start and finish as a pair so the event cap cannot
            // admit an unmatched run while the diagnostic window is active.
            let mut trace_guard =
                diagnostic_gate.and_then(|gate| gate.start_run(&name, &dna_hash, cell_token, wake));
            match fut().await {
                Ok(WorkComplete::Incomplete(delay)) => {
                    tracing::debug!("Work incomplete, re-triggering workflow - {}.", name);
                    if let Some(trace_guard) = &mut trace_guard {
                        trace_guard.finish("incomplete");
                    }
                    metric_guard.finish("incomplete");
                    drop(trace_guard);
                    if let Some(dly) = delay {
                        tracing::debug!(
                            "Sleeping for {} ms before re-triggering - {}.",
                            dly.as_millis(),
                            name
                        );
                        tokio::time::sleep(dly).await;
                    }
                    tx.trigger(&"retrigger");
                }
                Err(err) if err.workflow_should_bail() => {
                    if let Some(trace_guard) = &mut trace_guard {
                        trace_guard.finish("fatal_error");
                    }
                    metric_guard.finish("fatal_error");
                    return handle_workflow_error(&name, err);
                }
                Err(err) => {
                    // A non-fatal error like a database write error due to
                    // multiple threads trying to write means this run consumed
                    // its trigger but did no useful work.
                    // Retrigger the workflow after a delay.
                    handle_workflow_error(&name, err)?;
                    if let Some(trace_guard) = &mut trace_guard {
                        trace_guard.finish("retryable_error");
                    }
                    metric_guard.finish("retryable_error");
                    drop(trace_guard);
                    tokio::time::sleep(WORKFLOW_ERROR_RETRY_DELAY).await;
                    tx.trigger(&"retry after error");
                }
                Ok(WorkComplete::Complete) => {
                    if let Some(trace_guard) = &mut trace_guard {
                        trace_guard.finish("complete");
                    }
                    metric_guard.finish("complete");
                }
            }
        } else {
            tracing::info!("Cell is shutting down: stopping queue consumer '{}'", name);
            break;
        }
    }
    ManagedTaskResult::Ok(())
}

fn queue_consumer_dna_bound<Fut: 'static + Send + Future<Output = WorkflowResult<WorkComplete>>>(
    name: &str,
    dna_hash: Arc<DnaHash>,
    tm: TaskManagerClient,
    (tx, rx): (TriggerSender, TriggerReceiver),
    fut: impl 'static + Send + FnMut() -> Fut,
) {
    let workflow_name = name.to_string();
    let task_dna_hash = dna_hash.clone();
    tx.configure_telemetry(name, &dna_hash, None);
    tm.add_dna_task_critical(name, dna_hash, {
        move |stop| {
            queue_consumer_main_task_impl(
                workflow_name,
                task_dna_hash,
                None,
                None,
                (tx, rx),
                stop,
                fut,
            )
        }
    });
}

fn queue_consumer_cell_bound<
    Fut: 'static + Send + Future<Output = WorkflowResult<WorkComplete>>,
>(
    name: &str,
    cell_id: CellId,
    tm: TaskManagerClient,
    (tx, rx): (TriggerSender, TriggerReceiver),
    fut: impl 'static + Send + FnMut() -> Fut,
) {
    let workflow_name = name.to_string();
    let dna_hash = cell_id.dna_hash().clone();
    let agent = cell_id.agent_pubkey().clone();
    let (cell_token, cell_token_lease) = cell_trace_token(&cell_id);
    tx.configure_telemetry(name, &dna_hash, Some(cell_token));
    tm.add_cell_task_critical(name, cell_id, {
        move |stop| {
            let _cell_token_lease = cell_token_lease;
            queue_consumer_main_task_impl(
                workflow_name,
                Arc::new(dna_hash),
                Some(agent),
                Some(cell_token),
                (tx, rx),
                stop,
                fut,
            )
        }
    });
}

/// Does nothing.
/// Does extra nothing and logs about it if the error shouldn't bail the
/// workflow.
fn handle_workflow_error(workflow_name: &String, err: WorkflowError) -> ManagedTaskResult {
    if err.workflow_should_bail() {
        Err(Box::new(ConductorError::from(err)).into())
    } else {
        tracing::error!(?workflow_name, ?err);
        Ok(())
    }
}
