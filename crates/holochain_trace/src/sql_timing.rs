//! Bounded, private SQLx statement timing capture.

use crate::diagnostic_identity::{kernel_monotonic_ms, DiagnosticProcessIdentity};
use crate::errors::TracingError;
use crate::private_capture::{valid_capture_nonce, PrivateCaptureDirectory};
use ring::{hmac, rand as ring_rand};
use serde_json::{json, Value};
use std::fmt::Write as _;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    fs::File,
    io::Write,
    path::Path,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Condvar, Mutex, OnceLock, TryLockError, Weak,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
#[cfg(test)]
use std::{fs::OpenOptions, io, path::PathBuf};
use tracing::{Event, Metadata, Subscriber};
use tracing_core::field::{Field, Visit};
use tracing_core::subscriber::Interest;
use tracing_subscriber::{
    layer::{Context, Filter},
    Layer,
};

const WINDOW_ENV: &str = "HOLOCHAIN_SQL_DIAGNOSTICS_SECONDS";
const DIRECTORY_ENV: &str = "HOLOCHAIN_SQL_DIAGNOSTICS_DIR";
const LEGACY_OUTPUT_ENV: &str = "HOLOCHAIN_SQL_DIAGNOSTICS_OUTPUT";
const MAX_WINDOW_SECONDS: u64 = 900;
const MAX_EVENTS: u64 = 10_000;
const MAX_GENERATIONS: u8 = 16;
const MAX_IDENTITIES: usize = 4_096;
const MAX_SQL_BYTES: usize = 64 * 1024;
const MAX_OUTPUT_BYTES: usize = 2 * 1024 * 1024;
const SQLX_TARGET: &str = "sqlx::query";
pub(crate) const SQL_SITE_TARGET: &str = "holochain::sql_site";
const MAX_SOURCE_SITES_PER_IDENTITY: usize = 4;
static SQL_CONTROLLER: OnceLock<Option<Arc<SqlTimingController>>> = OnceLock::new();
static DISABLED_SQL_REQUESTS: AtomicU64 = AtomicU64::new(0);

const SOURCE_SITE_IDS: [&str; 5] = [
    "dht.publish.select_ready",
    "dht.publish.pending_count",
    "dht.publish.record_sent",
    "dht.validation.sys.pending_ops",
    "dht.validation.app.pending_ops",
];

#[derive(Clone)]
pub(crate) struct SqlTimingLayer {
    controller: Arc<SqlTimingController>,
}

/// Finalizes an active SQL timing generation on graceful shutdown.
pub struct SqlTimingGuard {
    controller: Option<Arc<SqlTimingController>>,
}

impl SqlTimingGuard {
    fn disabled() -> Self {
        Self { controller: None }
    }
}

impl Drop for SqlTimingGuard {
    fn drop(&mut self) {
        if let Some(controller) = &self.controller {
            controller.close_active("shutdown_before_expiry");
        }
    }
}

/// Internal admission outcome mapped onto the conductor admin wire by `holochain`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SqlCaptureOutcome {
    /// A new generation is active.
    Admitted,
    /// Startup authorization was absent.
    RefusedDisabled,
    /// Another generation or its terminal serialization is active.
    RefusedBusy,
    /// The nonce was already retained in this process.
    RefusedDuplicateNonce,
    /// The process-lifetime generation budget is exhausted.
    RefusedGenerationBudget,
    /// Version, nonce, or duration validation failed.
    RefusedInvalidRequest,
    /// Private artifact or timer setup failed.
    RefusedIo,
}

/// Process-lifetime counters after one SQL timing admission decision.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SqlCaptureCounters {
    /// Admitted generations.
    pub admitted: u64,
    /// Disabled refusals.
    pub refused_disabled: u64,
    /// Busy refusals.
    pub refused_busy: u64,
    /// Duplicate-nonce refusals.
    pub refused_duplicate_nonce: u64,
    /// Generation-budget refusals.
    pub refused_generation_budget: u64,
    /// Strict-validation refusals.
    pub refused_invalid_request: u64,
    /// Private I/O or timer refusals.
    pub refused_io: u64,
}

/// Immediate result of requesting a SQL timing generation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SqlCaptureAdmission {
    /// Typed immediate result.
    pub outcome: SqlCaptureOutcome,
    /// Actual process producer identifier on admission.
    pub producer_id: Option<String>,
    /// Process-local generation on admission.
    pub generation: Option<u8>,
    /// Private artifact basename on admission.
    pub output_basename: Option<String>,
    /// Saturating process-lifetime counters after this decision.
    pub counters: SqlCaptureCounters,
}

#[derive(Default)]
struct AdmissionCounterAtoms {
    admitted: AtomicU64,
    refused_disabled: AtomicU64,
    refused_busy: AtomicU64,
    refused_duplicate_nonce: AtomicU64,
    refused_generation_budget: AtomicU64,
    refused_invalid_request: AtomicU64,
    refused_io: AtomicU64,
}

impl AdmissionCounterAtoms {
    fn increment(&self, outcome: SqlCaptureOutcome) {
        let counter = match outcome {
            SqlCaptureOutcome::Admitted => &self.admitted,
            SqlCaptureOutcome::RefusedDisabled => &self.refused_disabled,
            SqlCaptureOutcome::RefusedBusy => &self.refused_busy,
            SqlCaptureOutcome::RefusedDuplicateNonce => &self.refused_duplicate_nonce,
            SqlCaptureOutcome::RefusedGenerationBudget => &self.refused_generation_budget,
            SqlCaptureOutcome::RefusedInvalidRequest => &self.refused_invalid_request,
            SqlCaptureOutcome::RefusedIo => &self.refused_io,
        };
        let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            Some(value.saturating_add(1))
        });
    }

    fn snapshot(&self) -> SqlCaptureCounters {
        let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        SqlCaptureCounters {
            admitted: load(&self.admitted),
            refused_disabled: load(&self.refused_disabled),
            refused_busy: load(&self.refused_busy),
            refused_duplicate_nonce: load(&self.refused_duplicate_nonce),
            refused_generation_budget: load(&self.refused_generation_budget),
            refused_invalid_request: load(&self.refused_invalid_request),
            refused_io: load(&self.refused_io),
        }
    }
}

struct SqlTimingController {
    directory: PrivateCaptureDirectory,
    producer_id: String,
    state: Mutex<ControllerState>,
    counters: AdmissionCounterAtoms,
}

#[derive(Default)]
struct ControllerState {
    generations: u8,
    retained_nonces: BTreeSet<String>,
    active: Option<Arc<State>>,
}

struct State {
    generation: u8,
    nonce: String,
    output_basename: String,
    owner: Weak<SqlTimingController>,
    producer_id: String,
    process_id: u32,
    requested: Duration,
    started: Instant,
    started_unix_ms: u128,
    native_process: Option<DiagnosticProcessIdentity>,
    started_monotonic_ms: Option<f64>,
    key: hmac::Key,
    closed: AtomicBool,
    stop: (Mutex<bool>, Condvar),
    data: Mutex<CaptureData>,
    output: Mutex<OutputFile>,
}

struct OutputFile {
    file: File,
    bytes_written: usize,
}

#[derive(Default)]
struct CaptureData {
    observed_events: u64,
    aggregated_events: u64,
    dropped_events: u64,
    missing_statement_events: u64,
    oversize_statement_events: u64,
    identity_overflow_events: u64,
    malformed_elapsed_events: u64,
    malformed_statement_events: u64,
    arithmetic_overflow_events: u64,
    unattributed_events: u64,
    unmapped_source_site_events: u64,
    source_site_overflow_events: u64,
    aggregates: BTreeMap<[u8; 32], Aggregate>,
}

#[derive(Default)]
struct Aggregate {
    count: u64,
    total_elapsed_seconds: f64,
    max_elapsed_seconds: f64,
    rows_affected: Option<u64>,
    rows_returned: Option<u64>,
    rows_affected_complete: bool,
    rows_returned_complete: bool,
    source_site_ids: BTreeSet<&'static str>,
    unattributed_events: u64,
    unmapped_source_site_events: u64,
    source_site_overflow_events: u64,
}

#[derive(Clone, Copy)]
enum SourceSite {
    Attributed(&'static str),
    Unattributed,
    Unmapped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecordClosure {
    Expiry,
    EventLimit,
    ArithmeticOverflow,
}

impl RecordClosure {
    const fn reason(self) -> &'static str {
        match self {
            Self::Expiry => "expiry",
            Self::EventLimit => "event_limit",
            Self::ArithmeticOverflow => "arithmetic_overflow",
        }
    }
}

impl SqlTimingLayer {
    pub(crate) fn from_env() -> Result<(Option<Self>, SqlTimingGuard), TracingError> {
        if std::env::var_os(LEGACY_OUTPUT_ENV).is_some() {
            return Err(error(format!(
                "{LEGACY_OUTPUT_ENV} is retired; authorize a private directory with {DIRECTORY_ENV}"
            )));
        }
        let directory = std::env::var_os(DIRECTORY_ENV).filter(|value| !value.is_empty());
        let seconds = configured_seconds()?;
        let controller = match directory {
            Some(directory) => Arc::new(SqlTimingController::new(Path::new(&directory))?),
            None if seconds.is_some() => {
                return Err(error(format!(
                    "{DIRECTORY_ENV} is required when {WINDOW_ENV} enables a startup capture"
                )))
            }
            None => {
                let _ = SQL_CONTROLLER.set(None);
                return Ok((None, SqlTimingGuard::disabled()));
            }
        };
        SQL_CONTROLLER
            .set(Some(Arc::clone(&controller)))
            .map_err(|_| error("SQL timing controller was initialized more than once".into()))?;
        if let Some(seconds) = seconds {
            let admission = controller.admit(1, "startup", seconds);
            if admission.outcome != SqlCaptureOutcome::Admitted {
                return Err(error(format!(
                    "startup SQL timing capture was refused: {:?}",
                    admission.outcome
                )));
            }
        }
        Ok((
            Some(Self {
                controller: Arc::clone(&controller),
            }),
            SqlTimingGuard {
                controller: Some(controller),
            },
        ))
    }
}

impl<S> Layer<S> for SqlTimingLayer
where
    S: Subscriber + for<'lookup> tracing_subscriber::registry::LookupSpan<'lookup>,
{
    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        if event.metadata().target() != SQLX_TARGET {
            return;
        }
        let Some(state) = self.controller.active() else {
            return;
        };
        let mut visitor = QueryVisitor::new(&state.key);
        event.record(&mut visitor);
        if let Some(closure) = state.record_with_site(visitor, source_site(&ctx, event)) {
            state.close(closure.reason());
        }
    }
}

impl<S> Filter<S> for SqlTimingLayer
where
    S: Subscriber + for<'lookup> tracing_subscriber::registry::LookupSpan<'lookup>,
{
    fn enabled(&self, metadata: &Metadata<'_>, _ctx: &Context<'_, S>) -> bool {
        matches!(metadata.target(), SQLX_TARGET | SQL_SITE_TARGET) && self.controller.has_active()
    }

    fn callsite_enabled(&self, metadata: &'static Metadata<'static>) -> Interest {
        if matches!(metadata.target(), SQLX_TARGET | SQL_SITE_TARGET) {
            Interest::sometimes()
        } else {
            Interest::never()
        }
    }
}

/// Request one bounded SQL timing generation from the startup-authorized controller.
pub fn capture_sql_timing(
    schema_version: u8,
    nonce: &str,
    requested_seconds: u64,
) -> SqlCaptureAdmission {
    match SQL_CONTROLLER.get().and_then(Option::as_ref) {
        Some(controller) => controller.admit(schema_version, nonce, requested_seconds),
        None => {
            let _ =
                DISABLED_SQL_REQUESTS.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                    Some(value.saturating_add(1))
                });
            let counters = SqlCaptureCounters {
                refused_disabled: DISABLED_SQL_REQUESTS.load(Ordering::Relaxed),
                ..Default::default()
            };
            SqlCaptureAdmission {
                outcome: SqlCaptureOutcome::RefusedDisabled,
                producer_id: None,
                generation: None,
                output_basename: None,
                counters,
            }
        }
    }
}

impl SqlTimingController {
    fn new(path: &Path) -> Result<Self, TracingError> {
        let directory = PrivateCaptureDirectory::open(path).map_err(|cause| {
            error(format!(
                "could not open startup-authorized private directory: {}",
                cause.kind()
            ))
        })?;
        let process_id = std::process::id();
        Ok(Self {
            directory,
            producer_id: format!("sql-{process_id:x}-{:x}", unix_millis()),
            state: Mutex::new(ControllerState::default()),
            counters: AdmissionCounterAtoms::default(),
        })
    }

    fn admission(&self, outcome: SqlCaptureOutcome, state: Option<&State>) -> SqlCaptureAdmission {
        self.counters.increment(outcome);
        SqlCaptureAdmission {
            outcome,
            producer_id: state.map(|_| self.producer_id.clone()),
            generation: state.map(|state| state.generation),
            output_basename: state.map(|state| state.output_basename.clone()),
            counters: self.counters.snapshot(),
        }
    }

    fn admit(
        self: &Arc<Self>,
        schema_version: u8,
        nonce: &str,
        requested_seconds: u64,
    ) -> SqlCaptureAdmission {
        if schema_version != 1 || !valid_request(nonce, requested_seconds) {
            return self.admission(SqlCaptureOutcome::RefusedInvalidRequest, None);
        }
        let mut controller = match self.state.try_lock() {
            Ok(controller) => controller,
            Err(TryLockError::WouldBlock) | Err(TryLockError::Poisoned(_)) => {
                return self.admission(SqlCaptureOutcome::RefusedBusy, None)
            }
        };
        if controller.active.is_some() {
            return self.admission(SqlCaptureOutcome::RefusedBusy, None);
        }
        if controller.retained_nonces.contains(nonce) {
            return self.admission(SqlCaptureOutcome::RefusedDuplicateNonce, None);
        }
        let Some(generation) = controller.generations.checked_add(1) else {
            return self.admission(SqlCaptureOutcome::RefusedGenerationBudget, None);
        };
        if generation > MAX_GENERATIONS {
            return self.admission(SqlCaptureOutcome::RefusedGenerationBudget, None);
        }
        let output_basename = format!("sql-timing-g{generation:02}-{nonce}.jsonl");
        let file = match self.directory.create_new(&output_basename) {
            Ok(file) => file,
            Err(_) => return self.admission(SqlCaptureOutcome::RefusedIo, None),
        };
        let state = match State::new(
            Arc::downgrade(self),
            generation,
            nonce.to_owned(),
            output_basename,
            Duration::from_secs(requested_seconds),
            file,
        ) {
            Ok(state) => Arc::new(state),
            Err(_) => return self.admission(SqlCaptureOutcome::RefusedIo, None),
        };
        controller.generations = generation;
        controller.retained_nonces.insert(nonce.to_owned());
        controller.active = Some(Arc::clone(&state));
        drop(controller);

        let timer_state = Arc::clone(&state);
        if thread::Builder::new()
            .name(format!("sql-timing-g{generation:02}"))
            .spawn(move || timer_state.wait_for_expiry())
            .is_err()
        {
            state.close("timer_error");
            return self.admission(SqlCaptureOutcome::RefusedIo, None);
        }
        self.admission(SqlCaptureOutcome::Admitted, Some(&state))
    }

    fn active(&self) -> Option<Arc<State>> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .active
            .clone()
    }

    fn has_active(&self) -> bool {
        self.state
            .try_lock()
            .map(|state| state.active.is_some())
            .unwrap_or(false)
    }

    fn finish(&self, generation: u8) {
        let mut controller = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if controller
            .active
            .as_ref()
            .is_some_and(|active| active.generation == generation)
        {
            controller.active = None;
        }
    }

    fn close_active(&self, reason: &'static str) {
        if let Some(active) = self.active() {
            active.close(reason);
        }
    }
}

fn valid_request(nonce: &str, requested_seconds: u64) -> bool {
    valid_capture_nonce(nonce) && (1..=MAX_WINDOW_SECONDS).contains(&requested_seconds)
}

impl State {
    fn new(
        owner: Weak<SqlTimingController>,
        generation: u8,
        nonce: String,
        output_basename: String,
        requested: Duration,
        file: File,
    ) -> Result<Self, TracingError> {
        let mut random_key = [0_u8; 32];
        ring_rand::SecureRandom::fill(&ring_rand::SystemRandom::new(), &mut random_key)
            .map_err(|_| error("could not generate capture-local HMAC key".into()))?;
        let process_id = std::process::id();
        let started_unix_ms = unix_millis();
        let producer_id = owner
            .upgrade()
            .map(|owner| owner.producer_id.clone())
            .ok_or_else(|| error("SQL timing controller is unavailable".into()))?;
        let state = Self {
            generation,
            nonce,
            output_basename,
            owner,
            producer_id,
            process_id,
            requested,
            started: Instant::now(),
            started_unix_ms,
            native_process: DiagnosticProcessIdentity::capture().ok(),
            started_monotonic_ms: kernel_monotonic_ms().ok(),
            key: hmac::Key::new(hmac::HMAC_SHA256, &random_key),
            closed: AtomicBool::new(false),
            stop: (Mutex::new(false), Condvar::new()),
            data: Mutex::new(CaptureData::default()),
            output: Mutex::new(OutputFile {
                file,
                bytes_written: 0,
            }),
        };
        random_key.fill(0);
        state.write_json(&json!({
            "diagnostic_schema": 1,
            "diagnostic_kind": "sql_timing_window_started",
            "generation": state.generation,
            "nonce": state.nonce,
            "output_basename": state.output_basename,
            "process_id": state.process_id,
            "producer_id": state.producer_id,
            "started_unix_ms": state.started_unix_ms,
            "native_process": state.native_process.as_ref().map(DiagnosticProcessIdentity::as_json),
            "started_monotonic_ms": state.started_monotonic_ms,
            "requested_seconds": state.requested.as_secs(),
            "event_limit": MAX_EVENTS,
            "identity_limit": MAX_IDENTITIES,
            "source_site_limit": MAX_SOURCE_SITES_PER_IDENTITY,
            "statement_byte_limit": MAX_SQL_BYTES,
            "scope": "completed sqlx::query logger events observed by this layer during the bounded window",
            "limitations": [
                "not a denominator for all database executions",
                "queries with logging disabled or emitted by other drivers are not observed",
                "elapsed time is SQLx QueryLogger lifetime and may include iterator or stream hold time",
                "statement outcome and cancellation are not observed"
            ]
        }))?;
        Ok(state)
    }
    fn wait_for_expiry(self: Arc<Self>) {
        let (lock, wake) = &self.stop;
        let stopped = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let remaining = self.requested.saturating_sub(self.started.elapsed());
        let result = wake.wait_timeout_while(stopped, remaining, |stopped| !*stopped);
        match result {
            Ok((guard, timeout)) => {
                let timed_out = timeout.timed_out();
                drop(guard);
                if timed_out {
                    self.close("expiry");
                }
            }
            Err(poisoned) => {
                drop(poisoned.into_inner());
                eprintln!("SQL timing diagnostics timer synchronization failed");
                self.close("timer_error");
            }
        }
    }

    /// Returns the cutoff which closes the window, if this event reaches one.
    #[cfg(test)]
    fn record(&self, visitor: QueryVisitor) -> Option<RecordClosure> {
        self.record_with_site(visitor, SourceSite::Unattributed)
    }

    fn record_with_site(
        &self,
        visitor: QueryVisitor,
        source_site: SourceSite,
    ) -> Option<RecordClosure> {
        let mut data = self
            .data
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if self.closed.load(Ordering::Acquire) {
            return None;
        }
        if self.started.elapsed() >= self.requested {
            checked_increment(&mut data.dropped_events);
            return Some(RecordClosure::Expiry);
        }
        if data.observed_events >= MAX_EVENTS {
            checked_increment(&mut data.dropped_events);
            return Some(RecordClosure::EventLimit);
        }
        if !checked_increment(&mut data.observed_events) {
            checked_increment(&mut data.arithmetic_overflow_events);
            checked_increment(&mut data.dropped_events);
            return Some(RecordClosure::ArithmeticOverflow);
        }
        let Some(elapsed) = visitor
            .elapsed
            .filter(|value| value.is_finite() && *value >= 0.0)
        else {
            checked_increment(&mut data.malformed_elapsed_events);
            return None;
        };
        let digest = match visitor.statement_digest() {
            StatementDigest::Present(digest) => digest,
            StatementDigest::Missing => {
                checked_increment(&mut data.missing_statement_events);
                return None;
            }
            StatementDigest::Oversize => {
                checked_increment(&mut data.oversize_statement_events);
                return None;
            }
            StatementDigest::Malformed => {
                checked_increment(&mut data.malformed_statement_events);
                return None;
            }
        };
        if !data.aggregates.contains_key(&digest) && data.aggregates.len() >= MAX_IDENTITIES {
            checked_increment(&mut data.identity_overflow_events);
            return None;
        }
        let (
            exists,
            count,
            total_elapsed_seconds,
            rows_affected,
            rows_returned,
            rows_affected_complete,
            rows_returned_complete,
        ) = data
            .aggregates
            .get(&digest)
            .map(|aggregate| {
                (
                    true,
                    aggregate.count,
                    aggregate.total_elapsed_seconds,
                    aggregate.rows_affected,
                    aggregate.rows_returned,
                    aggregate.rows_affected_complete,
                    aggregate.rows_returned_complete,
                )
            })
            .unwrap_or((false, 0, 0.0, None, None, true, true));
        let next_rows_affected = if rows_affected_complete && visitor.rows_affected.is_some() {
            checked_optional_sum(rows_affected, visitor.rows_affected)
        } else {
            Some(None)
        };
        let Some(next_rows_affected) = next_rows_affected else {
            checked_increment(&mut data.arithmetic_overflow_events);
            return None;
        };
        let next_rows_returned = if rows_returned_complete && visitor.rows_returned.is_some() {
            checked_optional_sum(rows_returned, visitor.rows_returned)
        } else {
            Some(None)
        };
        let Some(next_rows_returned) = next_rows_returned else {
            checked_increment(&mut data.arithmetic_overflow_events);
            return None;
        };
        if count.checked_add(1).is_none() || !checked_elapsed_sum(total_elapsed_seconds, elapsed) {
            checked_increment(&mut data.arithmetic_overflow_events);
            return None;
        }
        let aggregate = data.aggregates.entry(digest).or_default();
        aggregate.count += 1;
        aggregate.total_elapsed_seconds += elapsed;
        aggregate.max_elapsed_seconds = aggregate.max_elapsed_seconds.max(elapsed);
        aggregate.rows_affected = next_rows_affected;
        aggregate.rows_returned = next_rows_returned;
        aggregate.rows_affected_complete =
            (if exists { rows_affected_complete } else { true }) && visitor.rows_affected.is_some();
        aggregate.rows_returned_complete =
            (if exists { rows_returned_complete } else { true }) && visitor.rows_returned.is_some();
        match source_site {
            SourceSite::Attributed(source_site) => {
                if !aggregate.source_site_ids.contains(source_site) {
                    if aggregate.source_site_ids.len() < MAX_SOURCE_SITES_PER_IDENTITY {
                        aggregate.source_site_ids.insert(source_site);
                    } else {
                        checked_increment(&mut aggregate.source_site_overflow_events);
                        checked_increment(&mut data.source_site_overflow_events);
                    }
                }
            }
            SourceSite::Unattributed => {
                checked_increment(&mut aggregate.unattributed_events);
                checked_increment(&mut data.unattributed_events);
            }
            SourceSite::Unmapped => {
                checked_increment(&mut aggregate.unmapped_source_site_events);
                checked_increment(&mut data.unmapped_source_site_events);
            }
        }
        checked_increment(&mut data.aggregated_events);
        None
    }

    fn close(&self, reason: &'static str) {
        // This bounds the active interval, not the later serialization/flush time.
        // Scheduling delays must never extend the requested diagnostic window.
        let ended_monotonic_ms = self.started_monotonic_ms.and_then(|started| {
            kernel_monotonic_ms()
                .ok()
                .map(|now| now.min(started + self.requested.as_secs_f64() * 1000.0))
        });
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        if let Ok(mut stopped) = self.stop.0.lock() {
            *stopped = true;
            self.stop.1.notify_all();
        }
        let data = self
            .data
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let no_loss = data.observed_events == data.aggregated_events
            && data.dropped_events == 0
            && data.missing_statement_events == 0
            && data.oversize_statement_events == 0
            && data.identity_overflow_events == 0
            && data.malformed_elapsed_events == 0
            && data.malformed_statement_events == 0
            && data.arithmetic_overflow_events == 0;
        let identities: Vec<Value> = data
            .aggregates
            .iter()
            .map(|(digest, aggregate)| {
                json!({
                    "statement_hmac_sha256": hex(digest),
                    "count": aggregate.count,
                    "total_elapsed_seconds": aggregate.total_elapsed_seconds,
                    "max_elapsed_seconds": aggregate.max_elapsed_seconds,
                    "rows_affected": aggregate.rows_affected,
                    "rows_returned": aggregate.rows_returned,
                    "source_site_ids": aggregate.source_site_ids,
                    "unattributed_events": aggregate.unattributed_events,
                    "unmapped_source_site_events": aggregate.unmapped_source_site_events,
                    "source_site_overflow_events": aggregate.source_site_overflow_events
                })
            })
            .collect();
        let witness = json!({
            "diagnostic_schema": 1,
            "diagnostic_kind": "sql_timing_window_closed",
            "generation": self.generation,
            "nonce": self.nonce,
            "output_basename": self.output_basename,
            "process_id": self.process_id,
            "producer_id": self.producer_id,
            "started_unix_ms": self.started_unix_ms,
            "native_process": self.native_process.as_ref().map(DiagnosticProcessIdentity::as_json),
            "started_monotonic_ms": self.started_monotonic_ms,
            "ended_monotonic_ms": ended_monotonic_ms,
            "ended_unix_ms": unix_millis(),
            "requested_seconds": self.requested.as_secs(),
            "observed_seconds": self.started.elapsed().as_secs_f64(),
            "closure_reason": reason,
            "coverage_complete": reason == "expiry" && no_loss,
            "coverage_scope": "only completed sqlx::query logger events delivered to this layer while its gate was active",
            "observed_events": data.observed_events,
            "aggregated_events": data.aggregated_events,
            "dropped_events": data.dropped_events,
            "missing_statement_events": data.missing_statement_events,
            "oversize_statement_events": data.oversize_statement_events,
            "identity_overflow_events": data.identity_overflow_events,
            "malformed_elapsed_events": data.malformed_elapsed_events,
            "malformed_statement_events": data.malformed_statement_events,
            "arithmetic_overflow_events": data.arithmetic_overflow_events,
            "source_site_limit": MAX_SOURCE_SITES_PER_IDENTITY,
            "unattributed_events": data.unattributed_events,
            "unmapped_source_site_events": data.unmapped_source_site_events,
            "source_site_overflow_events": data.source_site_overflow_events,
            "identities": identities,
            "limitations": [
                "coverage_complete does not establish coverage of all database executions",
                "quiet zero-event capture proves timer lifecycle only",
                "queries with logging disabled or emitted by other drivers are outside this scope",
                "elapsed time is SQLx QueryLogger lifetime and may include iterator or stream hold time",
                "statement outcome and cancellation are not observed",
                "source-site IDs cover only five explicitly instrumented DHT publish and validation helpers",
                "source-site IDs are static metadata names, not SQL text, bind values, or span fields",
                "source-site mapping is partial and does not allocate elapsed time per site"
            ]
        });
        drop(data);
        if let Err(cause) = self.write_json(&witness) {
            // Do not claim a persisted closure when the private file is no longer writable.
            // Error text is deliberately reduced to the I/O class; it cannot include SQL.
            eprintln!(
                "SQL timing diagnostics terminal witness was not persisted (write failure: {})",
                cause
            );
        }
        if let Some(owner) = self.owner.upgrade() {
            owner.finish(self.generation);
        }
    }

    fn write_json(&self, value: &Value) -> Result<(), TracingError> {
        let mut bytes = serde_json::to_vec(value)
            .map_err(|_| error("could not serialize bounded witness".into()))?;
        bytes.push(b'\n');
        if bytes.len() > MAX_OUTPUT_BYTES {
            return Err(error("bounded witness exceeded output byte limit".into()));
        }
        let mut output = self
            .output
            .lock()
            .map_err(|_| error("output lock was poisoned".into()))?;
        let next_size = output
            .bytes_written
            .checked_add(bytes.len())
            .ok_or_else(|| error("output byte accounting overflowed".into()))?;
        if next_size > MAX_OUTPUT_BYTES {
            return Err(error("bounded output file would exceed byte limit".into()));
        }
        output
            .file
            .write_all(&bytes)
            .and_then(|()| output.file.flush())
            .map_err(|cause| error(format!("output write failed: {}", cause.kind())))
            .map(|()| output.bytes_written = next_size)
    }
}

fn source_site<S>(ctx: &Context<'_, S>, event: &Event<'_>) -> SourceSite
where
    S: Subscriber + for<'lookup> tracing_subscriber::registry::LookupSpan<'lookup>,
{
    let Some(span) = ctx.event_scope(event).and_then(|scope| {
        scope
            .from_root()
            .filter(|span| span.metadata().target() == SQL_SITE_TARGET)
            .last()
    }) else {
        return SourceSite::Unattributed;
    };
    source_site_id(span.metadata().name()).map_or(SourceSite::Unmapped, SourceSite::Attributed)
}

fn source_site_id(name: &'static str) -> Option<&'static str> {
    SOURCE_SITE_IDS.contains(&name).then_some(name)
}

struct QueryVisitor<'a> {
    key: &'a hmac::Key,
    elapsed: Option<f64>,
    rows_affected: Option<u64>,
    rows_returned: Option<u64>,
    statement: Candidate,
    summary: Candidate,
}

impl<'a> QueryVisitor<'a> {
    fn new(key: &'a hmac::Key) -> Self {
        Self {
            key,
            elapsed: None,
            rows_affected: None,
            rows_returned: None,
            statement: Candidate::Missing,
            summary: Candidate::Missing,
        }
    }

    fn statement_digest(&self) -> StatementDigest {
        match self.statement {
            Candidate::Digest(digest) => StatementDigest::Present(digest),
            Candidate::Oversize => StatementDigest::Oversize,
            Candidate::Malformed => StatementDigest::Malformed,
            Candidate::Empty => match self.summary {
                Candidate::Digest(digest) => StatementDigest::Present(digest),
                Candidate::Oversize => StatementDigest::Oversize,
                _ => StatementDigest::Missing,
            },
            Candidate::Missing => StatementDigest::Missing,
        }
    }
}

impl Visit for QueryVisitor<'_> {
    fn record_f64(&mut self, field: &Field, value: f64) {
        if field.name() == "elapsed_secs" {
            self.elapsed = Some(value);
        }
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        match field.name() {
            "rows_affected" => self.rows_affected = Some(value),
            "rows_returned" => self.rows_returned = Some(value),
            _ => {}
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        match field.name() {
            "db.statement" if !value.is_empty() => {
                self.statement = match value
                    .strip_prefix("\n\n")
                    .and_then(|value| value.strip_suffix('\n'))
                {
                    Some(exact) => digest(self.key, exact.as_bytes()),
                    None => Candidate::Malformed,
                };
            }
            "db.statement" => self.statement = Candidate::Empty,
            "summary" => self.summary = digest(self.key, value.as_bytes()),
            _ => {}
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        // SQLx 0.9 records `summary`; its message is a slow-query constant.
        if field.name() == "summary" {
            let mut sink = HmacSink::new(self.key);
            self.summary = if write!(&mut sink, "{value:?}").is_ok() {
                sink.finish()
            } else {
                Candidate::Missing
            };
        }
    }
}

#[derive(Clone, Copy)]
enum Candidate {
    Missing,
    Empty,
    Malformed,
    Oversize,
    Digest([u8; 32]),
}

enum StatementDigest {
    Missing,
    Malformed,
    Oversize,
    Present([u8; 32]),
}

struct HmacSink {
    context: hmac::Context,
    bytes: usize,
    oversize: bool,
}

impl HmacSink {
    fn new(key: &hmac::Key) -> Self {
        Self {
            context: hmac::Context::with_key(key),
            bytes: 0,
            oversize: false,
        }
    }

    fn finish(self) -> Candidate {
        if self.oversize {
            Candidate::Oversize
        } else if self.bytes == 0 {
            Candidate::Missing
        } else {
            let mut digest = [0_u8; 32];
            digest.copy_from_slice(self.context.sign().as_ref());
            Candidate::Digest(digest)
        }
    }
}

impl fmt::Write for HmacSink {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        if self.oversize {
            return Ok(());
        }
        self.bytes = self.bytes.checked_add(value.len()).ok_or(fmt::Error)?;
        if self.bytes > MAX_SQL_BYTES {
            self.oversize = true;
            return Ok(());
        }
        if !self.oversize {
            self.context.update(value.as_bytes());
        }
        Ok(())
    }
}

fn digest(key: &hmac::Key, bytes: &[u8]) -> Candidate {
    if bytes.is_empty() {
        Candidate::Missing
    } else if bytes.len() > MAX_SQL_BYTES {
        Candidate::Oversize
    } else {
        let tag = hmac::sign(key, bytes);
        let mut digest = [0_u8; 32];
        digest.copy_from_slice(tag.as_ref());
        Candidate::Digest(digest)
    }
}

fn configured_seconds() -> Result<Option<u64>, TracingError> {
    let Some(raw) = std::env::var_os(WINDOW_ENV) else {
        return Ok(None);
    };
    let raw = raw
        .to_str()
        .ok_or_else(|| error(format!("{WINDOW_ENV} must be valid UTF-8")))?;
    let seconds = raw
        .parse::<u64>()
        .map_err(|_| error(format!("{WINDOW_ENV} must be an integer from 0 to 900")))?;
    match seconds {
        0 => Ok(None),
        1..=MAX_WINDOW_SECONDS => Ok(Some(seconds)),
        _ => Err(error(format!("{WINDOW_ENV} must not exceed 900"))),
    }
}

#[cfg(unix)]
#[cfg(test)]
fn private_new_file(path: &PathBuf) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
#[cfg(test)]
fn private_new_file(path: &PathBuf) -> io::Result<File> {
    OpenOptions::new().write(true).create_new(true).open(path)
}

fn checked_increment(value: &mut u64) -> bool {
    if let Some(next) = value.checked_add(1) {
        *value = next;
        true
    } else {
        false
    }
}

fn checked_elapsed_sum(current: f64, next: f64) -> bool {
    current.is_finite() && next.is_finite() && (current + next).is_finite()
}

fn checked_optional_sum(current: Option<u64>, next: Option<u64>) -> Option<Option<u64>> {
    match (current, next) {
        (Some(current), Some(next)) => current.checked_add(next).map(Some),
        (None, Some(next)) => Some(Some(next)),
        (_, None) => Some(None),
    }
}

fn unix_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn hex(bytes: &[u8; 32]) -> String {
    use fmt::Write as _;
    let mut output = String::with_capacity(64);
    for byte in bytes {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn error(message: String) -> TracingError {
    TracingError::SqlTiming(message)
}

#[cfg(test)]
mod tests;
