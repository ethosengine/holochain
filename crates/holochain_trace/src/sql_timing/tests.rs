use super::*;
use crate::formatter_filter;
use crate::writer::InMemoryWriter;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use tracing_subscriber::{filter::EnvFilter, prelude::*};

fn emit_source_mapping_query() {
    tracing::event!(
        target: SQLX_TARGET,
        tracing::Level::DEBUG,
        "db.statement" = "\n\nSELECT source_mapping_test\n",
        elapsed_secs = 0.1,
        rows_affected = 1_u64,
        rows_returned = 1_u64,
        "source mapping test query"
    );
}

fn timing_subscriber(state: Arc<State>) -> impl tracing::Subscriber {
    let layer = SqlTimingLayer {
        controller: test_controller(state),
    };
    tracing_subscriber::registry().with(layer.clone().with_filter(layer))
}

fn test_controller(state: Arc<State>) -> Arc<SqlTimingController> {
    Arc::new(SqlTimingController {
        directory: PrivateCaptureDirectory::from_descriptor(
            OpenOptions::new()
                .read(true)
                .open(std::env::temp_dir())
                .unwrap(),
        ),
        producer_id: "test-producer".into(),
        state: Mutex::new(ControllerState {
            generations: state.generation,
            retained_nonces: BTreeSet::from([state.nonce.clone()]),
            active: Some(state),
        }),
        counters: AdmissionCounterAtoms::default(),
    })
}

fn test_path(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "holochain-sql-timing-{label}-{}-{}.jsonl",
        std::process::id(),
        unix_millis()
    ))
}

#[cfg(unix)]
fn test_private_directory(label: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "holochain-sql-controller-{label}-{}-{}",
        std::process::id(),
        unix_millis()
    ));
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    path
}

fn test_state(label: &str, requested: Duration) -> (Arc<State>, PathBuf) {
    let path = test_path(label);
    let state = Arc::new(State {
        generation: 1,
        nonce: label.into(),
        output_basename: path.file_name().unwrap().to_string_lossy().into_owned(),
        owner: Weak::new(),
        producer_id: "test-producer".into(),
        process_id: std::process::id(),
        requested,
        started: Instant::now(),
        started_unix_ms: unix_millis(),
        native_process: DiagnosticProcessIdentity::capture().ok(),
        started_monotonic_ms: kernel_monotonic_ms().ok(),
        key: hmac::Key::new(hmac::HMAC_SHA256, &[7; 32]),
        closed: AtomicBool::new(false),
        stop: (Mutex::new(false), Condvar::new()),
        data: Mutex::new(CaptureData::default()),
        output: Mutex::new(OutputFile {
            file: private_new_file(&path).unwrap(),
            bytes_written: 0,
        }),
    });
    (state, path)
}

fn visitor<'a>(state: &'a State, sql: &str, elapsed: f64) -> QueryVisitor<'a> {
    let mut visitor = QueryVisitor::new(&state.key);
    visitor.elapsed = Some(elapsed);
    visitor.rows_affected = Some(2);
    visitor.rows_returned = Some(3);
    visitor.statement = digest(&state.key, sql.as_bytes());
    visitor
}

#[test]
fn full_statement_not_four_word_summary_is_identity() {
    let key = hmac::Key::new(hmac::HMAC_SHA256, &[3; 32]);
    let first = digest(&key, b"SELECT value FROM records WHERE id = 1");
    let second = digest(&key, b"SELECT value FROM records WHERE id = 2");
    match (first, second) {
        (Candidate::Digest(first), Candidate::Digest(second)) => assert_ne!(first, second),
        _ => panic!("bounded statements should hash"),
    }
}

#[test]
fn sqlx_wrapped_and_short_statements_are_recovered_exactly() {
    let key = hmac::Key::new(hmac::HMAC_SHA256, &[5; 32]);
    let mut wrapped = QueryVisitor::new(&key);
    wrapped.record_str(
        &test_field("db.statement"),
        "\n\nSELECT value FROM records WHERE id = 1\n",
    );
    let mut short = QueryVisitor::new(&key);
    short.record_str(&test_field("db.statement"), "");
    short.record_str(&test_field("summary"), "SELECT 1");
    assert!(matches!(
        wrapped.statement_digest(),
        StatementDigest::Present(_)
    ));
    assert!(matches!(
        short.statement_digest(),
        StatementDigest::Present(_)
    ));
}

#[test]
fn oversized_statement_is_rejected_not_prefix_hashed() {
    let key = hmac::Key::new(hmac::HMAC_SHA256, &[5; 32]);
    assert!(matches!(
        digest(&key, &vec![b'x'; MAX_SQL_BYTES + 1]),
        Candidate::Oversize
    ));
}

#[test]
fn malformed_wrapped_statement_never_falls_back_to_a_message_summary() {
    let key = hmac::Key::new(hmac::HMAC_SHA256, &[5; 32]);
    let mut event = QueryVisitor::new(&key);
    event.record_str(&test_field("db.statement"), "SELECT a malformed wrapper");
    event.record_str(&test_field("summary"), "SELECT only a short summary");
    assert!(matches!(
        event.statement_digest(),
        StatementDigest::Malformed
    ));
}

#[test]
fn event_limit_counts_at_most_the_declared_observed_events() {
    let (state, path) = test_state("event-limit", Duration::from_secs(60));
    for _ in 0..MAX_EVENTS {
        assert_eq!(state.record(visitor(&state, "SELECT 1", 0.1)), None);
    }
    assert_eq!(
        state.record(visitor(&state, "SELECT 1", 0.1)),
        Some(RecordClosure::EventLimit)
    );
    let data = state.data.lock().unwrap();
    assert_eq!(data.observed_events, MAX_EVENTS);
    assert_eq!(data.aggregated_events, MAX_EVENTS);
    assert_eq!(data.dropped_events, 1);
    drop(data);
    state.close("event_limit");
    drop(state);
    fs::remove_file(path).unwrap();
}

#[test]
fn elapsed_window_cutoff_reports_expiry_not_event_limit() {
    let (state, path) = test_state("record-expiry", Duration::ZERO);
    assert_eq!(
        state.record(visitor(&state, "SELECT 1", 0.1)),
        Some(RecordClosure::Expiry)
    );
    state.close(RecordClosure::Expiry.reason());
    let output = fs::read_to_string(&path).unwrap();
    assert!(output.contains("\"closure_reason\":\"expiry\""));
    assert!(output.contains("\"dropped_events\":1"));
    assert!(output.contains("\"coverage_complete\":false"));
    drop(state);
    fs::remove_file(path).unwrap();
}

#[test]
fn aggregates_every_retained_identity_and_never_serializes_sql() {
    let (state, path) = test_state("aggregate", Duration::from_secs(60));
    assert_eq!(
        state.record(visitor(&state, "SELECT private_secret FROM vault", 0.25)),
        None
    );
    assert_eq!(
        state.record(visitor(&state, "SELECT private_secret FROM vault", 0.75)),
        None
    );
    state.close("expiry");

    let data = state.data.lock().unwrap();
    assert_eq!(data.observed_events, 2);
    assert_eq!(data.aggregated_events, 2);
    assert_eq!(data.aggregates.len(), 1);
    let aggregate = data.aggregates.values().next().unwrap();
    assert_eq!(aggregate.count, 2);
    assert_eq!(aggregate.total_elapsed_seconds, 1.0);
    drop(data);
    let output = fs::read_to_string(&path).unwrap();
    assert!(!output.contains("private_secret"));
    assert!(output.contains("\"coverage_complete\":true"));
    drop(state);
    fs::remove_file(path).unwrap();
}

#[test]
fn retained_identities_are_not_ranked_or_truncated_by_latency() {
    let (state, path) = test_state("all-identities", Duration::from_secs(60));
    assert_eq!(state.record(visitor(&state, "SELECT slow", 99.0)), None);
    assert_eq!(state.record(visitor(&state, "SELECT fast", 0.001)), None);
    state.close("expiry");

    let output = fs::read_to_string(&path).unwrap();
    assert_eq!(output.matches("statement_hmac_sha256").count(), 2);
    drop(state);
    fs::remove_file(path).unwrap();
}

#[test]
fn formatter_keeps_ordinary_warnings_but_never_formats_sqlx_during_or_after_capture() {
    let (state, path) = test_state("formatter-privacy", Duration::from_secs(60));
    let timing = SqlTimingLayer {
        controller: test_controller(Arc::clone(&state)),
    };
    let output = Arc::new(Mutex::new(Vec::new()));
    let writer = Arc::clone(&output);
    let broad_and_span_filter = EnvFilter::new("trace,[privacy{mode=\"open\"}]=trace");
    let formatter = tracing_subscriber::fmt::layer()
        .with_writer(move || InMemoryWriter::new(Arc::clone(&writer)))
        .with_ansi(false)
        .with_filter(formatter_filter(broad_and_span_filter, true));
    let subscriber = tracing_subscriber::registry()
        .with(timing.clone().with_filter(timing))
        .with(formatter);

    tracing::subscriber::with_default(subscriber, || {
        tracing::warn!("ordinary warning while capture is active");
        let span = tracing::info_span!("privacy", mode = "open");
        let _entered = span.enter();
        tracing::event!(
            target: "sqlx::query",
            tracing::Level::DEBUG,
            "db.statement" = "\n\nSELECT formatter_secret\n",
            elapsed_secs = 0.1,
            "sql event"
        );
        state.close("test_close");
        tracing::event!(
            target: "sqlx::query",
            tracing::Level::DEBUG,
            "db.statement" = "\n\nSELECT formatter_secret_after_close\n",
            elapsed_secs = 0.1,
            "sql event after close"
        );
        tracing::warn!("ordinary warning after capture is closed");
    });
    assert_eq!(state.data.lock().unwrap().aggregated_events, 1);
    let rendered = String::from_utf8(output.lock().unwrap().clone()).unwrap();
    assert!(rendered.contains("ordinary warning while capture is active"));
    assert!(rendered.contains("ordinary warning after capture is closed"));
    assert!(!rendered.contains("formatter_secret"));
    assert!(!rendered.contains("formatter_secret_after_close"));
    drop(state);
    fs::remove_file(path).unwrap();
}

#[test]
fn sqlx_0_9_logger_uses_full_or_explicit_short_statement_identity() {
    use sqlx_core::{connection::LogSettings, logger::QueryLogger, sql_str::SqlStr};

    let (state, path) = test_state("sqlx-producer", Duration::from_secs(60));
    let layer = SqlTimingLayer {
        controller: test_controller(Arc::clone(&state)),
    };
    let subscriber = tracing_subscriber::registry().with(layer.clone().with_filter(layer));
    tracing::subscriber::with_default(subscriber, || {
        let mut normal = QueryLogger::new(SqlStr::from_static("SELECT 1"), LogSettings::default());
        normal.increment_rows_returned();
        drop(normal);

        let mut slow_settings = LogSettings::default();
        slow_settings.log_slow_statements(log::LevelFilter::Warn, Duration::ZERO);
        drop(QueryLogger::new(
            SqlStr::from_static("SELECT alpha"),
            slow_settings.clone(),
        ));
        drop(QueryLogger::new(
            SqlStr::from_static("SELECT beta"),
            slow_settings,
        ));
        drop(QueryLogger::new(
            SqlStr::from_static("SELECT value FROM secrets WHERE id = 7"),
            LogSettings::default(),
        ));
    });
    let data = state.data.lock().unwrap();
    assert_eq!(data.aggregated_events, 4);
    assert_eq!(data.aggregates.len(), 4);
    drop(data);
    state.close("expiry");
    drop(state);
    fs::remove_file(path).unwrap();
}

#[test]
fn nested_unknown_site_does_not_fall_back_to_outer_allowed_site() {
    let (state, path) = test_state("nested-unknown-site", Duration::from_secs(60));
    let subscriber = timing_subscriber(Arc::clone(&state));
    tracing::subscriber::with_default(subscriber, || {
        let outer = tracing::span!(
            target: SQL_SITE_TARGET,
            tracing::Level::TRACE,
            "dht.publish.select_ready"
        );
        let _outer = outer.enter();
        let inner = tracing::span!(
            target: SQL_SITE_TARGET,
            tracing::Level::TRACE,
            "unapproved.site"
        );
        let _inner = inner.enter();
        emit_source_mapping_query();
    });
    let data = state.data.lock().unwrap();
    let aggregate = data.aggregates.values().next().unwrap();
    assert!(aggregate.source_site_ids.is_empty());
    assert_eq!(aggregate.unmapped_source_site_events, 1);
    assert_eq!(aggregate.unattributed_events, 0);
    assert_eq!(data.unmapped_source_site_events, 1);
    drop(data);
    state.close("expiry");
    drop(state);
    fs::remove_file(path).unwrap();
}

#[test]
fn same_statement_retains_multiple_static_sites_without_site_timing() {
    let (state, path) = test_state("multiple-sites", Duration::from_secs(60));
    let subscriber = timing_subscriber(Arc::clone(&state));
    tracing::subscriber::with_default(subscriber, || {
        let first = tracing::span!(
            target: SQL_SITE_TARGET,
            tracing::Level::TRACE,
            "dht.publish.select_ready"
        );
        let _first = first.enter();
        emit_source_mapping_query();
        drop(_first);
        let second = tracing::span!(
            target: SQL_SITE_TARGET,
            tracing::Level::TRACE,
            "dht.validation.sys.pending_ops"
        );
        let _second = second.enter();
        emit_source_mapping_query();
    });
    let data = state.data.lock().unwrap();
    let aggregate = data.aggregates.values().next().unwrap();
    assert_eq!(aggregate.count, 2);
    assert_eq!(
        aggregate.source_site_ids,
        BTreeSet::from(["dht.publish.select_ready", "dht.validation.sys.pending_ops"])
    );
    assert_eq!(aggregate.total_elapsed_seconds, 0.2);
    drop(data);
    state.close("expiry");
    let output = fs::read_to_string(&path).unwrap();
    assert!(!output.contains("source_site_elapsed"));
    drop(state);
    fs::remove_file(path).unwrap();
}

#[test]
fn source_site_cap_and_unattributed_counts_are_explicit() {
    let (state, path) = test_state("site-cap", Duration::from_secs(60));
    let subscriber = timing_subscriber(Arc::clone(&state));
    tracing::subscriber::with_default(subscriber, || {
        let first = tracing::span!(target: SQL_SITE_TARGET, tracing::Level::TRACE, "dht.publish.select_ready");
        let _first = first.enter();
        emit_source_mapping_query();
        drop(_first);
        let second = tracing::span!(target: SQL_SITE_TARGET, tracing::Level::TRACE, "dht.publish.pending_count");
        let _second = second.enter();
        emit_source_mapping_query();
        drop(_second);
        let third = tracing::span!(target: SQL_SITE_TARGET, tracing::Level::TRACE, "dht.publish.record_sent");
        let _third = third.enter();
        emit_source_mapping_query();
        drop(_third);
        let fourth = tracing::span!(target: SQL_SITE_TARGET, tracing::Level::TRACE, "dht.validation.sys.pending_ops");
        let _fourth = fourth.enter();
        emit_source_mapping_query();
        drop(_fourth);
        let fifth = tracing::span!(target: SQL_SITE_TARGET, tracing::Level::TRACE, "dht.validation.app.pending_ops");
        let _fifth = fifth.enter();
        emit_source_mapping_query();
        drop(_fifth);
        emit_source_mapping_query();
    });
    let data = state.data.lock().unwrap();
    let aggregate = data.aggregates.values().next().unwrap();
    assert_eq!(
        aggregate.source_site_ids.len(),
        MAX_SOURCE_SITES_PER_IDENTITY
    );
    assert_eq!(aggregate.source_site_overflow_events, 1);
    assert_eq!(aggregate.unattributed_events, 1);
    assert_eq!(data.source_site_overflow_events, 1);
    assert_eq!(data.unattributed_events, 1);
    drop(data);
    state.close("expiry");
    drop(state);
    fs::remove_file(path).unwrap();
}

#[test]
fn formatter_rejects_reserved_site_target_when_capture_is_disabled() {
    let output = Arc::new(Mutex::new(Vec::new()));
    let writer = Arc::clone(&output);
    let formatter = tracing_subscriber::fmt::layer()
        .with_writer(move || InMemoryWriter::new(Arc::clone(&writer)))
        .with_ansi(false)
        .with_filter(formatter_filter(EnvFilter::new("trace"), false));
    let subscriber = tracing_subscriber::registry().with(formatter);
    tracing::subscriber::with_default(subscriber, || {
        tracing::warn!("ordinary warning with capture disabled");
        let site = tracing::span!(
            target: SQL_SITE_TARGET,
            tracing::Level::TRACE,
            "dht.publish.select_ready",
            forbidden_field = "must_not_render"
        );
        let _entered = site.enter();
        tracing::trace!(target: SQL_SITE_TARGET, forbidden_event_field = "must_not_render");
    });
    let rendered = String::from_utf8(output.lock().unwrap().clone()).unwrap();
    assert!(rendered.contains("ordinary warning with capture disabled"));
    assert!(!rendered.contains("dht.publish.select_ready"));
    assert!(!rendered.contains("must_not_render"));
}

#[test]
fn losses_make_scoped_coverage_incomplete() {
    let (state, path) = test_state("missing", Duration::from_secs(60));
    let mut missing = QueryVisitor::new(&state.key);
    missing.elapsed = Some(0.1);
    assert_eq!(state.record(missing), None);
    state.close("expiry");
    let output = fs::read_to_string(&path).unwrap();
    assert!(output.contains("\"missing_statement_events\":1"));
    assert!(output.contains("\"coverage_complete\":false"));
    drop(state);
    fs::remove_file(path).unwrap();
}

#[test]
fn quiet_window_still_emits_terminal_witness() {
    let (state, path) = test_state("quiet", Duration::from_millis(5));
    let timer_state = Arc::clone(&state);
    let timer = thread::spawn(move || timer_state.wait_for_expiry());
    timer.join().unwrap();
    let output = fs::read_to_string(&path).unwrap();
    assert!(output.contains("\"closure_reason\":\"expiry\""));
    assert!(output.contains("\"observed_events\":0"));
    assert!(output.contains("quiet zero-event capture proves timer lifecycle only"));
    drop(state);
    fs::remove_file(path).unwrap();
}

#[test]
fn delayed_close_cannot_extend_monotonic_capture_interval() {
    let (state, path) = test_state("late-close", Duration::ZERO);
    state.close("expiry");
    let output = fs::read_to_string(&path).unwrap();
    let row: Value = serde_json::from_str(output.trim()).unwrap();
    assert_eq!(row["ended_monotonic_ms"], row["started_monotonic_ms"]);
    drop(state);
    fs::remove_file(path).unwrap();
}

#[test]
fn delayed_timer_uses_remaining_window_not_another_full_window() {
    let (mut state, path) = test_state("late-timer", Duration::from_secs(30));
    Arc::get_mut(&mut state).unwrap().started = Instant::now() - Duration::from_secs(31);
    let started = Instant::now();
    Arc::clone(&state).wait_for_expiry();
    assert!(started.elapsed() < Duration::from_secs(2));
    let output = fs::read_to_string(&path).unwrap();
    assert!(output.contains("\"closure_reason\":\"expiry\""));
    drop(state);
    fs::remove_file(path).unwrap();
}

#[test]
fn graceful_guard_interrupts_timer_without_waiting_for_window() {
    let (state, path) = test_state("shutdown", Duration::from_secs(900));
    let timer_state = Arc::clone(&state);
    let timer = thread::spawn(move || timer_state.wait_for_expiry());
    let started = Instant::now();
    let controller = test_controller(state);
    drop(SqlTimingGuard {
        controller: Some(controller),
    });
    timer.join().unwrap();
    assert!(started.elapsed() < Duration::from_secs(1));
    let output = fs::read_to_string(&path).unwrap();
    assert!(output.contains("\"closure_reason\":\"shutdown_before_expiry\""));
    assert!(output.contains("\"coverage_complete\":false"));
    fs::remove_file(path).unwrap();
}

#[cfg(unix)]
#[test]
fn output_is_private_and_create_new() {
    use std::os::unix::fs::PermissionsExt;
    let path = test_path("private");
    let file = private_new_file(&path).unwrap();
    assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0o600);
    assert_eq!(
        private_new_file(&path).unwrap_err().kind(),
        io::ErrorKind::AlreadyExists
    );
    drop(file);
    fs::remove_file(path).unwrap();
}

#[cfg(unix)]
#[test]
fn controller_rearms_sequentially_and_old_generation_cannot_close_new() {
    let directory = test_private_directory("sequential");
    let controller = Arc::new(SqlTimingController::new(&directory).unwrap());

    let first = controller.admit(1, "first", 60);
    assert_eq!(first.outcome, SqlCaptureOutcome::Admitted);
    assert_eq!(first.generation, Some(1));
    let first_state = controller.active().unwrap();
    assert_eq!(
        controller.admit(1, "second", 60).outcome,
        SqlCaptureOutcome::RefusedBusy
    );
    first_state.close("test_close");
    assert_eq!(
        controller.admit(1, "first", 60).outcome,
        SqlCaptureOutcome::RefusedDuplicateNonce
    );

    let second = controller.admit(1, "second", 60);
    assert_eq!(second.outcome, SqlCaptureOutcome::Admitted);
    assert_eq!(second.generation, Some(2));
    first_state.close("late_old_timer");
    assert_eq!(controller.active().unwrap().generation, 2);
    controller.close_active("test_close");

    let first_output = fs::read_to_string(directory.join(first.output_basename.unwrap())).unwrap();
    assert!(first_output.contains("\"nonce\":\"first\""));
    assert!(first_output.contains("\"generation\":1"));
    let second_output =
        fs::read_to_string(directory.join(second.output_basename.unwrap())).unwrap();
    assert!(second_output.contains("\"nonce\":\"second\""));
    assert!(second_output.contains("\"generation\":2"));
    fs::remove_dir_all(directory).unwrap();
}

#[cfg(unix)]
#[test]
fn terminal_serialization_remains_busy_and_request_caps_are_strict() {
    let directory = test_private_directory("terminal-busy");
    let controller = Arc::new(SqlTimingController::new(&directory).unwrap());
    assert_eq!(
        controller.admit(0, "bad-version", 1).outcome,
        SqlCaptureOutcome::RefusedInvalidRequest
    );
    assert_eq!(
        controller.admit(1, "../path", 1).outcome,
        SqlCaptureOutcome::RefusedInvalidRequest
    );
    assert_eq!(
        controller.admit(1, "too-long", 901).outcome,
        SqlCaptureOutcome::RefusedInvalidRequest
    );
    assert_eq!(
        controller.admit(1, "terminal", 60).outcome,
        SqlCaptureOutcome::Admitted
    );
    let active = controller.active().unwrap();
    let output_guard = active.output.lock().unwrap();
    let closing = Arc::clone(&active);
    let closer = thread::spawn(move || closing.close("test_close"));
    let deadline = Instant::now() + Duration::from_secs(2);
    while !active.closed.load(Ordering::Acquire) {
        assert!(Instant::now() < deadline);
        thread::yield_now();
    }
    assert_eq!(
        controller.admit(1, "next", 60).outcome,
        SqlCaptureOutcome::RefusedBusy
    );
    drop(output_guard);
    closer.join().unwrap();
    fs::remove_dir_all(directory).unwrap();
}

#[cfg(unix)]
#[test]
fn generation_budget_and_counters_saturate() {
    let directory = test_private_directory("budget");
    let controller = Arc::new(SqlTimingController::new(&directory).unwrap());
    controller.state.lock().unwrap().generations = MAX_GENERATIONS;
    assert_eq!(
        controller.admit(1, "budget", 1).outcome,
        SqlCaptureOutcome::RefusedGenerationBudget
    );
    controller
        .counters
        .refused_busy
        .store(u64::MAX, Ordering::Relaxed);
    let response = controller.admission(SqlCaptureOutcome::RefusedBusy, None);
    assert_eq!(response.counters.refused_busy, u64::MAX);
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn global_api_is_default_off_without_controller_initialization() {
    let response = capture_sql_timing(1, "default-off", 1);
    assert_eq!(response.outcome, SqlCaptureOutcome::RefusedDisabled);
    assert!(response.producer_id.is_none());
    assert!(response.generation.is_none());
    assert!(response.output_basename.is_none());
}

// Produces a Field with the same name handling used by tracing events without
// relying on a global subscriber in these deterministic visitor tests.
fn test_field(name: &'static str) -> Field {
    struct Callsite;
    static CALLSITE: Callsite = Callsite;
    impl tracing_core::callsite::Callsite for Callsite {
        fn set_interest(&self, _: tracing_core::subscriber::Interest) {}
        fn metadata(&self) -> &Metadata<'_> {
            unreachable!()
        }
    }
    let names = Box::leak(Box::new([name]));
    let fields = Box::leak(Box::new(tracing_core::field::FieldSet::new(
        names,
        tracing_core::identify_callsite!(&CALLSITE),
    )));
    fields.field(name).unwrap()
}
