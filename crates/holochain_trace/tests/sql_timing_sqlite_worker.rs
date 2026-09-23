use holochain_trace::{init_fmt_with_sql_timing, Output};
use sqlx_core::{connection::Connection, executor::Executor};
use sqlx_sqlite::{SqliteConnectOptions, SqliteConnection};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::{
    env, fs,
    time::{SystemTime, UNIX_EPOCH},
};
use tracing::Instrument;

#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
async fn sqlite_worker_keeps_innermost_static_site_under_global_dispatch() {
    let parent = env::temp_dir().join(format!(
        "holochain-sql-site-worker-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    fs::create_dir_all(&parent).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
    let output = parent.join("sql-timing-g01-startup.jsonl");
    env::set_var("HOLOCHAIN_SQL_DIAGNOSTICS_SECONDS", "60");
    env::set_var("HOLOCHAIN_SQL_DIAGNOSTICS_DIR", &parent);

    // This integration-test binary has its own global subscriber, so the SQLx
    // worker can emit timing events. `Instrument` preserves the nested static
    // span ancestry around the polled query future, matching production helpers.
    let guard = init_fmt_with_sql_timing(Output::None).unwrap();
    let mut connection =
        SqliteConnection::connect_with(&SqliteConnectOptions::new().in_memory(true))
            .await
            .unwrap();
    let outer = tracing::span!(
        target: "holochain::sql_site",
        tracing::Level::TRACE,
        "dht.publish.select_ready",
        ignored_field = "must_not_persist"
    );
    async {
        let inner = tracing::span!(
            target: "holochain::sql_site",
            tracing::Level::TRACE,
            "dht.publish.pending_count",
            ignored_field = "must_not_persist"
        );
        (&mut connection)
            .execute("SELECT 1")
            .instrument(inner)
            .await
            .unwrap();
    }
    .instrument(outer)
    .await;
    connection.close().await.unwrap();
    drop(guard);

    let output = fs::read_to_string(&output).unwrap();
    let records: Vec<serde_json::Value> = output
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let start = records
        .iter()
        .find(|row| row["diagnostic_kind"] == "sql_timing_window_started")
        .unwrap();
    let close = records
        .iter()
        .find(|row| row["diagnostic_kind"] == "sql_timing_window_closed")
        .unwrap();
    #[cfg(target_os = "linux")]
    {
        let native = holochain_trace::diagnostic_identity::DiagnosticProcessIdentity::capture()
            .unwrap()
            .as_json();
        assert_eq!(start["native_process"], native);
        assert_eq!(close["native_process"], native);
        assert_eq!(start["started_monotonic_ms"], close["started_monotonic_ms"]);
        assert!(
            close["ended_monotonic_ms"].as_f64().unwrap()
                >= start["started_monotonic_ms"].as_f64().unwrap()
        );
    }
    let identities = close["identities"].as_array().unwrap();
    let identity = identities
        .iter()
        .find(|identity| {
            identity["source_site_ids"] == serde_json::json!(["dht.publish.pending_count"])
        })
        .unwrap();
    assert_eq!(identity["count"], 1);
    assert_eq!(
        identity["source_site_ids"],
        serde_json::json!(["dht.publish.pending_count"])
    );
    assert_eq!(identity["unattributed_events"], 0);
    assert_eq!(identity["unmapped_source_site_events"], 0);
    assert_eq!(identity["source_site_overflow_events"], 0);
    assert!(!output.contains("dht.publish.select_ready"));
    assert!(!output.contains("must_not_persist"));
    assert!(!output.contains("SELECT 1"));
    env::remove_var("HOLOCHAIN_SQL_DIAGNOSTICS_SECONDS");
    env::remove_var("HOLOCHAIN_SQL_DIAGNOSTICS_DIR");
    fs::remove_dir_all(parent).unwrap();
}
