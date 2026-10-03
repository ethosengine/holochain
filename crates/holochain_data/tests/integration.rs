use holochain_data::kind::DbKind;
use holochain_data::DbKey;
use holochain_data::{open_db, DatabaseIdentifier};
use sqlx::Row;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone)]
struct TestDbId(String);

impl DatabaseIdentifier for TestDbId {
    fn database_id(&self) -> &str {
        &self.0
    }

    fn db_kind(&self) -> DbKind {
        DbKind::Wasm
    }
}

#[tokio::test]
async fn create_database() {
    let tmp_dir = tempfile::TempDir::new().unwrap();
    let db_id = TestDbId("test_database".to_string());

    let config = holochain_data::HolochainDataConfig::new();
    let result = open_db(&tmp_dir, db_id.clone(), config).await;

    assert!(
        result.is_ok(),
        "Failed to create database connection: {:?}",
        result.err()
    );

    let db_conn = result.unwrap();
    assert_eq!(db_conn.identifier().database_id(), "test_database");

    // Verify the database file was created
    let db_file = tmp_dir.path().join("test_database");
    assert!(
        db_file.exists(),
        "Database file was not created at {db_file:?}"
    );
}

#[tokio::test]
async fn multiple_databases_same_directory() {
    let tmp_dir = tempfile::TempDir::new().unwrap();

    let db_id_1 = TestDbId("database_one".to_string());
    let db_id_2 = TestDbId("database_two".to_string());

    let config = holochain_data::HolochainDataConfig::new();
    let result_1 = open_db(&tmp_dir, db_id_1.clone(), config.clone()).await;
    let result_2 = open_db(&tmp_dir, db_id_2.clone(), config).await;

    assert!(result_1.is_ok());
    assert!(result_2.is_ok());

    // Verify both database files exist
    assert!(tmp_dir.path().join("database_one").exists());
    assert!(tmp_dir.path().join("database_two").exists());
}

#[tokio::test]
async fn error_on_non_directory_path() {
    let tmp_dir = tempfile::TempDir::new().unwrap();
    let file_path = tmp_dir.path().join("some_file");
    std::fs::write(&file_path, b"test").unwrap();

    let db_id = TestDbId("test_database".to_string());
    let config = holochain_data::HolochainDataConfig::new();
    let err = open_db(file_path, db_id, config).await.unwrap_err();

    assert!(err.to_string().contains("Path must be a directory"));
}

#[tokio::test]
async fn encrypted_database() {
    let tmp_dir = tempfile::TempDir::new().unwrap();
    let db_id = TestDbId("encrypted_test_database".to_string());

    // Generate a database key with a test passphrase
    let passphrase = Arc::new(Mutex::new(sodoken::LockedArray::from(
        b"test_passphrase_for_encryption".to_vec(),
    )));
    let db_key = DbKey::generate(passphrase.clone())
        .await
        .expect("Failed to generate database key");

    // Create database with encryption
    let config = holochain_data::HolochainDataConfig::new().with_key(db_key.clone());
    let result = open_db(&tmp_dir, db_id.clone(), config).await;
    assert!(
        result.is_ok(),
        "Failed to create encrypted database: {:?}",
        result.err()
    );

    let db_conn = result.unwrap();
    assert_eq!(
        db_conn.identifier().database_id(),
        "encrypted_test_database"
    );

    // Create a table to test that encryption works
    sqlx::query("CREATE TABLE test_table (id INTEGER PRIMARY KEY);")
        .execute(db_conn.pool())
        .await
        .expect("Failed to create table in encrypted database");

    // Verify WAL mode is enabled
    let row = sqlx::query("PRAGMA journal_mode;")
        .fetch_one(db_conn.pool())
        .await
        .expect("Failed to query journal mode");
    let mode: String = row.get(0);
    assert_eq!(
        mode.to_lowercase(),
        "wal",
        "Expected WAL mode to be enabled"
    );

    // Verify the database file was created
    let db_file = tmp_dir.path().join("encrypted_test_database");
    assert!(
        db_file.exists(),
        "Encrypted database file was not created at {db_file:?}"
    );

    // Drop the connection
    drop(db_conn);

    // Try to open the same database again with the same key
    let config_reopen = holochain_data::HolochainDataConfig::new().with_key(db_key);
    let result_reopen = open_db(&tmp_dir, db_id.clone(), config_reopen).await;
    assert!(
        result_reopen.is_ok(),
        "Failed to reopen encrypted database: {:?}",
        result_reopen.err()
    );
}

#[tokio::test]
async fn encrypted_database_wrong_key_fails() {
    let tmp_dir = tempfile::TempDir::new().unwrap();
    let db_id = TestDbId("encrypted_fail_test".to_string());

    // Create database with first key
    let passphrase1 = Arc::new(Mutex::new(sodoken::LockedArray::from(
        b"first_passphrase".to_vec(),
    )));
    let db_key1 = DbKey::generate(passphrase1)
        .await
        .expect("Failed to generate first database key");

    let config1 = holochain_data::HolochainDataConfig::new().with_key(db_key1);
    let result = open_db(&tmp_dir, db_id.clone(), config1).await;
    assert!(result.is_ok(), "Failed to create encrypted database");
    let db_conn1 = result.unwrap();

    // Create a table to ensure the database is properly encrypted
    sqlx::query("CREATE TABLE test_table (id INTEGER PRIMARY KEY, value TEXT);")
        .execute(db_conn1.pool())
        .await
        .expect("Failed to create table");
    drop(db_conn1);

    // Try to open with different key
    let passphrase2 = Arc::new(Mutex::new(sodoken::LockedArray::from(
        b"wrong_passphrase".to_vec(),
    )));
    let db_key2 = DbKey::generate(passphrase2)
        .await
        .expect("Failed to generate second database key");

    let config2 = holochain_data::HolochainDataConfig::new().with_key(db_key2);
    // With WAL mode enabled, connection fails immediately with wrong key
    // because enabling WAL requires reading the database header
    let err = open_db(&tmp_dir, db_id.clone(), config2).await.unwrap_err();
    // SQLCipher returns errors related to SQL or encryption when the wrong key is used
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("not a database")
            || err_msg.contains("encrypted")
            || err_msg.contains("cipher")
            || err_msg.contains("SQL logic error"),
        "Expected encryption-related error, got: {err_msg}"
    );
}

#[tokio::test]
async fn pragma_configuration() {
    let tmp_dir = tempfile::TempDir::new().unwrap();
    let db_id = TestDbId("pragma_test_database".to_string());

    // Create database with custom sync level
    let config = holochain_data::HolochainDataConfig::new()
        .with_sync_level(holochain_data::DbSyncLevel::Off);
    let result = open_db(&tmp_dir, db_id.clone(), config).await;
    assert!(
        result.is_ok(),
        "Failed to create database: {:?}",
        result.err()
    );

    let db_conn = result.unwrap();

    // Verify synchronous level is set correctly
    let row = sqlx::query("PRAGMA synchronous;")
        .fetch_one(db_conn.pool())
        .await
        .expect("Failed to query synchronous");
    let sync_value: i32 = row.get(0);
    assert_eq!(sync_value, 0, "Expected synchronous level to be 0 (Off)");

    // Verify trusted_schema is set to false
    let row = sqlx::query("PRAGMA trusted_schema;")
        .fetch_one(db_conn.pool())
        .await
        .expect("Failed to query trusted_schema");
    let trusted_value: i32 = row.get(0);
    assert_eq!(trusted_value, 0, "Expected trusted_schema to be 0 (false)");
}

#[tokio::test]
async fn migrations_applied() {
    let tmp_dir = tempfile::TempDir::new().unwrap();
    let db_id = TestDbId("migrations_test_database".to_string());

    let config = holochain_data::HolochainDataConfig::new();
    let result = open_db(&tmp_dir, db_id.clone(), config).await;
    assert!(
        result.is_ok(),
        "Failed to create database: {:?}",
        result.err()
    );

    let db_conn = result.unwrap();

    // Verify the Wasm database tables were created by migration
    let row = sqlx::query("SELECT name FROM sqlite_master WHERE type='table' AND name='Wasm';")
        .fetch_one(db_conn.pool())
        .await
        .expect("Failed to query for Wasm table");
    let table_name: String = row.get(0);
    assert_eq!(table_name, "Wasm", "Expected Wasm table to exist");

    // Verify all expected tables exist
    let tables = sqlx::query("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        .fetch_all(db_conn.pool())
        .await
        .expect("Failed to query tables");

    let table_names: Vec<String> = tables
        .iter()
        .map(|row| row.get::<String, _>("name"))
        .collect();

    assert!(
        table_names.contains(&"Wasm".to_string()),
        "Wasm table missing"
    );
    assert!(
        table_names.contains(&"CompiledWasm".to_string()),
        "CompiledWasm table missing"
    );
    assert!(
        table_names.contains(&"DnaDef".to_string()),
        "DnaDef table missing"
    );
    assert!(
        table_names.contains(&"EntryDef".to_string()),
        "EntryDef table missing"
    );
    assert!(
        table_names.contains(&"IntegrityZome".to_string()),
        "IntegrityZome table missing"
    );
    assert!(
        table_names.contains(&"CoordinatorZome".to_string()),
        "CoordinatorZome table missing"
    );

    // Verify foreign keys are enabled
    let row = sqlx::query("PRAGMA foreign_keys;")
        .fetch_one(db_conn.pool())
        .await
        .expect("Failed to query foreign_keys pragma");
    let fk_enabled: i32 = row.get(0);
    assert_eq!(fk_enabled, 1, "Expected foreign_keys to be enabled (1)");
}

#[tokio::test]
async fn test_foreign_key_constraints() {
    let tmp_dir = tempfile::TempDir::new().unwrap();
    let db_id = TestDbId("fk_test_database".to_string());

    let config = holochain_data::HolochainDataConfig::new();
    let db_conn = open_db(&tmp_dir, db_id, config)
        .await
        .expect("Failed to create database");

    // Insert a DnaDef
    let dna_hash = vec![1u8; 32];
    let agent = vec![2u8; 32]; // Agent public key
    sqlx::query(
        "INSERT INTO DnaDef (hash, agent, name, network_seed, properties) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&dna_hash)
    .bind(&agent)
    .bind("test_dna")
    .bind("test_seed")
    .bind(vec![0u8])
    .execute(db_conn.pool())
    .await
    .expect("Failed to insert DnaDef");

    // Insert an IntegrityZome referencing the DnaDef
    sqlx::query(
        "INSERT INTO IntegrityZome (dna_hash, agent, zome_index, zome_name, zome_hash, dependencies) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(&dna_hash)
    .bind(&agent)
    .bind(0)
    .bind("test_zome")
    .bind(vec![0u8])
    .bind("[]")
    .execute(db_conn.pool())
    .await
    .expect("Failed to insert IntegrityZome");

    // Verify the zome was inserted
    let count: i32 =
        sqlx::query_scalar("SELECT COUNT(*) FROM IntegrityZome WHERE dna_hash = ? AND agent = ?")
            .bind(&dna_hash)
            .bind(&agent)
            .fetch_one(db_conn.pool())
            .await
            .expect("Failed to count zomes");
    assert_eq!(count, 1);

    // Try to insert an IntegrityZome with a non-existent dna_hash (should fail)
    let bad_dna_hash = vec![99u8; 32];
    let bad_agent = vec![99u8; 32];
    let err = sqlx::query(
        "INSERT INTO IntegrityZome (dna_hash, agent, zome_index, zome_name, zome_hash, dependencies) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(&bad_dna_hash)
    .bind(&bad_agent)
    .bind(0)
    .bind("bad_zome")
    .bind(vec![0u8])
    .bind("[]")
    .execute(db_conn.pool())
    .await
    .unwrap_err();
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("FOREIGN KEY constraint failed")
            || err_msg.contains("foreign key")
            || err_msg.contains("constraint"),
        "Expected foreign key error, got: {err_msg}"
    );

    // Delete the DnaDef and verify cascading delete removes the zome
    sqlx::query("DELETE FROM DnaDef WHERE hash = ? AND agent = ?")
        .bind(&dna_hash)
        .bind(&agent)
        .execute(db_conn.pool())
        .await
        .expect("Failed to delete DnaDef");

    let count: i32 =
        sqlx::query_scalar("SELECT COUNT(*) FROM IntegrityZome WHERE dna_hash = ? AND agent = ?")
            .bind(&dna_hash)
            .bind(&agent)
            .fetch_one(db_conn.pool())
            .await
            .expect("Failed to count zomes after delete");
    assert_eq!(count, 0, "Expected cascading delete to remove zome");
}

/// ELOHIM PATCH (H3): the WAL is checkpointed into the main file and truncated
/// by the bounded maintenance pass; a reader pinning an old snapshot makes the
/// truncating step report `busy` within its bounded wait instead of stalling
/// writers; once the reader is gone the next pass empties the WAL file.
#[tokio::test(flavor = "multi_thread")]
async fn wal_maintenance_checkpoints_and_truncates_within_bound() {
    use holochain_data::wal::{WalCheckpointMode, JOURNAL_SIZE_LIMIT_BYTES};
    use std::time::{Duration, Instant};

    let tmp_dir = tempfile::TempDir::new().unwrap();
    let db_id = TestDbId("wal_maintenance".to_string());
    let db = open_db(&tmp_dir, db_id, holochain_data::HolochainDataConfig::new())
        .await
        .unwrap();
    let main_path = tmp_dir.path().join("wal_maintenance");
    let wal_path = tmp_dir.path().join("wal_maintenance-wal");
    let len = |p: &std::path::Path| std::fs::metadata(p).map(|m| m.len()).unwrap_or(0);

    let limit: i64 = sqlx::query_scalar("PRAGMA journal_size_limit")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(limit, JOURNAL_SIZE_LIMIT_BYTES);

    sqlx::query("CREATE TABLE t (id INTEGER PRIMARY KEY, b BLOB NOT NULL)")
        .execute(db.pool())
        .await
        .unwrap();
    let insert = |from: i64| {
        let db = db.clone();
        async move {
            for id in from..from + 200 {
                sqlx::query("INSERT INTO t (id, b) VALUES (?, ?)")
                    .bind(id)
                    .bind(vec![id as u8; 4096])
                    .execute(db.pool())
                    .await
                    .unwrap();
            }
        }
    };
    insert(0).await;

    // A reader pins the current snapshot.
    let mut reader = db.pool().begin().await.unwrap();
    let seen: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM t")
        .fetch_one(&mut *reader)
        .await
        .unwrap();
    assert_eq!(seen, 200);

    // Writes after the snapshot put frames in the WAL that the reader's
    // snapshot predates; a truncating checkpoint must wait for that reader.
    insert(200).await;

    let started = Instant::now();
    let pinned = db
        .wal_maintenance_pass(0, Duration::from_millis(200))
        .await
        .unwrap();
    let waited = started.elapsed();
    let truncate = pinned
        .truncate
        .expect("a non-empty log escalates to TRUNCATE");
    assert!(
        truncate.busy,
        "a pinned reader must make TRUNCATE report busy: {pinned:?}"
    );
    assert!(
        waited < Duration::from_secs(5),
        "the truncating step must give up within its bound, waited {waited:?}"
    );
    assert!(len(&wal_path) > 0, "the pinned WAL cannot be truncated yet");

    // The busy timeout of the pool's connections is restored afterwards.
    let restored: i64 = sqlx::query_scalar("PRAGMA busy_timeout")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(restored, holochain_data::BUSY_TIMEOUT.as_millis() as i64);

    reader.rollback().await.unwrap();
    let main_before = len(&main_path);

    let freed = db
        .wal_maintenance_pass(0, Duration::from_millis(200))
        .await
        .unwrap();
    let truncate = freed.truncate.expect("still above the threshold");
    assert!(
        !truncate.busy,
        "no reader left, TRUNCATE completes: {freed:?}"
    );
    assert_eq!(len(&wal_path), 0, "TRUNCATE empties the WAL file");
    assert!(
        len(&main_path) >= main_before,
        "the frames were copied into the main database file"
    );

    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM t")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(rows, 400, "no row is lost by checkpointing");

    // A passive checkpoint never blocks and, on an empty log, reports so.
    let passive = db
        .wal_checkpoint(WalCheckpointMode::Passive, Duration::ZERO)
        .await
        .unwrap();
    assert!(passive.fully_backfilled(), "{passive:?}");
}

/// ELOHIM PATCH (H3): a truncating checkpoint blocks new writers while it
/// copies, so it is skipped when more than `WAL_TRUNCATE_MAX_COPY_FRAMES` would
/// be left for it to copy (a reader pinning an old snapshot); the passive
/// checkpoint still runs and never blocks.
#[tokio::test(flavor = "multi_thread")]
async fn wal_maintenance_skips_truncate_with_a_large_remainder() {
    use holochain_data::wal::WAL_TRUNCATE_MAX_COPY_FRAMES;
    use std::time::Duration;

    let tmp_dir = tempfile::TempDir::new().unwrap();
    let db = open_db(
        &tmp_dir,
        TestDbId("wal_remainder".to_string()),
        holochain_data::HolochainDataConfig::new(),
    )
    .await
    .unwrap();
    sqlx::query("CREATE TABLE t (id INTEGER PRIMARY KEY, b BLOB NOT NULL)")
        .execute(db.pool())
        .await
        .unwrap();

    let mut reader = db.pool().begin().await.unwrap();
    let _: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM t")
        .fetch_one(&mut *reader)
        .await
        .unwrap();

    // More frames than a truncating checkpoint may copy, all newer than the
    // reader's snapshot.
    let rows = WAL_TRUNCATE_MAX_COPY_FRAMES + 512;
    for id in 0..rows {
        sqlx::query("INSERT INTO t (id, b) VALUES (?, ?)")
            .bind(id)
            .bind(vec![1u8; 4096])
            .execute(db.pool())
            .await
            .unwrap();
    }

    let outcome = db
        .wal_maintenance_pass(0, Duration::from_millis(200))
        .await
        .unwrap();
    assert!(
        outcome.passive.log_frames - outcome.passive.checkpointed_frames
            > WAL_TRUNCATE_MAX_COPY_FRAMES,
        "the pinned reader leaves a large remainder: {outcome:?}"
    );
    assert_eq!(
        outcome.truncate, None,
        "no truncating checkpoint with a large remainder: {outcome:?}"
    );

    reader.rollback().await.unwrap();
    let freed = db
        .wal_maintenance_pass(0, Duration::from_millis(200))
        .await
        .unwrap();
    assert!(
        freed.passive.fully_backfilled(),
        "with the reader gone the passive checkpoint copies everything: {freed:?}"
    );
    assert!(
        matches!(freed.truncate, Some(t) if !t.busy),
        "and the (now copy-free) truncation completes: {freed:?}"
    );
}

/// The capability-grant backfill publishes how many secret-bearing grants
/// still have no lookup key as the `hc.db.cap_grant.unkeyed` gauge, one series
/// per database, through the same exporter the conductor's `/metrics` scrape
/// reads — so an incomplete backfill, or a grant that can never be keyed, is a
/// scrape and not a log line.
#[tokio::test]
async fn cap_grant_backfill_publishes_the_unkeyed_gauge() {
    use holo_hash::{ActionHash, AgentPubKey, DnaHash, EntryHash, HoloHashed};
    use holochain_data::dht::{CapGrantBackfillConfig, CapGrantBackfillEvent};
    use holochain_data::kind::Dht;
    use holochain_integrity_types::action::{
        Action, ActionData, ActionHeader, CreateData, EntryType, RecordValidity,
    };
    use holochain_integrity_types::capability::{
        CapAccess, CapSecret, GrantedFunctions, ZomeCallCapGrant,
    };
    use holochain_integrity_types::entry::Entry;
    use holochain_integrity_types::record::SignedHashed;
    use holochain_integrity_types::signature::Signature;
    use holochain_timestamp::Timestamp;
    use std::time::Duration;

    let (exporter, provider) = holochain_metrics::PrometheusExporter::install();
    opentelemetry::global::set_meter_provider(provider);

    let dir = tempfile::tempdir().unwrap();
    let id = Dht::new(Arc::new(DnaHash::from_raw_36(vec![0xD1; 36])));
    let database_id = id.database_id().to_string();
    let db = open_db(dir.path(), id, Default::default()).await.unwrap();

    // Two grants written the way a binary that predates the lookup columns
    // writes them. The first has its private entry; the second does not, so no
    // key can ever be derived for it.
    let author = AgentPubKey::from_raw_36(vec![1; 36]);
    let mut entries = Vec::new();
    for n in 1..=2u8 {
        let entry = Entry::CapGrant(ZomeCallCapGrant::new(
            format!("grant-{n}"),
            CapAccess::Transferable {
                secret: CapSecret::from([n; 64]),
            },
            GrantedFunctions::All,
        ));
        let entry_hash = EntryHash::from_raw_36(vec![0x20 + n; 36]);
        let action = Action {
            header: ActionHeader {
                author: author.clone(),
                timestamp: Timestamp::from_micros(i64::from(n)),
                action_seq: u32::from(n),
                prev_action: Some(ActionHash::from_raw_36(vec![0xEE; 36])),
            },
            data: ActionData::Create(CreateData {
                entry_type: EntryType::CapGrant,
                entry_hash: entry_hash.clone(),
            }),
        };
        let sah = SignedHashed::with_presigned(
            HoloHashed::with_pre_hashed(action, ActionHash::from_raw_36(vec![0x10 + n; 36])),
            Signature([7; 64]),
        );
        db.insert_action(&sah, Some(RecordValidity::Accepted))
            .await
            .unwrap();
        sqlx::query("INSERT INTO CapGrant (action_hash, cap_access, tag) VALUES (?, 1, NULL)")
            .bind(sah.as_hash().get_raw_36())
            .execute(db.pool())
            .await
            .unwrap();
        entries.push((entry_hash, entry));
    }
    db.insert_private_entry(&entries[0].0, &author, &entries[0].1)
        .await
        .unwrap();
    assert_eq!(db.as_ref().count_cap_grants_unkeyed().await.unwrap(), 2);

    let config = CapGrantBackfillConfig {
        start_delay: Duration::ZERO,
        batch: 8,
        pause: Duration::ZERO,
        min_backoff: Duration::from_millis(1),
        max_backoff: Duration::from_millis(1),
    };
    let gauge = |body: &str| -> Option<String> {
        body.lines()
            .find(|line| {
                line.starts_with("hc_db_cap_grant_unkeyed{")
                    && line.contains(&format!("id=\"{database_id}\""))
                    && line.contains("kind=\"dht\"")
            })
            .and_then(|line| line.rsplit(' ').next())
            .map(str::to_string)
    };

    // One row keyed, one left that cannot be: the gauge says 1.
    let mut converged = None;
    let report = db
        .converge_cap_grant_lookup_keys(config, &mut |event| {
            if let CapGrantBackfillEvent::Converged { unkeyed, .. } = event {
                converged = Some(unkeyed);
            }
        })
        .await;
    assert_eq!(
        (report.secret_keys_filled, report.left_unkeyed),
        (1, 1),
        "{report:?}"
    );
    assert_eq!(converged, Some(Some(1)));
    let body = exporter.render().unwrap();
    assert!(
        body.contains("# TYPE hc_db_cap_grant_unkeyed gauge\n"),
        "{body}"
    );
    assert_eq!(gauge(&body).as_deref(), Some("1"), "{body}");

    // Its private entry turns up; the next pass keys it and the gauge says 0.
    db.insert_private_entry(&entries[1].0, &author, &entries[1].1)
        .await
        .unwrap();
    let report = db.converge_cap_grant_lookup_keys(config, &mut |_| {}).await;
    assert_eq!((report.secret_keys_filled, report.left_unkeyed), (1, 0));
    assert_eq!(gauge(&exporter.render().unwrap()).as_deref(), Some("0"));
}
