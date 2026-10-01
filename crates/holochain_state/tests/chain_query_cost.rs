//! Cost bound for `SourceChain::query`: a range-bounded read of an agent's own
//! chain must cost the same at ten chain entries as at two thousand.
//!
//! This is its own integration-test binary on purpose. The only statement
//! counter sqlx offers is the `tracing` event it emits per statement
//! (target `sqlx::query`), and that event fires on the connection's dedicated
//! worker thread, so only a GLOBAL subscriber sees it. A global subscriber in
//! the `holochain_state` lib-test binary would also count every other test's
//! queries. Here it is process-wide and this file holds exactly ONE test, so
//! every counted statement belongs to it. Keep it that way: add another test
//! to this file and the counts stop meaning anything.

use holochain_keystore::test_keystore;
use holochain_serialized_bytes::{SerializedBytes, UnsafeBytes};
use holochain_state::prelude::*;
use holochain_state::source_chain::{genesis, SourceChain};
use holochain_state::test_utils::test_dht_store;
use kitsune2_api::DhtArc;
use std::sync::{Mutex, OnceLock};
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record as SpanRecord};
use tracing::{Event, Metadata, Subscriber};

/// One `sqlx::query` event: the statement text and the rows it returned.
#[derive(Debug, Clone, Default)]
struct Stmt {
    sql: String,
    rows_returned: u64,
}

fn log() -> &'static Mutex<Vec<Stmt>> {
    static LOG: OnceLock<Mutex<Vec<Stmt>>> = OnceLock::new();
    LOG.get_or_init(|| Mutex::new(Vec::new()))
}

#[derive(Default)]
struct StmtVisitor {
    summary: String,
    statement: String,
    rows_returned: u64,
}

impl Visit for StmtVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        match field.name() {
            "summary" => self.summary = value.to_string(),
            "db.statement" => self.statement = value.to_string(),
            _ => {}
        }
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        if field.name() == "rows_returned" {
            self.rows_returned = value;
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        match field.name() {
            "summary" => self.summary = format!("{value:?}"),
            "db.statement" => self.statement = format!("{value:?}"),
            _ => {}
        }
    }
}

/// Minimal subscriber: records every `sqlx::query` event, ignores the rest.
struct SqlxStatementCounter;

impl Subscriber for SqlxStatementCounter {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.target() == "sqlx::query"
    }

    fn new_span(&self, _: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }

    fn record(&self, _: &Id, _: &SpanRecord<'_>) {}

    fn record_follows_from(&self, _: &Id, _: &Id) {}

    fn event(&self, event: &Event<'_>) {
        let mut v = StmtVisitor::default();
        event.record(&mut v);
        // sqlx logs the full text in `db.statement` only when it differs from
        // the (truncated) summary.
        let sql = if v.statement.trim().is_empty() {
            v.summary
        } else {
            v.statement
        };
        log().lock().unwrap().push(Stmt {
            sql,
            rows_returned: v.rows_returned,
        });
    }

    fn enter(&self, _: &Id) {}

    fn exit(&self, _: &Id) {}
}

/// What one `query` call cost at the SQL layer.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Cost {
    /// SELECT statements issued.
    statements: usize,
    /// Rows returned by statements reading the `Action` table.
    action_rows: u64,
    /// Rows returned by statements reading `Entry` / `PrivateEntry`.
    entry_rows: u64,
}

/// Run `query` once and report the SQL it cost. Connection-establishment
/// PRAGMAs are not SELECTs, so a pool that happens to open a connection
/// mid-call does not perturb the count.
async fn measure(chain: &SourceChain, query: ChainQueryFilter) -> (Vec<Record>, Cost) {
    log().lock().unwrap().clear();
    let records = chain.query(query).await.unwrap();
    let stmts = std::mem::take(&mut *log().lock().unwrap());
    let selects: Vec<&Stmt> = stmts
        .iter()
        .filter(|s| {
            s.sql
                .trim_start()
                .to_ascii_uppercase()
                .starts_with("SELECT")
        })
        .collect();
    let cost = Cost {
        statements: selects.len(),
        action_rows: selects
            .iter()
            .filter(|s| s.sql.contains("FROM Action"))
            .map(|s| s.rows_returned)
            .sum(),
        entry_rows: selects
            .iter()
            .filter(|s| s.sql.contains("FROM Entry") || s.sql.contains("FROM PrivateEntry"))
            .map(|s| s.rows_returned)
            .sum(),
    };
    (records, cost)
}

fn app_entry_type() -> EntryType {
    EntryType::App(AppEntryDef {
        zome_index: 0.into(),
        entry_index: 0.into(),
        visibility: EntryVisibility::Public,
    })
}

/// A genesis'd chain with `n` app `Create`s, each carrying a distinct public
/// entry, all flushed to the store. Returns a fresh handle at the new head.
async fn chain_of(n: u32) -> SourceChain {
    chain_with_links(n, 0).await
}

/// Keep the number of entry actions fixed while unrelated link history grows.
async fn chain_with_links(n: u32, links: u32) -> SourceChain {
    let keystore = test_keystore();
    let dna_hash = DnaHash::from_raw_36(vec![0xdb; 36]);
    let dht_store = test_dht_store(dna_hash.clone()).await;
    let author = keystore.new_sign_keypair_random().await.unwrap();
    genesis(
        dht_store.clone(),
        keystore.clone(),
        dna_hash,
        author.clone(),
        None,
    )
    .await
    .unwrap();

    let chain = SourceChain::new(dht_store.clone(), keystore.clone(), author.clone())
        .await
        .unwrap();
    for i in 0..n {
        let bytes =
            holochain_serialized_bytes::encode(&(u64::from(i), "chain-query-cost")).unwrap();
        let entry = Entry::App(AppEntryBytes(SerializedBytes::from(UnsafeBytes::from(
            bytes,
        ))));
        let entry_hash = EntryHash::with_data_sync(&entry);
        chain
            .put(
                ActionData::Create(CreateData {
                    entry_type: app_entry_type(),
                    entry_hash,
                }),
                Some(entry),
                ChainTopOrdering::default(),
            )
            .await
            .unwrap();
    }
    for i in 0..links {
        chain
            .put(
                ActionData::CreateLink(CreateLinkData {
                    base_address: EntryHash::from_raw_36(vec![1; 36]).into(),
                    target_address: EntryHash::from_raw_36(vec![2; 36]).into(),
                    zome_index: 0.into(),
                    link_type: 0.into(),
                    tag: LinkTag::new(i.to_le_bytes().to_vec()),
                }),
                None,
                ChainTopOrdering::default(),
            )
            .await
            .unwrap();
    }
    chain.flush(vec![DhtArc::Empty]).await.unwrap();

    SourceChain::new(dht_store, keystore, author).await.unwrap()
}

/// The reference semantics: read the whole chain with the same entry/order
/// settings, then apply the filter in Rust — exactly what `query` did before
/// the range was pushed into SQL.
async fn reference(chain: &SourceChain, query: &ChainQueryFilter) -> Vec<Record> {
    let all = chain
        .query(ChainQueryFilter {
            include_entries: query.include_entries,
            order_descending: query.order_descending,
            ..ChainQueryFilter::default()
        })
        .await
        .unwrap();
    query.filter_records(all)
}

#[tokio::test(flavor = "multi_thread")]
async fn chain_query_range_cost_does_not_scale_with_chain_length() {
    tracing::subscriber::set_global_default(SqlxStatementCounter)
        .expect("this binary must own the global subscriber");

    const GENESIS_LEN: u32 = 3;
    const RANGE_LEN: u32 = 10;

    let mut costs = Vec::new();
    for app_actions in [10_u32, 2_000] {
        let chain = chain_of(app_actions).await;
        let head_seq = GENESIS_LEN + app_actions - 1;

        // Warm the pool so connection establishment is not inside a measure.
        chain.query(ChainQueryFilter::default()).await.unwrap();

        let from_start = ChainQueryFilter::default()
            .sequence_range(ChainQueryFilterRange::ActionSeqRange(
                GENESIS_LEN,
                GENESIS_LEN + RANGE_LEN - 1,
            ))
            .include_entries(true);
        let at_head = ChainQueryFilter::default()
            .sequence_range(ChainQueryFilterRange::ActionSeqRange(
                head_seq + 1 - RANGE_LEN,
                head_seq,
            ))
            .include_entries(true)
            .descending();
        // Not range-bounded: reported, not asserted on action rows.
        let entry_type_only = ChainQueryFilter::default()
            .entry_type(EntryType::AgentPubKey)
            .include_entries(true);

        let mut row = Vec::new();
        for (name, query) in [
            ("seq-range from start", from_start),
            ("seq-range at head, descending", at_head),
            ("entry_type only (AgentPubKey)", entry_type_only),
        ] {
            let (got, cost) = measure(&chain, query.clone()).await;
            let expected = reference(&chain, &query).await;
            assert_eq!(
                got, expected,
                "{name}: pushed-down result differs from whole-chain-then-Rust-filter at {app_actions} app actions"
            );
            assert!(
                got.iter()
                    .filter(|r| r.action().entry_hash().is_some())
                    .all(|r| matches!(r.entry(), RecordEntry::Present(_))),
                "{name}: every returned public entry must be attached"
            );
            eprintln!(
                "chain_query_cost app_actions={app_actions} filter=\"{name}\" records={} statements={} action_rows={} entry_rows={}",
                got.len(),
                cost.statements,
                cost.action_rows,
                cost.entry_rows
            );
            row.push((name, got.len(), cost));
        }
        costs.push(row);
    }

    let (short, long) = (&costs[0], &costs[1]);
    for ((name, short_len, short_cost), (_, long_len, long_cost)) in short.iter().zip(long.iter()) {
        assert_eq!(
            short_len, long_len,
            "{name}: same result size at both lengths"
        );
        assert_eq!(
            short_cost.statements, long_cost.statements,
            "{name}: statement count grew with chain length: {short_cost:?} -> {long_cost:?}"
        );
        assert_eq!(
            short_cost.entry_rows, long_cost.entry_rows,
            "{name}: entry rows loaded grew with chain length: {short_cost:?} -> {long_cost:?}"
        );
    }
    // The range-bounded reads also read a bounded number of action rows.
    for i in 0..2 {
        let (name, _, short_cost) = &short[i];
        let (_, _, long_cost) = &long[i];
        assert_eq!(
            short_cost.action_rows, long_cost.action_rows,
            "{name}: action rows read grew with chain length: {short_cost:?} -> {long_cost:?}"
        );
        assert_eq!(
            short_cost.action_rows,
            u64::from(RANGE_LEN),
            "{name}: action rows read should be exactly the range"
        );
    }

    // An entry-type-only custody read must not deserialize every unrelated
    // link on an old chain. The final entry-type predicate still runs in Rust.
    const ENTRY_ACTIONS: u32 = 3;
    for links in [10, 2_000] {
        let chain = chain_with_links(ENTRY_ACTIONS, links).await;
        chain.query(ChainQueryFilter::default()).await.unwrap();
        for include_entries in [false, true] {
            for order_descending in [false, true] {
                let query = ChainQueryFilter {
                    entry_type: Some(vec![app_entry_type()]),
                    include_entries,
                    order_descending,
                    ..ChainQueryFilter::default()
                };
                let (got, cost) = measure(&chain, query.clone()).await;
                let expected = reference(&chain, &query).await;
                assert_eq!(got, expected, "entry-only links={links} {query:?}");
                assert_eq!(got.len(), ENTRY_ACTIONS as usize);
                // Three app Creates and the genesis agent Create are the
                // only committed Create/Update headers; the Rust filter drops
                // the genesis entry of a different type.
                assert_eq!(cost.action_rows, u64::from(ENTRY_ACTIONS + 1));
                assert_eq!(
                    cost.entry_rows,
                    if include_entries {
                        u64::from(ENTRY_ACTIONS)
                    } else {
                        0
                    }
                );
                eprintln!(
                    "entry_only_query_cost links={links} include_entries={include_entries} descending={order_descending} records={} action_rows={} entry_rows={}",
                    got.len(), cost.action_rows, cost.entry_rows
                );
            }
        }
    }
}
