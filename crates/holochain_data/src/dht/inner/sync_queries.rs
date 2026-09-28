//! K2 op-store reads that span the
//! `Action`/`Entry`/`ChainOp`/`Warrant`/`WarrantOp` tables.
//!
//! These are the cross-table queries Kitsune2's `OpStore` trait expects.
//! Each `async fn` is generic over `sqlx::Executor` so it can run against a
//! pool (`DbRead`/`DbWrite`) or a transaction (`TxRead`/`TxWrite`).
//!
//! Reads that *serve* ops to peers (time-slice, ids-since, ops-for-wire,
//! earliest-timestamp) filter `ChainOp.locally_validated = 1` so network-
//! cached ops are never gossiped. Warrants need no such filter: they always
//! route through `LimboWarrantOp` validation before being promoted to
//! `WarrantOp`, so every warrant joined against `WarrantOp` is locally
//! validated by construction.
//!
//! The op-discovery reads (`op_hashes_in_time_slice`, `op_ids_since_time_batch`),
//! the by-hash content read (`get_chain_ops_for_wire`), and the earliest-data
//! boundary (`earliest_authored_timestamp_in_arc`) additionally exclude
//! `CreateEntry` ops (`op_type = 2`) whose action carries a private entry
//! (`Action.private_entry = 1`), matching [`super::chain_op_publish::get_ops_to_publish`].
//! A private `CreateEntry` op is produced and stored locally so its author can
//! validate their own entry, but it must never be advertised or served to
//! peers: `check_entry_visibility` in `holochain`'s sys-validation rejects any
//! `CreateEntry` op whose action declares a private entry as
//! `PrivateEntryLeaked`, so a peer that received one anyway could never
//! converge on it — leaving it permanently unreconciled between the author's
//! slice hash and every peer's.
//!
//! `check_op_hashes_present` is the exception: it answers "do we already
//! hold this op in a form that doesn't need re-delivery?" so the fetch logic
//! never re-requests ops that are already in the validation pipeline. It
//! matches `LimboChainOp` (awaiting validation) and `ChainOp` with
//! `locally_validated = 1` (integrated), but *not* cache-mirrored ops
//! (`locally_validated = 0`), which still rely on gossip to re-deliver them
//! into validation.
//!
//! `count_integrated_ops` counts every integrated op (`ChainOp` +
//! `WarrantOp`) to report the total observed DHT size.

use crate::models::dht::{
    DumpChainOpRow, DumpOpCursorRow, DumpOpPage, DumpOpRow, DumpOpState, DumpOpWireRow,
    K2ChainOpForWireRow, K2OpHashRow, K2OpIdSinceRow, K2OpPresentRow, K2WarrantForWireRow,
    OpTimingRow, OpTimingsPage,
};
#[cfg(any(test, feature = "inspection"))]
use holo_hash::AnyLinkableHash;
use holo_hash::{AgentPubKey, DhtOpHash};
use sqlx::{Executor, QueryBuilder, Sqlite};
use std::collections::HashMap;

/// Inclusive `[storage_start_loc, storage_end_loc]` arc bounds.
#[derive(Debug, Clone, Copy)]
pub struct ArcBounds {
    /// Inclusive lower bound on `storage_center_loc`.
    pub start: u32,
    /// Inclusive upper bound on `storage_center_loc`.
    pub end: u32,
}

impl ArcBounds {
    // ELOHIM PATCH (k2 DHT-model cold start): the arc filter used to be ONE
    // shape for both arc kinds —
    //   (?s <= ?e AND loc >= ?s AND loc <= ?e) OR (?s > ?e AND (loc <= ?e OR loc >= ?s))
    // — whose `?s <= ?e` guard is only known at bind time, so SQLite's planner
    // cannot use any index on `storage_center_loc` and SCANs every `ChainOp`
    // row. Kitsune2 builds its DHT model (`Dht::try_from_store`, awaited by
    // `K2Gossip::create` inside the first `join` of a space, which
    // `create_cells_and_startup` awaits before any cell is running) with ~20
    // of these reads per sector × 512 sectors, so a restart paid ~10k full
    // scans of the DHT store before a single cell was enabled. The shape is
    // now chosen in Rust: a non-wrapping arc (every sector arc, and FULL) is a
    // plain range; a wrapping arc is the two-sided OR, which SQLite serves as
    // a MULTI-INDEX OR. The rows selected are identical.

    /// SQL arc predicate over `column`; bind [`Self::binds`] in order.
    fn predicate(self, column: &str) -> String {
        if self.start <= self.end {
            format!("({column} >= ? AND {column} <= ?)")
        } else {
            format!("({column} <= ? OR {column} >= ?)")
        }
    }

    /// The two values [`Self::predicate`]'s placeholders expect, in order.
    fn binds(self) -> (i64, i64) {
        if self.start <= self.end {
            (self.start as i64, self.end as i64)
        } else {
            (self.end as i64, self.start as i64)
        }
    }
}

/// SQL for [`op_hashes_in_time_slice`]; its placeholders take the arc binds of
/// [`ArcBounds::binds`] once per `UNION ALL` branch.
fn op_hashes_in_time_slice_sql(arc: ArcBounds) -> String {
    // Two arc-filter shapes: non-wrapping (start <= end) keeps everything
    // inside the range; wrapping (start > end) keeps everything outside.
    // The shape is chosen here, not in SQL, so the planner can use
    // `storage_center_loc` indexes (see `ArcBounds::predicate`).
    let chain_arc = arc.predicate("ChainOp.storage_center_loc");
    let warrant_arc = arc.predicate("WarrantOp.storage_center_loc");
    format!(
        "
        SELECT op_hash AS hash, basis_hash, serialized_size, sort_ts FROM (
            SELECT
                ChainOp.hash AS op_hash,
                ChainOp.basis_hash AS basis_hash,
                ChainOp.serialized_size AS serialized_size,
                Action.timestamp AS sort_ts
            FROM ChainOp
            JOIN Action ON ChainOp.action_hash = Action.hash
            WHERE
                {chain_arc}
                AND Action.timestamp >= ?
                AND Action.timestamp <  ?
                AND ChainOp.locally_validated = 1
                AND (ChainOp.op_type != 2 OR Action.private_entry = 0)
            UNION ALL
            SELECT
                Warrant.hash AS op_hash,
                Warrant.warrantee AS basis_hash,
                WarrantOp.serialized_size AS serialized_size,
                Warrant.timestamp AS sort_ts
            FROM Warrant
            JOIN WarrantOp ON WarrantOp.hash = Warrant.hash
            WHERE
                {warrant_arc}
                AND Warrant.timestamp >= ?
                AND Warrant.timestamp <  ?
        )
        ORDER BY sort_ts ASC
    "
    )
}

/// Return `(hash, basis, size)` for every integrated, locally-validated op
/// whose authored timestamp falls in `[t_start_micros, t_end_micros)`.
///
/// "Authored timestamp" comes from `Action.timestamp` for chain ops and
/// `Warrant.timestamp` for warrants. Results are ordered by authored
/// timestamp ascending.
pub(crate) async fn op_hashes_in_time_slice<'e, E>(
    executor: E,
    arc: ArcBounds,
    t_start_micros: i64,
    t_end_micros: i64,
) -> sqlx::Result<Vec<K2OpHashRow>>
where
    E: Executor<'e, Database = Sqlite>,
{
    let sql = op_hashes_in_time_slice_sql(arc);

    let (a, b) = arc.binds();
    // SQL is assembled from compile-time-constant arc predicates (no user
    // input), so asserting it is safe.
    sqlx::query_as::<_, K2OpHashRow>(sqlx::AssertSqlSafe(sql))
        // chain-op branch
        .bind(a)
        .bind(b)
        .bind(t_start_micros)
        .bind(t_end_micros)
        // warrant branch
        .bind(a)
        .bind(b)
        .bind(t_start_micros)
        .bind(t_end_micros)
        .fetch_all(executor)
        .await
}

/// SQL for [`op_ids_since_time_batch`]; its placeholders take the arc binds of
/// [`ArcBounds::binds`] once per `UNION ALL` branch.
fn op_ids_since_time_batch_sql(arc: ArcBounds) -> String {
    let chain_arc = arc.predicate("ChainOp.storage_center_loc");
    let warrant_arc = arc.predicate("WarrantOp.storage_center_loc");
    format!(
        "
        SELECT op_hash AS hash, basis_hash, when_integrated, serialized_size FROM (
            SELECT
                ChainOp.hash AS op_hash,
                ChainOp.basis_hash AS basis_hash,
                ChainOp.when_integrated AS when_integrated,
                ChainOp.serialized_size AS serialized_size
            FROM ChainOp
            JOIN Action ON ChainOp.action_hash = Action.hash
            WHERE
                {chain_arc}
                AND ChainOp.when_integrated >= ?
                AND ChainOp.locally_validated = 1
                AND (ChainOp.op_type != 2 OR Action.private_entry = 0)
            UNION ALL
            SELECT
                Warrant.hash AS op_hash,
                Warrant.warrantee AS basis_hash,
                WarrantOp.when_integrated AS when_integrated,
                WarrantOp.serialized_size AS serialized_size
            FROM Warrant
            JOIN WarrantOp ON WarrantOp.hash = Warrant.hash
            WHERE
                {warrant_arc}
                AND WarrantOp.when_integrated >= ?
        )
        ORDER BY when_integrated ASC
        LIMIT ?
    "
    )
}

/// Return up to `limit` ops with `when_integrated >= t_min_micros` in
/// integration-time order. Used by the K2 gossip "since" cursor.
pub(crate) async fn op_ids_since_time_batch<'e, E>(
    executor: E,
    arc: ArcBounds,
    t_min_micros: i64,
    limit: u32,
) -> sqlx::Result<Vec<K2OpIdSinceRow>>
where
    E: Executor<'e, Database = Sqlite>,
{
    let sql = op_ids_since_time_batch_sql(arc);

    let (a, b) = arc.binds();
    // SQL is assembled from compile-time-constant arc predicates (no user
    // input), so asserting it is safe.
    sqlx::query_as::<_, K2OpIdSinceRow>(sqlx::AssertSqlSafe(sql))
        // chain-op branch
        .bind(a)
        .bind(b)
        .bind(t_min_micros)
        // warrant branch
        .bind(a)
        .bind(b)
        .bind(t_min_micros)
        .bind(limit as i64)
        .fetch_all(executor)
        .await
}

/// Return the subset of `hashes` we already hold in a way that does not need
/// re-delivery, with their basis hashes — used to decide which ops still
/// need fetching from peers.
///
/// "Hold" means a chain op that is either awaiting validation in
/// `LimboChainOp` or already integrated by us (`ChainOp` with
/// `locally_validated = 1`), or a warrant whose content row exists in
/// `Warrant` (which by invariant implies a `LimboWarrantOp` or `WarrantOp`
/// row, both of which route through validation).
///
/// Cache-mirrored ops (`ChainOp` with `locally_validated = 0`) are
/// deliberately *excluded*: their content is held only to serve reads, they
/// never entered the validation pipeline, and the only way they reach it is
/// to be re-delivered by gossip. Reporting them as present would suppress
/// that re-delivery and they would never integrate.
pub(crate) async fn check_op_hashes_present<'e, E>(
    executor: E,
    hashes: &[Vec<u8>],
) -> sqlx::Result<Vec<K2OpPresentRow>>
where
    E: Executor<'e, Database = Sqlite>,
{
    if hashes.is_empty() {
        return Ok(Vec::new());
    }

    // sqlx doesn't expand `IN (...)` for blob slices directly, so build the
    // UNION across the limbo + locally-validated chain-op tables and the
    // shared warrant content table, binding each hash list in turn.
    let mut qb: QueryBuilder<Sqlite> =
        QueryBuilder::new("SELECT hash, basis_hash FROM LimboChainOp WHERE hash IN (");
    {
        let mut sep = qb.separated(", ");
        for h in hashes {
            sep.push_bind(h);
        }
    }
    qb.push(
        ") UNION
         SELECT hash, basis_hash FROM ChainOp WHERE locally_validated = 1 AND hash IN (",
    );
    {
        let mut sep = qb.separated(", ");
        for h in hashes {
            sep.push_bind(h);
        }
    }
    qb.push(
        ") UNION
         SELECT hash, warrantee AS basis_hash FROM Warrant WHERE hash IN (",
    );
    {
        let mut sep = qb.separated(", ");
        for h in hashes {
            sep.push_bind(h);
        }
    }
    qb.push(")");

    qb.build_query_as::<K2OpPresentRow>()
        .fetch_all(executor)
        .await
}

/// Fetch full chain-op rows (joined with `Action` and optional `Entry`) for
/// the given op hashes, filtered to `locally_validated = 1`. A `CreateEntry`
/// op carrying a private entry is excluded even if directly requested by
/// hash — see the module-level doc for why it must never be served.
pub(crate) async fn get_chain_ops_for_wire<'e, E>(
    executor: E,
    op_hashes: &[Vec<u8>],
) -> sqlx::Result<Vec<K2ChainOpForWireRow>>
where
    E: Executor<'e, Database = Sqlite>,
{
    if op_hashes.is_empty() {
        return Ok(Vec::new());
    }

    let mut qb: QueryBuilder<Sqlite> = QueryBuilder::new(
        "SELECT
            ChainOp.hash AS op_hash,
            ChainOp.basis_hash AS basis_hash,
            ChainOp.op_type AS op_type,
            Action.hash AS action_hash,
            Action.author AS author,
            Action.timestamp AS timestamp,
            Action.seq AS seq,
            Action.prev_hash AS prev_hash,
            Action.action_data AS action_data,
            Action.signature AS signature,
            Entry.blob AS entry_blob
         FROM ChainOp
         JOIN Action ON ChainOp.action_hash = Action.hash
         LEFT JOIN Entry ON Action.entry_hash = Entry.hash
         WHERE ChainOp.locally_validated = 1
           AND (ChainOp.op_type != 2 OR Action.private_entry = 0)
           AND ChainOp.hash IN (",
    );
    {
        let mut sep = qb.separated(", ");
        for h in op_hashes {
            sep.push_bind(h);
        }
    }
    qb.push(")");

    qb.build_query_as::<K2ChainOpForWireRow>()
        .fetch_all(executor)
        .await
}

/// Fetch full warrant rows for the given op hashes (integrated warrants
/// only — joined with `WarrantOp`).
pub(crate) async fn get_warrants_for_wire<'e, E>(
    executor: E,
    op_hashes: &[Vec<u8>],
) -> sqlx::Result<Vec<K2WarrantForWireRow>>
where
    E: Executor<'e, Database = Sqlite>,
{
    if op_hashes.is_empty() {
        return Ok(Vec::new());
    }

    let mut qb: QueryBuilder<Sqlite> = QueryBuilder::new(
        "SELECT Warrant.hash, Warrant.author, Warrant.timestamp,
                Warrant.warrantee, Warrant.proof, Warrant.signature
         FROM Warrant
         JOIN WarrantOp ON WarrantOp.hash = Warrant.hash
         WHERE Warrant.hash IN (",
    );
    {
        let mut sep = qb.separated(", ");
        for h in op_hashes {
            sep.push_bind(h);
        }
    }
    qb.push(")");

    qb.build_query_as::<K2WarrantForWireRow>()
        .fetch_all(executor)
        .await
}

/// Integrated chain-op rows for the integration dump, joined with `Action` and
/// optional `Entry` for full wire reconstruction. Ordered by
/// `(when_integrated, hash)` and, when `after` is given, starting strictly after
/// that cursor — so repeated dumps page forward through newly integrated ops.
/// Passing `after = None` returns every integrated op (the dump's first page,
/// and how the consistency harness reads the full set). Reconstruct each row
/// with `build_chain_dht_op`.
pub(crate) async fn integrated_chain_ops_for_dump<'e, E>(
    executor: E,
    after: Option<(i64, &[u8])>,
    limit: Option<u32>,
) -> sqlx::Result<Vec<DumpChainOpRow>>
where
    E: Executor<'e, Database = Sqlite>,
{
    let mut qb: QueryBuilder<Sqlite> = QueryBuilder::new(
        "SELECT
            ChainOp.hash AS op_hash,
            ChainOp.basis_hash AS basis_hash,
            ChainOp.op_type AS op_type,
            ChainOp.when_integrated AS when_integrated,
            Action.hash AS action_hash,
            Action.author AS author,
            Action.timestamp AS timestamp,
            Action.seq AS seq,
            Action.prev_hash AS prev_hash,
            Action.action_data AS action_data,
            Action.signature AS signature,
            Entry.blob AS entry_blob
         FROM ChainOp
         JOIN Action ON ChainOp.action_hash = Action.hash
         LEFT JOIN Entry ON Action.entry_hash = Entry.hash
         WHERE ChainOp.locally_validated = 1",
    );
    if let Some((when_integrated, hash)) = after {
        qb.push(" AND (ChainOp.when_integrated > ");
        qb.push_bind(when_integrated);
        qb.push(" OR (ChainOp.when_integrated = ");
        qb.push_bind(when_integrated);
        qb.push(" AND ChainOp.hash > ");
        qb.push_bind(hash);
        qb.push("))");
    }
    qb.push(" ORDER BY ChainOp.when_integrated ASC, ChainOp.hash ASC");
    if let Some(limit) = limit {
        qb.push(" LIMIT ");
        qb.push_bind(i64::from(limit));
    }
    qb.build_query_as::<DumpChainOpRow>()
        .fetch_all(executor)
        .await
}

/// Fetch the chain-op rows that `author` has authored and shares with the
/// DHT, joined for full wire reconstruction. Same columns as
/// [`all_integrated_chain_ops_for_wire`] but scoped to a single author and
/// with the private-entry filter applied: `CreateEntry` ops (`op_type = 2`)
/// carrying a private entry are excluded so private entries never leak into
/// the published set. Ordered by `ChainOp.hash` for a stable result.
pub(crate) async fn ops_to_publish_for_wire<'e, E>(
    executor: E,
    author: &AgentPubKey,
) -> sqlx::Result<Vec<K2ChainOpForWireRow>>
where
    E: Executor<'e, Database = Sqlite>,
{
    sqlx::query_as::<_, K2ChainOpForWireRow>(
        "SELECT
            ChainOp.hash AS op_hash,
            ChainOp.basis_hash AS basis_hash,
            ChainOp.op_type AS op_type,
            Action.hash AS action_hash,
            Action.author AS author,
            Action.timestamp AS timestamp,
            Action.seq AS seq,
            Action.prev_hash AS prev_hash,
            Action.action_data AS action_data,
            Action.signature AS signature,
            Entry.blob AS entry_blob
         FROM ChainOp
         JOIN Action ON ChainOp.action_hash = Action.hash
         LEFT JOIN Entry ON Action.entry_hash = Entry.hash
         WHERE ChainOp.locally_validated = 1
           AND Action.author = ?
           AND (ChainOp.op_type != 2 OR Action.private_entry = 0)
         ORDER BY ChainOp.hash ASC",
    )
    .bind(author.get_raw_36())
    .fetch_all(executor)
    .await
}

/// Fetch limbo chain-op rows for full wire reconstruction, joined with
/// `Action` and optional `Entry`. Same columns as [`get_chain_ops_for_wire`]
/// but sourced from `LimboChainOp`. When `ready` is true only rows matching
/// [`LIMBO_CHAIN_OP_READY_PRED`] are returned (integration-limbo); when false
/// only the complement is returned (validation-limbo). Ordered by
/// `LimboChainOp.hash` for a stable result (`LimboChainOp` is `WITHOUT
/// ROWID`).
pub(crate) async fn limbo_chain_ops_for_dump<'e, E>(
    executor: E,
    ready: bool,
) -> sqlx::Result<Vec<K2ChainOpForWireRow>>
where
    E: Executor<'e, Database = Sqlite>,
{
    let predicate = if ready {
        LIMBO_CHAIN_OP_READY_PRED.to_string()
    } else {
        limbo_chain_op_not_ready_pred()
    };
    let sql = format!(
        "SELECT
            LimboChainOp.hash AS op_hash,
            LimboChainOp.basis_hash AS basis_hash,
            LimboChainOp.op_type AS op_type,
            Action.hash AS action_hash,
            Action.author AS author,
            Action.timestamp AS timestamp,
            Action.seq AS seq,
            Action.prev_hash AS prev_hash,
            Action.action_data AS action_data,
            Action.signature AS signature,
            Entry.blob AS entry_blob
         FROM LimboChainOp
         JOIN Action ON LimboChainOp.action_hash = Action.hash
         LEFT JOIN Entry ON Action.entry_hash = Entry.hash
         WHERE {predicate}
         ORDER BY LimboChainOp.hash ASC"
    );
    // SQL is assembled from a compile-time-constant predicate (no user
    // input), so asserting it is safe.
    sqlx::query_as::<_, K2ChainOpForWireRow>(sqlx::AssertSqlSafe(sql))
        .fetch_all(executor)
        .await
}

/// Fetch every integrated warrant row for full wire reconstruction. Same
/// columns as [`get_warrants_for_wire`] but with no hash filter. Ordered by
/// `WarrantOp.hash` for a stable result (`WarrantOp` is `WITHOUT ROWID`).
pub(crate) async fn integrated_warrants_for_dump<'e, E>(
    executor: E,
) -> sqlx::Result<Vec<K2WarrantForWireRow>>
where
    E: Executor<'e, Database = Sqlite>,
{
    sqlx::query_as::<_, K2WarrantForWireRow>(
        "SELECT Warrant.hash, Warrant.author, Warrant.timestamp,
                Warrant.warrantee, Warrant.proof, Warrant.signature
         FROM Warrant
         JOIN WarrantOp ON WarrantOp.hash = Warrant.hash
         ORDER BY WarrantOp.hash ASC",
    )
    .fetch_all(executor)
    .await
}

#[derive(Debug, sqlx::FromRow)]
struct DumpOpKeyRow {
    hash: Vec<u8>,
    when_received: i64,
    state: i64,
    kind: i64,
}

#[derive(Debug, Clone, Copy)]
enum DumpChainTable {
    Integrated,
    Limbo,
}

/// Select and hydrate one globally ordered DHT-op dump page.
///
/// The caller must pass a connection inside a [`TxRead`](crate::TxRead), so
/// selecting lightweight keys and hydrating their wire rows observes one
/// immutable snapshot while workflow transactions promote ops between tables.
pub(crate) async fn dht_ops_page_for_dump(
    conn: &mut sqlx::SqliteConnection,
    after: Option<(i64, &DhtOpHash)>,
    limit: Option<u32>,
) -> sqlx::Result<DumpOpPage> {
    let mut qb: QueryBuilder<Sqlite> = QueryBuilder::new(
        "SELECT hash, when_received, state, kind FROM (
            SELECT hash, when_received, 2 AS state, 0 AS kind
            FROM ChainOp WHERE locally_validated = 1
            UNION ALL
            SELECT hash, when_received, 2 AS state, 1 AS kind FROM WarrantOp
            UNION ALL
            SELECT hash, when_received,
                CASE WHEN ",
    );
    qb.push(LIMBO_CHAIN_OP_READY_PRED);
    qb.push(
        " THEN 1 ELSE 0 END AS state,
            0 AS kind
         FROM LimboChainOp
         UNION ALL
         SELECT hash, when_received,
            CASE WHEN sys_validation_status IN (1, 2) THEN 1 ELSE 0 END AS state,
            1 AS kind
         FROM LimboWarrantOp
         ) WHERE 1 = 1",
    );
    if let Some((when_received, hash)) = after {
        qb.push(" AND (when_received > ");
        qb.push_bind(when_received);
        qb.push(" OR (when_received = ");
        qb.push_bind(when_received);
        qb.push(" AND hash > ");
        qb.push_bind(hash.get_raw_36());
        qb.push("))");
    }
    qb.push(" ORDER BY when_received ASC, hash ASC");
    if let Some(limit) = limit {
        qb.push(" LIMIT ");
        qb.push_bind(i64::from(limit));
    }
    let keys = qb
        .build_query_as::<DumpOpKeyRow>()
        .fetch_all(&mut *conn)
        .await?;

    let cursor = keys.last().map(|key| DumpOpCursorRow {
        when_received: key.when_received,
        hash: DhtOpHash::from_raw_36(key.hash.clone()),
    });
    let integrated_chain_hashes = dump_hashes(&keys, Some(2), 0);
    let limbo_chain_hashes = dump_hashes(&keys, None, 0);
    let warrant_hashes = dump_hashes(&keys, None, 1);

    let mut integrated_chain = chain_ops_for_dump_by_hashes(
        &mut *conn,
        DumpChainTable::Integrated,
        &integrated_chain_hashes,
    )
    .await?
    .into_iter()
    .map(|row| (row.op_hash.clone(), row))
    .collect::<HashMap<_, _>>();
    let mut limbo_chain =
        chain_ops_for_dump_by_hashes(&mut *conn, DumpChainTable::Limbo, &limbo_chain_hashes)
            .await?
            .into_iter()
            .map(|row| (row.op_hash.clone(), row))
            .collect::<HashMap<_, _>>();
    let mut warrants = warrants_for_dump_by_hashes(&mut *conn, &warrant_hashes)
        .await?
        .into_iter()
        .map(|row| (row.hash.clone(), row))
        .collect::<HashMap<_, _>>();

    let rows = keys
        .into_iter()
        .filter_map(|key| {
            let state = match key.state {
                0 => DumpOpState::ValidationLimbo,
                1 => DumpOpState::IntegrationLimbo,
                2 => DumpOpState::Integrated,
                _ => return None,
            };
            let wire = match (key.kind, state) {
                (0, DumpOpState::Integrated) => {
                    integrated_chain.remove(&key.hash).map(DumpOpWireRow::Chain)
                }
                (0, _) => limbo_chain.remove(&key.hash).map(DumpOpWireRow::Chain),
                (1, _) => warrants.remove(&key.hash).map(DumpOpWireRow::Warrant),
                _ => None,
            }?;
            Some(DumpOpRow { state, wire })
        })
        .collect();

    Ok(DumpOpPage { rows, cursor })
}

/// Select one globally ordered page of DHT-op lifecycle timings.
///
/// Unions the two limbo tables with the two integrated tables so in-flight and
/// integrated ops share one `(when_received, hash)` ordering and one limit.
/// Unlike [`dht_ops_page_for_dump`] this does not filter out cache-inserted
/// chain ops: `locally_validated = 0` is what explains an op whose integration
/// time equals its received time.
///
/// One op hash can be present in an integrated table and in its limbo
/// counterpart at the same time, so each pair carries a `NOT EXISTS` clause
/// that suppresses the shadowed row and keeps the page at one row per op:
///
/// - `ChainOp` / `LimboChainOp`: the cascade mirrors ops into `ChainOp` with
///   `locally_validated = 0` without deleting anything from limbo, and
///   `op_exists` deliberately ignores those mirrored rows so the op is still
///   delivered into the validation path. The limbo row is the truthful one
///   there — the op is not integrated, its mirrored `when_integrated` is just
///   the cache-write time — so the mirror is dropped. In the reverse case
///   (`locally_validated = 1` alongside a limbo row, which promotion should
///   have deleted) the integrated row is the truthful one and the limbo row is
///   dropped instead.
/// - `WarrantOp` / `LimboWarrantOp`: the cascade re-stages warrants that come
///   back with a get response into limbo unconditionally, so an already
///   integrated warrant can regain a limbo row. A `WarrantOp` row is only ever
///   written by promotion, so it always wins and the limbo row is dropped.
pub(crate) async fn op_timings_page<'e, E>(
    executor: E,
    after: Option<(i64, &DhtOpHash)>,
    limit: Option<u32>,
) -> sqlx::Result<OpTimingsPage>
where
    E: Executor<'e, Database = Sqlite>,
{
    let mut qb: QueryBuilder<Sqlite> = QueryBuilder::new(
        "SELECT hash, when_received, when_integrated, abandoned_at,
                validation_status, locally_validated FROM (
            SELECT hash, when_received, when_integrated,
                   NULL AS abandoned_at, validation_status, locally_validated
            FROM ChainOp
            WHERE locally_validated = 1
               OR NOT EXISTS (
                   SELECT 1 FROM LimboChainOp
                   WHERE LimboChainOp.hash = ChainOp.hash
               )
            UNION ALL
            SELECT hash, when_received, when_integrated,
                   NULL AS abandoned_at, validation_status,
                   NULL AS locally_validated
            FROM WarrantOp
            UNION ALL
            SELECT hash, when_received, NULL AS when_integrated, abandoned_at,
                   NULL AS validation_status, NULL AS locally_validated
            FROM LimboChainOp
            WHERE NOT EXISTS (
                SELECT 1 FROM ChainOp
                WHERE ChainOp.hash = LimboChainOp.hash
                  AND ChainOp.locally_validated = 1
            )
            UNION ALL
            SELECT hash, when_received, NULL AS when_integrated, abandoned_at,
                   NULL AS validation_status, NULL AS locally_validated
            FROM LimboWarrantOp
            WHERE NOT EXISTS (
                SELECT 1 FROM WarrantOp
                WHERE WarrantOp.hash = LimboWarrantOp.hash
            )
         ) WHERE 1 = 1",
    );
    if let Some((when_received, hash)) = after {
        qb.push(" AND (when_received > ");
        qb.push_bind(when_received);
        qb.push(" OR (when_received = ");
        qb.push_bind(when_received);
        qb.push(" AND hash > ");
        qb.push_bind(hash.get_raw_36());
        qb.push("))");
    }
    qb.push(" ORDER BY when_received ASC, hash ASC");
    if let Some(limit) = limit {
        qb.push(" LIMIT ");
        qb.push_bind(i64::from(limit));
    }

    let rows = qb
        .build_query_as::<OpTimingRow>()
        .fetch_all(executor)
        .await?;
    let cursor = rows.last().map(|row| DumpOpCursorRow {
        when_received: row.when_received,
        hash: DhtOpHash::from_raw_36(row.hash.clone()),
    });

    Ok(OpTimingsPage { rows, cursor })
}

fn dump_hashes(keys: &[DumpOpKeyRow], state: Option<i64>, kind: i64) -> Vec<Vec<u8>> {
    keys.iter()
        .filter(|key| key.kind == kind && state.is_none_or(|state| key.state == state))
        .map(|key| key.hash.clone())
        .collect()
}

async fn chain_ops_for_dump_by_hashes(
    conn: &mut sqlx::SqliteConnection,
    table: DumpChainTable,
    hashes: &[Vec<u8>],
) -> sqlx::Result<Vec<K2ChainOpForWireRow>> {
    if hashes.is_empty() {
        return Ok(Vec::new());
    }
    let mut qb: QueryBuilder<Sqlite> = QueryBuilder::new(
        "SELECT
            op.hash AS op_hash,
            op.basis_hash AS basis_hash,
            op.op_type AS op_type,
            Action.hash AS action_hash,
            Action.author AS author,
            Action.timestamp AS timestamp,
            Action.seq AS seq,
            Action.prev_hash AS prev_hash,
            Action.action_data AS action_data,
            Action.signature AS signature,
            Entry.blob AS entry_blob
         FROM ",
    );
    qb.push(match table {
        DumpChainTable::Integrated => "ChainOp",
        DumpChainTable::Limbo => "LimboChainOp",
    });
    qb.push(
        " AS op
         JOIN Action ON op.action_hash = Action.hash
         LEFT JOIN Entry ON Action.entry_hash = Entry.hash
         WHERE op.hash IN (",
    );
    {
        let mut separated = qb.separated(", ");
        for hash in hashes {
            separated.push_bind(hash);
        }
    }
    qb.push(")");
    qb.build_query_as::<K2ChainOpForWireRow>()
        .fetch_all(conn)
        .await
}

async fn warrants_for_dump_by_hashes(
    conn: &mut sqlx::SqliteConnection,
    hashes: &[Vec<u8>],
) -> sqlx::Result<Vec<K2WarrantForWireRow>> {
    if hashes.is_empty() {
        return Ok(Vec::new());
    }
    let mut qb: QueryBuilder<Sqlite> = QueryBuilder::new(
        "SELECT hash, author, timestamp, warrantee, proof, signature
         FROM Warrant WHERE hash IN (",
    );
    {
        let mut separated = qb.separated(", ");
        for hash in hashes {
            separated.push_bind(hash);
        }
    }
    qb.push(")");
    qb.build_query_as::<K2WarrantForWireRow>()
        .fetch_all(conn)
        .await
}

/// SQL for [`earliest_authored_timestamp_in_arc`]; its placeholders take the arc binds of
/// [`ArcBounds::binds`] once per `UNION ALL` branch.
fn earliest_authored_timestamp_in_arc_sql(arc: ArcBounds) -> String {
    let chain_arc = arc.predicate("ChainOp.storage_center_loc");
    let warrant_arc = arc.predicate("WarrantOp.storage_center_loc");
    format!(
        "
        SELECT MIN(ts) FROM (
            SELECT Action.timestamp AS ts
            FROM ChainOp
            JOIN Action ON ChainOp.action_hash = Action.hash
            WHERE
                {chain_arc}
                AND ChainOp.locally_validated = 1
                AND (ChainOp.op_type != 2 OR Action.private_entry = 0)
            UNION ALL
            SELECT Warrant.timestamp AS ts
            FROM Warrant
            JOIN WarrantOp ON WarrantOp.hash = Warrant.hash
            WHERE
                {warrant_arc}
        )
    "
    )
}

/// Minimum authored timestamp across both `ChainOp` (joined with `Action`)
/// and integrated warrants (`Warrant` joined with `WarrantOp`), filtered
/// to `arc` and (for chain ops) `locally_validated = 1` with private
/// `CreateEntry` ops excluded so a withheld private op never sets the
/// advertised earliest-data boundary. `None` when no rows match.
pub(crate) async fn earliest_authored_timestamp_in_arc<'e, E>(
    executor: E,
    arc: ArcBounds,
) -> sqlx::Result<Option<i64>>
where
    E: Executor<'e, Database = Sqlite>,
{
    let sql = earliest_authored_timestamp_in_arc_sql(arc);
    let (a, b) = arc.binds();
    // SQL is assembled from compile-time-constant arc predicates (no user
    // input), so asserting it is safe.
    let row: Option<(Option<i64>,)> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
        // chain-op branch
        .bind(a)
        .bind(b)
        // warrant branch
        .bind(a)
        .bind(b)
        .fetch_optional(executor)
        .await?;
    Ok(row.and_then(|(v,)| v))
}

// ELOHIM PATCH (k2 DHT-model cold start): secondary indexes the K2 op-store
// arc reads need. The 0.7 `holochain_data` DHT schema ships no secondary
// index at all (0.6's `DhtOp` had `storage_center_loc` and
// `authored_timestamp` indexes), so every per-sector read above was a full
// `ChainOp` scan whatever its predicate. The loc index is covering for the
// time-slice / earliest / ids-since reads (the `WITHOUT ROWID` primary key
// `hash` rides along), so a sector read touches ~1/512 of the table plus one
// `Action` primary-key probe per row.
//
// Created idempotently at open time rather than as a sqlx migration on
// purpose: a migration recorded in `_sqlx_migrations` that an older binary
// does not know makes that binary refuse to open the database
// (`VersionMissing`), which would turn a conductor rollback into an outage.
// An extra index is invisible to an older binary. Names carry an `elohim_`
// prefix so an upstream migration adding equivalents cannot collide.
/// `CREATE INDEX IF NOT EXISTS` statements applied to every DHT database at
/// open, after migrations.
pub(crate) const DHT_SYNC_INDEXES: &[&str] = &[
    "CREATE INDEX IF NOT EXISTS elohim_ChainOp_loc_sync_idx ON ChainOp (
        storage_center_loc, locally_validated, op_type, action_hash,
        basis_hash, serialized_size, when_integrated
    )",
    "CREATE INDEX IF NOT EXISTS elohim_WarrantOp_loc_idx ON WarrantOp (storage_center_loc)",
    // ELOHIM PATCH (fleet CPU storm): the per-author publish reads. The
    // publish selector and its still-needing-publish sibling run for every
    // hosted agent on every publish loop and filter on `Action.author`, but
    // with no author index and no `ChainOp.action_hash` index the planner
    // could only SCAN all of `ChainOp` (via the loc index) and probe `Action`
    // per row: seconds per call on a grown store, whoever the author. With
    // these two the plan is `Action` by author -> `ChainOp` by action ->
    // `ChainOpPublish` by primary key, proportional to the author's own ops.
    // Both are covering for those reads (`Action.private_entry` for the
    // private-entry guard; `locally_validated`, `op_type`, `basis_hash` on
    // `ChainOp`): measured on the household stores, a plain
    // `(action_hash)` index made a single-author store with a 160k-op chain
    // 3x slower than the scan (a table lookup per op), while the covering
    // pair holds it at parity and cuts an 18-agent store 36x.
    "CREATE INDEX IF NOT EXISTS elohim_Action_author_publish_idx
        ON Action (author, seq, private_entry)",
    "CREATE INDEX IF NOT EXISTS elohim_ChainOp_action_publish_idx
        ON ChainOp (action_hash, locally_validated, op_type, basis_hash)",
    // Sys-validation's chain-fork check (`get_actions_by_prev_hash`) runs per
    // incoming op and was a full `Action` scan.
    "CREATE INDEX IF NOT EXISTS elohim_Action_prev_hash_idx ON Action (prev_hash)",
    // ELOHIM PATCH (fleet CPU storm, get path): the authority / cascade reads
    // behind every zome `get`, `get_details` and `get_links`, and the receipt
    // count behind every received validation receipt, filter on columns the
    // 0.7 schema never indexed, so each was a full table scan returning 0-1
    // rows. With the publish scans gone these were the dominant slow
    // statements on the household mesh under scenario load.
    "CREATE INDEX IF NOT EXISTS elohim_ChainOp_basis_idx ON ChainOp (basis_hash, op_type)",
    "CREATE INDEX IF NOT EXISTS elohim_UpdatedRecord_original_action_idx
        ON UpdatedRecord (original_action_hash)",
    "CREATE INDEX IF NOT EXISTS elohim_UpdatedRecord_original_entry_idx
        ON UpdatedRecord (original_entry_hash)",
    "CREATE INDEX IF NOT EXISTS elohim_DeletedRecord_deletes_action_idx
        ON DeletedRecord (deletes_action_hash)",
    "CREATE INDEX IF NOT EXISTS elohim_DeletedRecord_deletes_entry_idx
        ON DeletedRecord (deletes_entry_hash)",
    "CREATE INDEX IF NOT EXISTS elohim_Link_base_idx ON Link (base_hash)",
    "CREATE INDEX IF NOT EXISTS elohim_DeletedLink_create_idx ON DeletedLink (create_link_hash)",
    "CREATE INDEX IF NOT EXISTS elohim_ValidationReceipt_op_idx ON ValidationReceipt (op_hash)",
];

/// Ensure [`DHT_SYNC_INDEXES`] exist. Idempotent; on a large store that
/// predates them the first call builds them once (a single sort of `ChainOp`).
pub(crate) async fn ensure_sync_indexes<'e, E>(executor: E) -> sqlx::Result<()>
where
    E: Executor<'e, Database = Sqlite> + Copy,
{
    for stmt in DHT_SYNC_INDEXES {
        sqlx::query(*stmt).execute(executor).await?;
    }
    Ok(())
}

/// Total count of every integrated op + warrant in this DHT store, with no
/// `locally_validated` filter — the total observed DHT size.
pub(crate) async fn count_integrated_ops<'e, E>(executor: E) -> sqlx::Result<i64>
where
    E: Executor<'e, Database = Sqlite>,
{
    let (n,): (i64,) = sqlx::query_as(
        "SELECT
            (SELECT COUNT(*) FROM ChainOp)
            +
            (SELECT COUNT(*) FROM WarrantOp)",
    )
    .fetch_one(executor)
    .await?;
    Ok(n)
}

/// Predicate matching `LimboChainOp` rows ready for integration. Kept in
/// sync with `limbo_chain_ops_ready_for_integration` (in
/// `inner/limbo_chain_op.rs`): a row is ready once sys-validation rejected it
/// outright, or sys-validation accepted it and app-validation reached a
/// terminal state.
const LIMBO_CHAIN_OP_READY_PRED: &str =
    "sys_validation_status = 2 OR (sys_validation_status = 1 AND app_validation_status IN (1, 2))";

/// Negation of [`LIMBO_CHAIN_OP_READY_PRED`]. The ready predicate evaluates
/// to `NULL` (not `false`) for rows with `sys_validation_status IS NULL`, so
/// a bare `NOT (...)` would silently drop pending ops under SQL's
/// three-valued logic. Wrapping in `COALESCE(..., 0)` forces those rows to
/// count as not-ready, which is what "still in validation" means.
fn limbo_chain_op_not_ready_pred() -> String {
    format!("NOT COALESCE(({LIMBO_CHAIN_OP_READY_PRED}), 0)")
}

/// `(validation_limbo, integration_limbo, integrated)` counts across the
/// limbo + integrated tables.
///
/// - `integrated` = locally-validated `ChainOp` rows (GET-cached ops with
///   `locally_validated = 0` are excluded) plus all `WarrantOp` rows.
/// - `integration_limbo` = limbo ops ready for integration: `LimboChainOp`
///   rows matching [`LIMBO_CHAIN_OP_READY_PRED`] plus `LimboWarrantOp` rows
///   with a terminal `sys_validation_status` (1 or 2).
/// - `validation_limbo` = limbo ops not yet ready: the complement of the
///   above within each limbo table.
pub(crate) async fn limbo_state_counts<'e, E>(executor: E) -> sqlx::Result<(i64, i64, i64)>
where
    E: Executor<'e, Database = Sqlite>,
{
    let sql = format!(
        "SELECT
            (
                (SELECT COUNT(*) FROM LimboChainOp WHERE {not_ready})
                +
                (SELECT COUNT(*) FROM LimboWarrantOp WHERE sys_validation_status IS NULL)
            ) AS validation_limbo,
            (
                (SELECT COUNT(*) FROM LimboChainOp WHERE {ready})
                +
                (SELECT COUNT(*) FROM LimboWarrantOp WHERE sys_validation_status IN (1, 2))
            ) AS integration_limbo,
            (
                (SELECT COUNT(*) FROM ChainOp WHERE locally_validated = 1)
                +
                (SELECT COUNT(*) FROM WarrantOp)
            ) AS integrated",
        ready = LIMBO_CHAIN_OP_READY_PRED,
        not_ready = limbo_chain_op_not_ready_pred(),
    );
    // SQL is assembled from a compile-time-constant predicate (no user
    // input), so asserting it is safe.
    let counts: (i64, i64, i64) = sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .fetch_one(executor)
        .await?;
    Ok(counts)
}

/// Count of integrated, locally-validated `ChainOp` rows that passed validation
/// (`validation_status = 1`). GET-cached copies (`locally_validated = 0`) and
/// rejected ops are excluded.
#[cfg(any(test, feature = "inspection"))]
pub(crate) async fn count_valid_integrated_ops<'e, E>(executor: E) -> sqlx::Result<i64>
where
    E: Executor<'e, Database = Sqlite>,
{
    let (n,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM ChainOp WHERE locally_validated = 1 AND validation_status = 1",
    )
    .fetch_one(executor)
    .await?;
    Ok(n)
}

/// Count of `LimboChainOp` rows that have passed both sys- and app-validation
/// (`sys_validation_status = 1 AND app_validation_status = 1`) but are not yet
/// integrated.
#[cfg(any(test, feature = "inspection"))]
pub(crate) async fn count_valid_not_integrated_ops<'e, E>(executor: E) -> sqlx::Result<i64>
where
    E: Executor<'e, Database = Sqlite>,
{
    let (n,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM LimboChainOp \
         WHERE sys_validation_status = 1 AND app_validation_status = 1",
    )
    .fetch_one(executor)
    .await?;
    Ok(n)
}

/// Count of not-yet-integrated `LimboChainOp` rows authored by `author`.
#[cfg(any(test, feature = "inspection"))]
pub(crate) async fn count_pending_ops_for_author<'e, E>(
    executor: E,
    author: &AgentPubKey,
) -> sqlx::Result<i64>
where
    E: Executor<'e, Database = Sqlite>,
{
    let (n,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM LimboChainOp \
         JOIN Action ON Action.hash = LimboChainOp.action_hash \
         WHERE Action.author = ?",
    )
    .bind(author.get_raw_36())
    .fetch_one(executor)
    .await?;
    Ok(n)
}

/// Hashes of integrated, locally-validated chain ops that were rejected.
/// GET-cached copies (`locally_validated = 0`) are excluded. Ordered by hash
/// for a stable result.
#[cfg(any(test, feature = "inspection"))]
pub(crate) async fn rejected_integrated_op_hashes<'e, E>(executor: E) -> sqlx::Result<Vec<Vec<u8>>>
where
    E: Executor<'e, Database = Sqlite>,
{
    let rows: Vec<(Vec<u8>,)> = sqlx::query_as(
        "SELECT hash FROM ChainOp \
         WHERE locally_validated = 1 AND validation_status = 2 \
         ORDER BY hash",
    )
    .fetch_all(executor)
    .await?;
    Ok(rows.into_iter().map(|(h,)| h).collect())
}

/// Total count of every op held in this DHT store: integrated `ChainOp` and
/// `WarrantOp` plus their limbo counterparts.
#[cfg(any(test, feature = "inspection"))]
pub(crate) async fn count_all_ops<'e, E>(executor: E) -> sqlx::Result<i64>
where
    E: Executor<'e, Database = Sqlite>,
{
    let (n,): (i64,) = sqlx::query_as(
        "SELECT
            (SELECT COUNT(*) FROM ChainOp)
            + (SELECT COUNT(*) FROM LimboChainOp)
            + (SELECT COUNT(*) FROM WarrantOp)
            + (SELECT COUNT(*) FROM LimboWarrantOp)",
    )
    .fetch_one(executor)
    .await?;
    Ok(n)
}

/// Whether the integrated chain op `op_hash` is flagged as requiring a
/// validation receipt. Returns `false` when the op is not an integrated
/// chain op.
#[cfg(any(test, feature = "inspection"))]
pub(crate) async fn op_requires_receipt<'e, E>(
    executor: E,
    op_hash: &DhtOpHash,
) -> sqlx::Result<bool>
where
    E: Executor<'e, Database = Sqlite>,
{
    let row: Option<(bool,)> = sqlx::query_as("SELECT require_receipt FROM ChainOp WHERE hash = ?")
        .bind(op_hash.get_raw_36())
        .fetch_optional(executor)
        .await?;
    Ok(row.map(|(b,)| b).unwrap_or(false))
}

/// Whether `op_hash` is present in the limbo (not-yet-integrated) chain ops.
#[cfg(any(test, feature = "inspection"))]
pub(crate) async fn limbo_op_exists<'e, E>(executor: E, op_hash: &DhtOpHash) -> sqlx::Result<bool>
where
    E: Executor<'e, Database = Sqlite>,
{
    let (b,): (bool,) = sqlx::query_as("SELECT EXISTS(SELECT 1 FROM LimboChainOp WHERE hash = ?)")
        .bind(op_hash.get_raw_36())
        .fetch_one(executor)
        .await?;
    Ok(b)
}

/// Hashes of limbo chain ops flagged as requiring a validation receipt.
/// Ordered by hash for a stable result.
#[cfg(any(test, feature = "inspection"))]
pub(crate) async fn limbo_op_hashes_requiring_receipt<'e, E>(
    executor: E,
) -> sqlx::Result<Vec<Vec<u8>>>
where
    E: Executor<'e, Database = Sqlite>,
{
    let rows: Vec<(Vec<u8>,)> =
        sqlx::query_as("SELECT hash FROM LimboChainOp WHERE require_receipt = 1 ORDER BY hash")
            .fetch_all(executor)
            .await?;
    Ok(rows.into_iter().map(|(h,)| h).collect())
}

/// Hashes of integrated chain ops with the given DHT `basis`. Ordered by hash
/// for a stable result.
#[cfg(any(test, feature = "inspection"))]
pub(crate) async fn get_ops_at_basis<'e, E>(
    executor: E,
    basis: &AnyLinkableHash,
) -> sqlx::Result<Vec<Vec<u8>>>
where
    E: Executor<'e, Database = Sqlite>,
{
    let rows: Vec<(Vec<u8>,)> = sqlx::query_as(
        "SELECT hash FROM ChainOp WHERE basis_hash = ? AND locally_validated = 1 ORDER BY hash",
    )
    .bind(basis.get_raw_36())
    .fetch_all(executor)
    .await?;
    Ok(rows.into_iter().map(|(h,)| h).collect())
}

/// Count of rows in the public `Entry` table (private entries live in
/// `PrivateEntry` and are not counted here).
#[cfg(any(test, feature = "inspection"))]
pub(crate) async fn count_entries<'e, E>(executor: E) -> sqlx::Result<i64>
where
    E: Executor<'e, Database = Sqlite>,
{
    let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM Entry")
        .fetch_one(executor)
        .await?;
    Ok(n)
}

/// Count of public `Entry` rows whose action carries a private entry. This is
/// always zero: private entries are stored only in `PrivateEntry`, never in the
/// shared `Entry` table.
#[cfg(any(test, feature = "inspection"))]
pub(crate) async fn count_private_entries_in_public_table<'e, E>(executor: E) -> sqlx::Result<i64>
where
    E: Executor<'e, Database = Sqlite>,
{
    let (n,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM Entry \
         JOIN Action ON Action.entry_hash = Entry.hash \
         WHERE Action.private_entry = 1",
    )
    .fetch_one(executor)
    .await?;
    Ok(n)
}

#[cfg(test)]
mod tests {
    use crate::handles::DbWrite;
    use crate::kind::Dht;
    use crate::models::dht::{DumpOpCursorRow, DumpOpRow, DumpOpState, DumpOpWireRow, OpTimingRow};
    use crate::test_open_db;
    use holo_hash::{AgentPubKey, DhtOpHash, DnaHash};
    use sqlx::{Pool, Sqlite};
    use std::sync::Arc;

    /// `ChainOpType::CreateEntry` discriminant.
    const STORE_ENTRY: i64 = 2;
    /// `ChainOpType::CreateRecord` discriminant.
    const STORE_RECORD: i64 = 1;
    /// Author shared by every seeded op so the publish read finds them all.
    const AUTHOR: u8 = 7;

    fn dht_id() -> Dht {
        Dht::new(Arc::new(DnaHash::from_raw_36(vec![0u8; 36])))
    }

    /// Insert one integrated, locally-validated chain op with its action, at
    /// storage location 0 so it falls inside a full arc. `op_tag` makes the
    /// op/action/basis hashes unique; `private_entry` is the action's
    /// private-entry flag; `timestamp` is used for both the authored timestamp
    /// and the integration time. Returns the op hash.
    async fn seed_op(
        pool: &Pool<Sqlite>,
        op_tag: u8,
        op_type: i64,
        private_entry: i64,
        timestamp: i64,
    ) -> Vec<u8> {
        let op_hash = vec![op_tag; 36];
        let action_hash = vec![op_tag + 10; 36];
        let basis_hash = vec![op_tag + 20; 36];

        sqlx::query(
            "INSERT INTO Action
                (hash, author, seq, prev_hash, timestamp, action_type,
                 action_data, signature, entry_hash, private_entry, record_validity)
             VALUES (?, ?, 0, NULL, ?, 0, ?, ?, NULL, ?, NULL)",
        )
        .bind(&action_hash)
        .bind(vec![AUTHOR; 36])
        .bind(timestamp)
        .bind(vec![0u8]) // dummy ActionData blob; reads under test never decode it
        .bind(vec![0u8]) // dummy signature blob
        .bind(private_entry)
        .execute(pool)
        .await
        .unwrap();

        sqlx::query(
            "INSERT INTO ChainOp
                (hash, op_type, action_hash, basis_hash, storage_center_loc,
                 validation_status, locally_validated, require_receipt,
                 when_received, when_integrated, serialized_size)
             VALUES (?, ?, ?, ?, 0, 1, 1, 0, ?, ?, 10)",
        )
        .bind(&op_hash)
        .bind(op_type)
        .bind(&action_hash)
        .bind(&basis_hash)
        .bind(timestamp)
        .bind(timestamp)
        .execute(pool)
        .await
        .unwrap();

        op_hash
    }

    async fn seed_limbo_chain_op(
        pool: &Pool<Sqlite>,
        op_tag: u8,
        when_received: i64,
        ready: bool,
    ) -> Vec<u8> {
        let op_hash = vec![op_tag; 36];
        let action_hash = vec![op_tag + 100; 36];
        sqlx::query(
            "INSERT INTO Action
                (hash, author, seq, prev_hash, timestamp, action_type,
                 action_data, signature, entry_hash, private_entry, record_validity)
             VALUES (?, ?, 0, NULL, ?, 0, ?, ?, NULL, 0, NULL)",
        )
        .bind(&action_hash)
        .bind(vec![AUTHOR; 36])
        .bind(when_received)
        .bind(vec![0u8])
        .bind(vec![0u8])
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO LimboChainOp
                (hash, op_type, action_hash, basis_hash, storage_center_loc,
                 sys_validation_status, app_validation_status, require_receipt,
                 when_received, serialized_size)
             VALUES (?, ?, ?, ?, 0, ?, ?, 0, ?, 10)",
        )
        .bind(&op_hash)
        .bind(STORE_RECORD)
        .bind(&action_hash)
        .bind(vec![op_tag + 50; 36])
        .bind(ready.then_some(1_i64))
        .bind(ready.then_some(1_i64))
        .bind(when_received)
        .execute(pool)
        .await
        .unwrap();
        op_hash
    }

    async fn seed_warrant_op(
        pool: &Pool<Sqlite>,
        op_tag: u8,
        when_received: i64,
        state: DumpOpState,
    ) -> Vec<u8> {
        let hash = vec![op_tag; 36];
        sqlx::query(
            "INSERT INTO Warrant
                (hash, author, timestamp, warrantee, proof, signature, reason)
             VALUES (?, ?, ?, ?, ?, ?, NULL)",
        )
        .bind(&hash)
        .bind(vec![AUTHOR; 36])
        .bind(when_received)
        .bind(vec![op_tag + 40; 36])
        .bind(vec![0u8])
        .bind(vec![0u8])
        .execute(pool)
        .await
        .unwrap();
        match state {
            DumpOpState::Integrated => {
                sqlx::query(
                    "INSERT INTO WarrantOp
                        (hash, storage_center_loc, when_received, when_integrated,
                         validation_status, serialized_size)
                     VALUES (?, 0, ?, ?, 1, 10)",
                )
                .bind(&hash)
                .bind(when_received)
                .bind(when_received + 1_000)
                .execute(pool)
                .await
                .unwrap();
            }
            DumpOpState::ValidationLimbo | DumpOpState::IntegrationLimbo => {
                sqlx::query(
                    "INSERT INTO LimboWarrantOp
                        (hash, storage_center_loc, sys_validation_status,
                         when_received, serialized_size)
                     VALUES (?, 0, ?, ?, 10)",
                )
                .bind(&hash)
                .bind((state == DumpOpState::IntegrationLimbo).then_some(1_i64))
                .bind(when_received)
                .execute(pool)
                .await
                .unwrap();
            }
        }
        hash
    }

    fn dump_row_hash(row: &DumpOpRow) -> &[u8] {
        match &row.wire {
            DumpOpWireRow::Chain(row) => &row.op_hash,
            DumpOpWireRow::Warrant(row) => &row.hash,
        }
    }

    async fn promote_seeded_limbo_chain_op(db: &DbWrite<Dht>, hash: &[u8]) {
        let mut tx = db.begin().await.unwrap();
        sqlx::query(
            "INSERT INTO ChainOp
                (hash, op_type, action_hash, basis_hash, storage_center_loc,
                 validation_status, locally_validated, require_receipt,
                 when_received, when_integrated, serialized_size)
             SELECT hash, op_type, action_hash, basis_hash, storage_center_loc,
                    1, 1, require_receipt, when_received, 999, serialized_size
             FROM LimboChainOp WHERE hash = ?",
        )
        .bind(hash)
        .execute(tx.conn_mut())
        .await
        .unwrap();
        sqlx::query("DELETE FROM LimboChainOp WHERE hash = ?")
            .bind(hash)
            .execute(tx.conn_mut())
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }

    /// Seed three integrated ops that exercise the private-entry filter:
    /// a public `CreateEntry` (servable), a private `CreateEntry` (must be
    /// withheld — it is authored *earliest*, at timestamp 1000, to also probe
    /// the earliest-timestamp boundary), and a `CreateRecord` carrying a private
    /// entry (servable, since it withholds the entry body). Returns
    /// `(db, public_store_entry, private_store_entry, private_store_record)`.
    async fn seed_filter_fixture() -> (DbWrite<Dht>, Vec<u8>, Vec<u8>, Vec<u8>) {
        let db = test_open_db(dht_id()).await.unwrap();
        let public = seed_op(db.pool(), 1, STORE_ENTRY, 0, 2000).await;
        let private = seed_op(db.pool(), 2, STORE_ENTRY, 1, 1000).await;
        let record = seed_op(db.pool(), 3, STORE_RECORD, 1, 3000).await;
        (db, public, private, record)
    }

    // ---- ELOHIM PATCH: K2 arc reads are index-served (DHT-model cold start) ----

    /// Seed one integrated, locally-validated public `CreateRecord` op at
    /// storage location `loc`, authored and integrated at `timestamp`.
    async fn seed_op_at(pool: &Pool<Sqlite>, op_tag: u8, loc: u32, timestamp: i64) -> Vec<u8> {
        let op_hash = vec![op_tag; 36];
        let action_hash = vec![op_tag.wrapping_add(100); 36];
        sqlx::query(
            "INSERT INTO Action
                (hash, author, seq, prev_hash, timestamp, action_type,
                 action_data, signature, entry_hash, private_entry, record_validity)
             VALUES (?, ?, 0, NULL, ?, 0, ?, ?, NULL, 0, NULL)",
        )
        .bind(&action_hash)
        .bind(vec![AUTHOR; 36])
        .bind(timestamp)
        .bind(vec![0u8])
        .bind(vec![0u8])
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO ChainOp
                (hash, op_type, action_hash, basis_hash, storage_center_loc,
                 validation_status, locally_validated, require_receipt,
                 when_received, when_integrated, serialized_size)
             VALUES (?, ?, ?, ?, ?, 1, 1, 0, ?, ?, 10)",
        )
        .bind(&op_hash)
        .bind(STORE_RECORD)
        .bind(&action_hash)
        .bind(vec![op_tag.wrapping_add(50); 36])
        .bind(loc as i64)
        .bind(timestamp)
        .bind(timestamp)
        .execute(pool)
        .await
        .unwrap();
        op_hash
    }

    /// `EXPLAIN QUERY PLAN` detail lines for `sql` with `n_binds` zero binds.
    async fn query_plan(pool: &Pool<Sqlite>, sql: &str, n_binds: usize) -> Vec<String> {
        let explain = format!("EXPLAIN QUERY PLAN {sql}");
        let mut q = sqlx::query_as::<_, (i64, i64, i64, String)>(sqlx::AssertSqlSafe(explain));
        for _ in 0..n_binds {
            q = q.bind(0_i64);
        }
        q.fetch_all(pool)
            .await
            .unwrap()
            .into_iter()
            .map(|(_, _, _, detail)| detail)
            .collect()
    }

    /// Kitsune2's DHT model is built from 512 non-wrapping sector arcs; every
    /// read it issues must be served by the loc index, never a `ChainOp` scan.
    /// Before this patch the arc predicate's bind-time `? <= ?` guard made the
    /// planner SCAN `ChainOp` for every one of ~10k startup reads.
    #[tokio::test]
    async fn sector_arc_reads_use_loc_index_not_chain_op_scan() {
        let db = test_open_db(dht_id()).await.unwrap();
        // A sector arc as kitsune2 builds them (SECTOR_SIZE = 2^23).
        let sector = super::ArcBounds {
            start: 7 << 23,
            end: (8 << 23) - 1,
        };
        for (name, sql, n_binds) in [
            ("time_slice", super::op_hashes_in_time_slice_sql(sector), 8),
            ("ids_since", super::op_ids_since_time_batch_sql(sector), 7),
            (
                "earliest",
                super::earliest_authored_timestamp_in_arc_sql(sector),
                4,
            ),
        ] {
            let plan = query_plan(db.pool(), &sql, n_binds).await;
            assert!(
                plan.iter()
                    .any(|d| d.contains("ChainOp USING")
                        && d.contains("elohim_ChainOp_loc_sync_idx")),
                "{name}: chain-op branch must search the loc index, plan: {plan:?}"
            );
            assert!(
                !plan.iter().any(|d| d.starts_with("SCAN ChainOp")),
                "{name}: chain-op branch must not scan the table, plan: {plan:?}"
            );
            assert!(
                plan.iter().any(
                    |d| d.contains("WarrantOp USING") && d.contains("elohim_WarrantOp_loc_idx")
                ),
                "{name}: warrant branch must search the loc index, plan: {plan:?}"
            );
        }
    }

    /// The Rust-side arc shape selects exactly the rows the single SQL shape
    /// used to: inside a non-wrapping arc, outside-the-gap for a wrapping one,
    /// everything for FULL — across all three K2 arc reads.
    #[tokio::test]
    async fn arc_shapes_select_the_same_rows() {
        let db = test_open_db(dht_id()).await.unwrap();
        let at_0 = seed_op_at(db.pool(), 1, 0, 4000).await;
        let at_10 = seed_op_at(db.pool(), 2, 10, 3000).await;
        let at_mid = seed_op_at(db.pool(), 3, 1 << 31, 2000).await;
        let at_top = seed_op_at(db.pool(), 4, u32::MAX - 5, 1000).await;

        let cases = [
            // non-wrapping, inclusive bounds
            ((10, 1 << 31), vec![&at_10, &at_mid], Some(2000)),
            // wrapping: [2^31+1, MAX] ∪ [0, 10]
            (
                ((1 << 31) + 1, 10),
                vec![&at_0, &at_10, &at_top],
                Some(1000),
            ),
            // full arc
            (
                (0, u32::MAX),
                vec![&at_0, &at_10, &at_mid, &at_top],
                Some(1000),
            ),
            // non-wrapping, empty of ops
            ((11, 12), vec![], None),
        ];

        for ((start, end), expected, expected_earliest) in cases {
            let mut expected: Vec<Vec<u8>> = expected.into_iter().cloned().collect();
            expected.sort();

            let mut slice: Vec<Vec<u8>> = db
                .as_ref()
                .op_hashes_in_time_slice(start, end, 0, i64::MAX)
                .await
                .unwrap()
                .into_iter()
                .map(|r| r.hash)
                .collect();
            slice.sort();
            assert_eq!(slice, expected, "time slice over arc ({start}, {end})");

            let mut since: Vec<Vec<u8>> = db
                .as_ref()
                .op_ids_since_time_batch(start, end, 0, 100)
                .await
                .unwrap()
                .into_iter()
                .map(|r| r.hash)
                .collect();
            since.sort();
            assert_eq!(since, expected, "ids since over arc ({start}, {end})");

            let earliest = db
                .as_ref()
                .earliest_authored_timestamp_in_arc(start, end)
                .await
                .unwrap();
            assert_eq!(
                earliest, expected_earliest,
                "earliest over arc ({start}, {end})"
            );
        }
    }

    /// The per-author publish reads run for every hosted agent on every
    /// publish loop. They must be driven from the author's own actions
    /// (`Action` by author, then `ChainOp` by action hash), never by scanning
    /// `ChainOp` and probing `Action` per row — the seconds-per-call shape the
    /// fleet CPU storm was made of. Same for sys-validation's per-op
    /// chain-fork check by `prev_hash`.
    #[tokio::test]
    async fn per_author_publish_and_fork_reads_are_index_driven() {
        let db = test_open_db(dht_id()).await.unwrap();
        for (name, sql, n_binds) in [
            (
                "get_ops_to_publish",
                super::super::chain_op_publish::GET_OPS_TO_PUBLISH_SQL,
                3,
            ),
            (
                "any_still_needing_publish",
                super::super::chain_op_publish::ANY_STILL_NEEDING_PUBLISH_SQL,
                2,
            ),
        ] {
            let plan = query_plan(db.pool(), sql, n_binds).await;
            assert!(
                plan.iter()
                    .any(|d| d.contains("SEARCH Action USING COVERING INDEX")
                        && d.contains("elohim_Action_author_publish_idx")),
                "{name}: must search Action by author, covered, plan: {plan:?}"
            );
            assert!(
                plan.iter()
                    .any(|d| d.contains("SEARCH ChainOp USING COVERING INDEX")
                        && d.contains("elohim_ChainOp_action_publish_idx")),
                "{name}: must reach ChainOp through the covering action-hash index, plan: {plan:?}"
            );
            assert!(
                !plan.iter().any(|d| d.starts_with("SCAN ChainOp")),
                "{name}: must not scan ChainOp, plan: {plan:?}"
            );
        }
        let plan = query_plan(
            db.pool(),
            "SELECT hash FROM Action WHERE prev_hash = ? AND hash != ?",
            2,
        )
        .await;
        assert!(
            plan.iter()
                .any(|d| d.contains("elohim_Action_prev_hash_idx")),
            "fork check must search Action by prev_hash, plan: {plan:?}"
        );
    }

    /// The reads behind zome `get` / `get_details` / `get_links` and the
    /// per-receipt count search an index, never scan their table.
    #[tokio::test]
    async fn get_path_and_receipt_reads_are_index_driven() {
        let db = test_open_db(dht_id()).await.unwrap();
        for (name, sql, n_binds, index) in [
            (
                "record/entry by basis",
                "SELECT a.hash FROM ChainOp c JOIN Action a ON c.action_hash = a.hash
                 WHERE c.basis_hash = ? AND c.op_type = ? AND c.validation_status = ?
                   AND c.when_integrated IS NOT NULL
                   AND NOT EXISTS (SELECT 1 FROM DeletedRecord d WHERE d.deletes_action_hash = a.hash)",
                3,
                "elohim_ChainOp_basis_idx",
            ),
            (
                "deletes of a record",
                "SELECT a.hash FROM DeletedRecord d JOIN Action a ON d.action_hash = a.hash
                 JOIN ChainOp c ON c.action_hash = a.hash AND c.op_type = ?
                 WHERE d.deletes_action_hash = ? AND c.locally_validated = 1",
                2,
                "elohim_DeletedRecord_deletes_action_idx",
            ),
            (
                "updates of a record",
                "SELECT a.hash FROM UpdatedRecord u JOIN Action a ON u.action_hash = a.hash
                 JOIN ChainOp c ON c.action_hash = a.hash AND c.op_type = ?
                 WHERE u.original_action_hash = ? AND c.locally_validated = 1",
                2,
                "elohim_UpdatedRecord_original_action_idx",
            ),
            (
                "updates of an entry",
                "SELECT action_hash FROM UpdatedRecord WHERE original_entry_hash = ?",
                1,
                "elohim_UpdatedRecord_original_entry_idx",
            ),
            (
                "deletes of an entry",
                "SELECT action_hash FROM DeletedRecord WHERE deletes_entry_hash = ?",
                1,
                "elohim_DeletedRecord_deletes_entry_idx",
            ),
            (
                "links on a base",
                "SELECT action_hash FROM Link WHERE base_hash = ?",
                1,
                "elohim_Link_base_idx",
            ),
            (
                "deletes of a link",
                "SELECT action_hash FROM DeletedLink WHERE create_link_hash = ?",
                1,
                "elohim_DeletedLink_create_idx",
            ),
            (
                "receipt count",
                "SELECT COUNT(*) FROM ValidationReceipt WHERE op_hash = ?",
                1,
                "elohim_ValidationReceipt_op_idx",
            ),
        ] {
            let plan = query_plan(db.pool(), sql, n_binds).await;
            assert!(
                plan.iter()
                    .any(|d| d.starts_with("SEARCH") && d.contains(index)),
                "{name}: must search {index}, plan: {plan:?}"
            );
            assert!(
                !plan.iter().any(|d| d.starts_with("SCAN")),
                "{name}: must not scan a table, plan: {plan:?}"
            );
        }
    }

    /// The indexes exist after open and re-ensuring them is a no-op, so a
    /// store that predates them gains them on its next open and an older
    /// binary (which knows no such migration) still opens the file.
    #[tokio::test]
    async fn sync_indexes_are_created_idempotently_outside_migrations() {
        let db = test_open_db(dht_id()).await.unwrap();
        super::ensure_sync_indexes(db.pool()).await.unwrap();

        let names: Vec<(String,)> = sqlx::query_as(
            "SELECT name FROM sqlite_master WHERE type = 'index' AND name LIKE 'elohim_%'
             ORDER BY name",
        )
        .fetch_all(db.pool())
        .await
        .unwrap();
        assert_eq!(
            names.into_iter().map(|(n,)| n).collect::<Vec<_>>(),
            vec![
                "elohim_Action_author_publish_idx",
                "elohim_Action_prev_hash_idx",
                "elohim_ChainOp_action_publish_idx",
                "elohim_ChainOp_basis_idx",
                "elohim_ChainOp_loc_sync_idx",
                "elohim_DeletedLink_create_idx",
                "elohim_DeletedRecord_deletes_action_idx",
                "elohim_DeletedRecord_deletes_entry_idx",
                "elohim_Link_base_idx",
                "elohim_UpdatedRecord_original_action_idx",
                "elohim_UpdatedRecord_original_entry_idx",
                "elohim_ValidationReceipt_op_idx",
                "elohim_WarrantOp_loc_idx",
            ]
        );

        let migrations: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM _sqlx_migrations")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(
            migrations.0, 1,
            "the indexes must not be recorded as a migration (rollback safety)"
        );
    }

    #[tokio::test]
    async fn time_slice_read_withholds_private_store_entry() {
        let (db, public, private, record) = seed_filter_fixture().await;

        let hashes: Vec<Vec<u8>> = db
            .as_ref()
            .op_hashes_in_time_slice(0, u32::MAX, 0, i64::MAX)
            .await
            .unwrap()
            .into_iter()
            .map(|r| r.hash)
            .collect();

        assert!(
            hashes.contains(&public),
            "public CreateEntry must be served"
        );
        assert!(
            hashes.contains(&record),
            "CreateRecord op with a private entry must be served (body withheld)"
        );
        assert!(
            !hashes.contains(&private),
            "private CreateEntry op must never be advertised in a time slice"
        );
    }

    #[tokio::test]
    async fn ids_since_read_withholds_private_store_entry() {
        let (db, public, private, record) = seed_filter_fixture().await;

        let hashes: Vec<Vec<u8>> = db
            .as_ref()
            .op_ids_since_time_batch(0, u32::MAX, 0, 100)
            .await
            .unwrap()
            .into_iter()
            .map(|r| r.hash)
            .collect();

        assert!(
            hashes.contains(&public),
            "public CreateEntry must be served"
        );
        assert!(hashes.contains(&record), "CreateRecord op must be served");
        assert!(
            !hashes.contains(&private),
            "private CreateEntry op must never be advertised in the since cursor"
        );
    }

    #[tokio::test]
    async fn for_wire_read_withholds_private_store_entry_even_when_requested() {
        let (db, public, private, record) = seed_filter_fixture().await;

        // Request all three by hash — the private CreateEntry must still be
        // withheld even though it was named explicitly.
        let requested = vec![public.clone(), private.clone(), record.clone()];
        let hashes: Vec<Vec<u8>> = db
            .as_ref()
            .get_chain_ops_for_wire(&requested)
            .await
            .unwrap()
            .into_iter()
            .map(|r| r.op_hash)
            .collect();

        assert!(
            hashes.contains(&public),
            "public CreateEntry must be served"
        );
        assert!(hashes.contains(&record), "CreateRecord op must be served");
        assert!(
            !hashes.contains(&private),
            "private CreateEntry op must never be served by hash"
        );
    }

    #[tokio::test]
    async fn earliest_timestamp_ignores_private_store_entry() {
        let (db, _public, _private, _record) = seed_filter_fixture().await;

        let earliest = db
            .as_ref()
            .earliest_authored_timestamp_in_arc(0, u32::MAX)
            .await
            .unwrap();

        // The private CreateEntry is authored at 1000 but is never servable, so
        // it must not set the advertised earliest-data boundary. The earliest
        // servable op is the public CreateEntry at 2000.
        assert_eq!(
            earliest,
            Some(2000),
            "earliest timestamp must reflect the earliest *servable* op, not a withheld private one"
        );
    }

    #[tokio::test]
    async fn ops_to_publish_read_withholds_private_store_entry() {
        let (db, public, private, record) = seed_filter_fixture().await;
        let author = AgentPubKey::from_raw_36(vec![AUTHOR; 36]);

        let hashes: Vec<Vec<u8>> = db
            .as_ref()
            .ops_to_publish_for_wire(&author)
            .await
            .unwrap()
            .into_iter()
            .map(|r| r.op_hash)
            .collect();

        assert!(
            hashes.contains(&public),
            "public CreateEntry must be published"
        );
        assert!(
            hashes.contains(&record),
            "CreateRecord op must be published"
        );
        assert!(
            !hashes.contains(&private),
            "private CreateEntry op must never be published"
        );
    }

    #[tokio::test]
    async fn integrated_dump_uses_exclusive_bounded_cursor_pages() {
        let (db, public, private, record) = seed_filter_fixture().await;
        let tied = seed_op(db.pool(), 4, STORE_RECORD, 0, 2000).await;

        let first_page = db
            .as_ref()
            .integrated_chain_ops_for_dump(None, Some(2))
            .await
            .unwrap();
        let first_hashes: Vec<_> = first_page
            .iter()
            .map(|row| row.wire.op_hash.clone())
            .collect();
        assert_eq!(first_hashes, vec![private, public]);

        let last = first_page.last().unwrap();
        let second_page = db
            .as_ref()
            .integrated_chain_ops_for_dump(
                Some((last.when_integrated, last.wire.op_hash.as_slice())),
                Some(10),
            )
            .await
            .unwrap();
        let second_hashes: Vec<_> = second_page
            .iter()
            .map(|row| row.wire.op_hash.clone())
            .collect();
        assert_eq!(second_hashes, vec![tied, record]);

        let empty_page = db
            .as_ref()
            .integrated_chain_ops_for_dump(
                Some((
                    second_page[1].when_integrated,
                    second_page[1].wire.op_hash.as_slice(),
                )),
                Some(10),
            )
            .await
            .unwrap();
        assert!(empty_page.is_empty());

        let unbounded = db
            .as_ref()
            .integrated_chain_ops_for_dump(None, None)
            .await
            .unwrap();
        assert_eq!(unbounded.len(), 4);
    }

    #[tokio::test]
    async fn dht_dump_pages_all_tables_in_received_order() {
        let db = test_open_db(dht_id()).await.unwrap();
        let integrated_chain = seed_op(db.pool(), 1, STORE_RECORD, 0, 100).await;
        let integrated_warrant = seed_warrant_op(db.pool(), 2, 100, DumpOpState::Integrated).await;
        let validation_chain = seed_limbo_chain_op(db.pool(), 3, 100, false).await;
        let integration_chain = seed_limbo_chain_op(db.pool(), 4, 100, true).await;
        let validation_warrant =
            seed_warrant_op(db.pool(), 5, 200, DumpOpState::ValidationLimbo).await;
        let integration_warrant =
            seed_warrant_op(db.pool(), 6, 200, DumpOpState::IntegrationLimbo).await;
        let cache_only = seed_op(db.pool(), 7, STORE_RECORD, 0, 50).await;
        sqlx::query("UPDATE ChainOp SET locally_validated = 0 WHERE hash = ?")
            .bind(&cache_only)
            .execute(db.pool())
            .await
            .unwrap();

        let expected = vec![
            (integrated_chain, DumpOpState::Integrated),
            (integrated_warrant, DumpOpState::Integrated),
            (validation_chain, DumpOpState::ValidationLimbo),
            (integration_chain.clone(), DumpOpState::Integrated),
            (validation_warrant, DumpOpState::ValidationLimbo),
            (integration_warrant, DumpOpState::IntegrationLimbo),
        ];
        let mut actual = Vec::new();
        let mut cursor = None;
        let mut promoted = false;
        loop {
            let page = db
                .as_ref()
                .dht_ops_page_for_dump(
                    cursor
                        .as_ref()
                        .map(|cursor: &DumpOpCursorRow| (cursor.when_received, &cursor.hash)),
                    Some(2),
                )
                .await
                .unwrap();
            assert!(page.rows.len() <= 2);
            actual.extend(
                page.rows
                    .iter()
                    .map(|row| (dump_row_hash(row).to_vec(), row.state)),
            );
            cursor = page.cursor;
            if cursor.is_none() {
                break;
            }
            if !promoted {
                promote_seeded_limbo_chain_op(&db, &integration_chain).await;
                promoted = true;
            }
        }
        assert_eq!(actual, expected);

        let unbounded = db.as_ref().dht_ops_page_for_dump(None, None).await.unwrap();
        assert_eq!(unbounded.rows.len(), expected.len());
        assert_eq!(
            unbounded.cursor.unwrap().hash,
            DhtOpHash::from_raw_36(expected.last().unwrap().0.clone())
        );
    }

    #[tokio::test]
    async fn op_timings_page_orders_and_pages_every_op_table() {
        let db = test_open_db(dht_id()).await.unwrap();
        // Two ops share when_received = 100 so the hash tie-break is exercised.
        let integrated_chain = seed_op(db.pool(), 1, STORE_RECORD, 0, 100).await;
        let integrated_warrant = seed_warrant_op(db.pool(), 2, 100, DumpOpState::Integrated).await;
        let limbo_chain = seed_limbo_chain_op(db.pool(), 3, 200, false).await;
        let limbo_warrant = seed_warrant_op(db.pool(), 4, 300, DumpOpState::ValidationLimbo).await;
        let cache_only = seed_op(db.pool(), 5, STORE_RECORD, 0, 400).await;
        sqlx::query("UPDATE ChainOp SET locally_validated = 0 WHERE hash = ?")
            .bind(&cache_only)
            .execute(db.pool())
            .await
            .unwrap();
        let abandoned = seed_limbo_chain_op(db.pool(), 6, 500, false).await;
        sqlx::query("UPDATE LimboChainOp SET abandoned_at = 550 WHERE hash = ?")
            .bind(&abandoned)
            .execute(db.pool())
            .await
            .unwrap();

        let expected = vec![
            integrated_chain,
            integrated_warrant,
            limbo_chain,
            limbo_warrant,
            cache_only.clone(),
            abandoned.clone(),
        ];

        // Page through two at a time.
        let mut actual: Vec<Vec<u8>> = Vec::new();
        let mut cursor: Option<DumpOpCursorRow> = None;
        loop {
            let page = db
                .as_ref()
                .op_timings_page(
                    cursor
                        .as_ref()
                        .map(|cursor| (cursor.when_received, &cursor.hash)),
                    Some(2),
                )
                .await
                .unwrap();
            assert!(page.rows.len() <= 2);
            actual.extend(page.rows.iter().map(|row| row.hash.clone()));
            cursor = page.cursor;
            if cursor.is_none() {
                break;
            }
        }
        assert_eq!(actual, expected);

        // Unbounded read reports the per-state fields.
        let unbounded = db.as_ref().op_timings_page(None, None).await.unwrap();
        let by_hash = |hash: &[u8]| -> OpTimingRow {
            unbounded
                .rows
                .iter()
                .find(|row| row.hash == hash)
                .expect("seeded op present")
                .clone()
        };

        let integrated = by_hash(&expected[0]);
        assert_eq!(integrated.when_received, 100);
        assert_eq!(integrated.when_integrated, Some(100));
        assert_eq!(integrated.abandoned_at, None);
        assert_eq!(integrated.validation_status, Some(1));
        assert_eq!(integrated.locally_validated, Some(1));

        let warrant = by_hash(&expected[1]);
        assert_eq!(warrant.when_integrated, Some(1_100));
        assert_eq!(warrant.validation_status, Some(1));
        assert_eq!(warrant.locally_validated, None);

        let limbo = by_hash(&expected[2]);
        assert_eq!(limbo.when_received, 200);
        assert_eq!(limbo.when_integrated, None);
        assert_eq!(limbo.abandoned_at, None);
        assert_eq!(limbo.validation_status, None);
        assert_eq!(limbo.locally_validated, None);

        let cached = by_hash(&cache_only);
        assert_eq!(cached.locally_validated, Some(0));
        // A cache insert stamps `when_integrated` with the received time, which
        // is exactly what `locally_validated = 0` explains.
        assert_eq!(cached.when_integrated, Some(400));

        let abandoned_row = by_hash(&abandoned);
        assert_eq!(abandoned_row.when_received, 500);
        assert_eq!(abandoned_row.when_integrated, None);
        assert_eq!(abandoned_row.abandoned_at, Some(550));
        assert_eq!(abandoned_row.validation_status, None);
    }

    /// One op hash can be present in an integrated table and its limbo
    /// counterpart at the same time: the cascade mirrors an op into `ChainOp`
    /// with `locally_validated = 0` while the same op sits in `LimboChainOp`,
    /// and it re-stages an already integrated warrant into `LimboWarrantOp`.
    /// Every such op must still be reported exactly once, by the row that
    /// reflects its real lifecycle position.
    #[tokio::test]
    async fn op_timings_page_reports_a_shadowed_op_once() {
        let db = test_open_db(dht_id()).await.unwrap();

        // Cache mirror of an op that is also awaiting validation in limbo.
        let cache_shadowed = seed_op(db.pool(), 1, STORE_RECORD, 0, 100).await;
        sqlx::query("UPDATE ChainOp SET locally_validated = 0 WHERE hash = ?")
            .bind(&cache_shadowed)
            .execute(db.pool())
            .await
            .unwrap();
        seed_limbo_chain_op(db.pool(), 1, 150, false).await;

        // Integrated chain op with a stale limbo row still present.
        let integrated_shadowed = seed_op(db.pool(), 2, STORE_RECORD, 0, 200).await;
        seed_limbo_chain_op(db.pool(), 2, 250, false).await;

        // Integrated warrant re-staged into limbo by a later cascade fetch.
        let warrant_shadowed = seed_warrant_op(db.pool(), 3, 300, DumpOpState::Integrated).await;
        sqlx::query(
            "INSERT INTO LimboWarrantOp
                (hash, storage_center_loc, sys_validation_status,
                 when_received, serialized_size)
             VALUES (?, 0, NULL, ?, 10)",
        )
        .bind(&warrant_shadowed)
        .bind(350_i64)
        .execute(db.pool())
        .await
        .unwrap();

        let page = db.as_ref().op_timings_page(None, None).await.unwrap();
        assert_eq!(page.rows.len(), 3, "each op hash must be reported once");
        let by_hash = |hash: &[u8]| -> OpTimingRow {
            page.rows
                .iter()
                .find(|row| row.hash == hash)
                .expect("seeded op present")
                .clone()
        };

        // The limbo row wins over a cache mirror: the op is not integrated yet.
        let cached = by_hash(&cache_shadowed);
        assert_eq!(cached.when_received, 150);
        assert_eq!(cached.when_integrated, None);
        assert_eq!(cached.locally_validated, None);

        // The integrated row wins over a stale limbo row.
        let integrated = by_hash(&integrated_shadowed);
        assert_eq!(integrated.when_received, 200);
        assert_eq!(integrated.when_integrated, Some(200));
        assert_eq!(integrated.locally_validated, Some(1));

        // The integrated warrant wins over its re-staged limbo row.
        let warrant = by_hash(&warrant_shadowed);
        assert_eq!(warrant.when_received, 300);
        assert_eq!(warrant.when_integrated, Some(1_300));
        assert_eq!(warrant.locally_validated, None);
    }
}
