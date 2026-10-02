//! Free-standing operations against the `CapGrant` table.

use crate::models::dht::{CapGrantRow, LiveCapGrantRow};
use holo_hash::{ActionHash, AgentPubKey};
use holochain_integrity_types::entry::Entry;
use sqlx::{Executor, Sqlite};

pub(crate) async fn insert_cap_grant<'e, E>(
    executor: E,
    action_hash: &ActionHash,
    cap_access: i64,
    tag: Option<&str>,
) -> sqlx::Result<()>
where
    E: Executor<'e, Database = Sqlite>,
{
    sqlx::query("INSERT INTO CapGrant (action_hash, cap_access, tag) VALUES (?, ?, ?)")
        .bind(action_hash.get_raw_36())
        .bind(cap_access)
        .bind(tag)
        .execute(executor)
        .await?;
    Ok(())
}

pub(crate) async fn get_cap_grants_by_access<'e, E>(
    executor: E,
    author: AgentPubKey,
    cap_access: i64,
) -> sqlx::Result<Vec<CapGrantRow>>
where
    E: Executor<'e, Database = Sqlite>,
{
    sqlx::query_as(
        "SELECT cg.action_hash, cg.cap_access, cg.tag
         FROM CapGrant cg
         JOIN Action ON cg.action_hash = Action.hash
         WHERE cg.cap_access = ? AND Action.author = ?
         ORDER BY Action.seq",
    )
    .bind(cap_access)
    .bind(author.get_raw_36())
    .fetch_all(executor)
    .await
}

/// The statement behind [`get_live_cap_grant_entries`]; `?1` is the access
/// class and `?2` the author.
///
/// `CROSS JOIN Action` pins `CapGrant` as the outer loop. With a plain `JOIN`
/// the planner serves `ORDER BY a.seq` from `elohim_Action_author_seq_idx`,
/// walking every action the author has written and probing `CapGrant` once
/// per action, so authorising a call costs the length of the chain. Pinned,
/// it reads the grants of the access class and probes `Action` by hash, then
/// sorts those few rows. `CROSS JOIN` in SQLite constrains the loop order and
/// nothing else, so the result set and its order are unchanged.
///
/// The revocation checks are correlated `NOT EXISTS` probes, one per candidate
/// grant, served by `elohim_UpdatedRecord_original_entry_idx` and
/// `elohim_DeletedRecord_deletes_entry_idx`. As uncorrelated `NOT IN` lists they
/// were materialised once per execution by walking every update and delete in
/// the store, for all authors, which was cheap only while the outer loop was the
/// author's whole chain. Both forms exclude exactly the same grants: the
/// compared columns are `NOT NULL`, so `NOT IN` has no NULL case to differ on.
const LIVE_CAP_GRANT_ENTRIES_SQL: &str = "
         SELECT a.hash, a.author, a.seq, a.prev_hash, a.timestamp, a.action_type,
                a.action_data, a.signature, a.entry_hash, a.private_entry,
                a.record_validity,
                pe.blob AS blob
         FROM CapGrant cg
         CROSS JOIN Action a ON cg.action_hash = a.hash
         LEFT JOIN PrivateEntry pe ON pe.hash = a.entry_hash AND pe.author = ?2
         WHERE cg.cap_access = ?1
           AND a.author = ?2
           AND (a.entry_hash IS NULL OR NOT EXISTS (
                 SELECT 1
                 FROM UpdatedRecord u
                 CROSS JOIN Action ua ON u.action_hash = ua.hash
                 WHERE u.original_entry_hash = a.entry_hash AND ua.author = ?2))
           AND (a.entry_hash IS NULL OR NOT EXISTS (
                 SELECT 1
                 FROM DeletedRecord d
                 CROSS JOIN Action da ON d.action_hash = da.hash
                 WHERE d.deletes_entry_hash = a.entry_hash AND da.author = ?2))
         ORDER BY a.seq";

/// The author's **live** capability-grant entries of one access class, in
/// source-chain order, resolved in a single query.
///
/// This is the set-based equivalent of the former three-step read
/// (`get_cap_grants_by_access` → per-row `get_action` → per-row update/delete
/// index probes → batched `get_entries_by_hashes`). It returns exactly the
/// same entries, in exactly the same order, at one query instead of
/// `3N + ceil(N/500)`.
///
/// Equivalence, clause by clause:
/// - `cg.cap_access = ? AND a.author = ? ORDER BY a.seq` is
///   [`get_cap_grants_by_access`]'s predicate and ordering, verbatim. Note
///   that `Action.seq` is NOT unique per author (the primary key is `hash`), so
///   a forked or restored chain can tie; neither this implementation nor the
///   one it replaces is stable under such a tie, and the tie-breaking order is
///   therefore unspecified in both.
/// - The `JOIN Action` replaces the per-row `get_action`. The `CapGrant ->
///   Action` foreign key makes the join total, and the old query already
///   joined `Action` to filter the author, so no row that used to survive is
///   dropped here.
/// - `a.entry_hash IS NOT NULL` replaces the old `entry_hash()` -> `None` ->
///   `continue`.
/// - The two `NOT IN` anti-joins replace `entry_updated_or_deleted_by_author`:
///   an entry is excluded when the author has an `Update` whose
///   `original_entry_hash` is this entry, or a `Delete` whose
///   `deletes_entry_hash` is this entry. The `ua.author` / `da.author`
///   predicates are load-bearing for security, not just for correctness: a
///   private grant's entry hash travels in the clear on its `Create` action, so
///   ANY agent can author a `Delete`/`Update` naming another agent's grant
///   entry hash and have it integrated. Only the author filter stops a foreign
///   revocation from taking effect.
///   Each is a correlated `NOT EXISTS` probe per candidate grant (see
///   [`LIVE_CAP_GRANT_ENTRIES_SQL`]); `CROSS JOIN` inside each pins the index
///   table as the outer loop so the probe goes through its entry-hash index and
///   then `Action` by primary key.
/// - The grant entry is read from `PrivateEntry` scoped to `?2` (this author)
///   and NOWHERE ELSE. This is a correctness invariant, not an optimisation,
///   and it is load-bearing: **`EntryType::CapGrant` is always
///   `EntryVisibility::Private`** (`holochain_integrity_types::action`,
///   `EntryType::visibility`), and the source-chain flush routes a private
///   entry ONLY to `PrivateEntry` (`source_chain::flush`, the
///   `private_entry_hashes` branch). A cap grant therefore has exactly one
///   legitimate home — this author's `PrivateEntry` — and a row in the public
///   `Entry` table at a grant entry hash cannot be a legitimate grant. Reading
///   the grant entry with any public-table precedence (the former
///   `COALESCE(e.blob, pe.blob)` / `get_entries_by_hashes(.., Some(author))`
///   union) is therefore incorrect: it can resolve a grant entry hash to a
///   public-table row that is not the author's real grant. **Do not reintroduce
///   a public-first (or public-fallback) read here.** A `LEFT JOIN` preserves
///   actions whose private entry is absent until after action decoding; only
///   then may that absence match the old `entries.get(&entry_hash)` skip.
/// - One output row per surviving `CapGrant` row, so repeated entries stay
///   repeated exactly as the old `candidate_hashes` loop kept them.
///
/// # Failing closed on a corrupt action
///
/// The old per-row `get_action` did NOT skip a corrupt action: its
/// `else { continue }` arm fires only when the row is MISSING, whereas a row
/// that fails to decode is an `sqlx::Error::Decode` propagated by `?` — so a
/// single corrupt action errored the whole authorisation read and every grant
/// was denied. That is the safe direction and it is preserved here: the action
/// columns are carried on each surviving row and decoded with the very same
/// [`row_to_signed_action_hashed`] the old path used (which validates both the
/// `ActionData` msgpack and the 64-byte signature length), and the decoded
/// `data.entry_hash()` is asserted equal to the `entry_hash` column the joins
/// were driven from. Trusting the column alone would have been a fail-open
/// inversion: `entry_hash` is a fixed-width value on the B-tree leaf while the
/// variable-length `action_data` spills to overflow pages, so one bad block can
/// corrupt the blob and leave the row perfectly readable. The same rule holds
/// when the private entry is missing or the indexed entry hash is NULL: neither
/// condition may filter a corrupt action before it is decoded.
///
/// One deliberate difference remains: a corrupt action belonging to an ALREADY
/// REVOKED grant no longer errors the read, because the anti-joins filter that
/// row out before anything is decoded. That is strictly more available and
/// cannot authorise anything that was not already authorised.
pub(crate) async fn get_live_cap_grant_entries<'e, E>(
    executor: E,
    author: AgentPubKey,
    cap_access: i64,
) -> sqlx::Result<Vec<Entry>>
where
    E: Executor<'e, Database = Sqlite>,
{
    let author_bytes = author.get_raw_36().to_vec();
    let rows: Vec<LiveCapGrantRow> = sqlx::query_as(LIVE_CAP_GRANT_ENTRIES_SQL)
        .bind(cap_access)
        .bind(author_bytes)
        .fetch_all(executor)
        .await?;

    let mut entries = Vec::with_capacity(rows.len());
    for row in rows {
        // The column the joins were driven from, kept before the action row is
        // consumed by the decoder.
        let column_entry_hash = row.action.entry_hash.clone();
        // Same decoder, same error shape, same checks as the `get_action` this
        // replaced: a corrupt action fails the read closed.
        let sah = super::action::row_to_signed_action_hashed(row.action)?;
        let decoded_entry_hash = sah.hashed.content.data.entry_hash();
        if decoded_entry_hash.map(|h| h.get_raw_36().to_vec()) != column_entry_hash {
            return Err(sqlx::Error::Decode(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "cap grant action entry_hash column disagrees with its decoded ActionData",
            ))));
        }
        if let Some(blob) = row.blob {
            entries.push(super::entry::decode_entry_blob(&blob)?);
        }
    }
    Ok(entries)
}

pub(crate) async fn get_cap_grants_by_tag<'e, E>(
    executor: E,
    author: AgentPubKey,
    tag: &str,
) -> sqlx::Result<Vec<CapGrantRow>>
where
    E: Executor<'e, Database = Sqlite>,
{
    sqlx::query_as(
        "SELECT cg.action_hash, cg.cap_access, cg.tag
         FROM CapGrant cg
         JOIN Action ON cg.action_hash = Action.hash
         WHERE cg.tag = ? AND Action.author = ?
         ORDER BY Action.seq",
    )
    .bind(tag)
    .bind(author.get_raw_36())
    .fetch_all(executor)
    .await
}

#[cfg(test)]
mod tests {
    use super::LIVE_CAP_GRANT_ENTRIES_SQL;
    use crate::kind::Dht;
    use crate::test_open_db;
    use holo_hash::DnaHash;
    use std::sync::Arc;

    /// Authorising a zome call must cost the author's grants, not the
    /// author's history.
    ///
    /// The lookup runs on every zome call signed by a key other than the
    /// author's. Left to itself the planner serves `ORDER BY a.seq` from
    /// `elohim_Action_author_seq_idx`: it walks every action the author ever
    /// wrote and probes `CapGrant` once per action. Measured on a household
    /// conductor at 19 081 actions and 9 grants: about 250 ms per access
    /// class, three classes per call, growing linearly with the chain.
    #[tokio::test]
    async fn live_cap_grant_lookup_is_driven_by_the_grant_table() {
        let db = test_open_db(Dht::new(Arc::new(DnaHash::from_raw_36(vec![0u8; 36]))))
            .await
            .unwrap();
        let explain = format!("EXPLAIN QUERY PLAN {LIVE_CAP_GRANT_ENTRIES_SQL}");
        let plan: Vec<String> =
            sqlx::query_as::<_, (i64, i64, i64, String)>(sqlx::AssertSqlSafe(explain))
                .bind(0_i64)
                .bind(vec![0u8; 36])
                .fetch_all(db.pool())
                .await
                .unwrap()
                .into_iter()
                .map(|(_, _, _, detail)| detail)
                .collect();
        let action_loop = plan
            .iter()
            .position(|d| d.starts_with("SEARCH a ") || d.starts_with("SCAN a"))
            .expect("the plan reads Action");
        let grant_loop = plan
            .iter()
            .position(|d| d.starts_with("SEARCH cg ") || d.starts_with("SCAN cg"))
            .expect("the plan reads CapGrant");
        assert!(
            grant_loop < action_loop,
            "CapGrant must be the outer loop, plan: {plan:?}"
        );
        assert!(
            plan[action_loop].contains("PRIMARY KEY"),
            "Action must be probed by hash, not walked by author, plan: {plan:?}"
        );
        assert!(
            plan[grant_loop].contains("elohim_CapGrant_access_idx"),
            "CapGrant must be read through its access-class index, plan: {plan:?}"
        );
        // The revocation checks must probe by entry hash per candidate, never
        // walk every update or delete in the store.
        assert!(
            !plan
                .iter()
                .any(|d| d.starts_with("SCAN u") || d.starts_with("SCAN d")),
            "revocation checks must not scan UpdatedRecord/DeletedRecord, plan: {plan:?}"
        );
        for (alias, index) in [
            ("u", "elohim_UpdatedRecord_original_entry_idx"),
            ("d", "elohim_DeletedRecord_deletes_entry_idx"),
        ] {
            assert!(
                plan.iter()
                    .any(|d| d.starts_with(&format!("SEARCH {alias} ")) && d.contains(index)),
                "{alias} must be probed through {index}, plan: {plan:?}"
            );
        }
    }
}
