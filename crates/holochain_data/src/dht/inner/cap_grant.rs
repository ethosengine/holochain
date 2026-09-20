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
///   Both subqueries are uncorrelated, so SQLite materialises each once for the
///   whole statement rather than once per candidate row (`EXPLAIN QUERY PLAN`
///   reports `LIST SUBQUERY`). `CROSS JOIN` (rather than `JOIN`) pins the join
///   order inside each: SQLite's default plan scans `Action` and probes the
///   index table, but every `UpdatedRecord`/`DeletedRecord` row has a foreign
///   key into `Action`, so the index table is never the larger of the two and
///   scanning it is always the cheaper order. Measured on a 15 768-grant /
///   60 000-action store: 91 ms with `JOIN`, 42 ms with `CROSS JOIN`. This is a
///   plan hint only — `CROSS JOIN` in SQLite constrains the loop order and
///   nothing else, so the result set is identical either way.
///   The inner `IS NOT NULL` guards are belt-and-braces against `NOT IN`'s NULL
///   semantics (a NULL in the subquery would make the predicate NULL and
///   silently deny *every* grant); the columns are declared `NOT NULL` on a
///   `STRICT` table, so the guard can never change the result.
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
///   a public-first (or public-fallback) read here.** An `INNER JOIN` on
///   `PrivateEntry` also drops a grant whose private entry is absent, matching
///   the old `entries.get(&entry_hash)` -> `None` -> `continue`.
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
/// corrupt the blob and leave the row perfectly readable.
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
    let rows: Vec<LiveCapGrantRow> = sqlx::query_as(
        "SELECT a.hash, a.author, a.seq, a.prev_hash, a.timestamp, a.action_type,
                a.action_data, a.signature, a.entry_hash, a.private_entry,
                a.record_validity,
                pe.blob AS blob
         FROM CapGrant cg
         JOIN Action a ON cg.action_hash = a.hash
         JOIN PrivateEntry pe ON pe.hash = a.entry_hash AND pe.author = ?2
         WHERE cg.cap_access = ?1
           AND a.author = ?2
           AND a.entry_hash IS NOT NULL
           AND pe.blob IS NOT NULL
           AND a.entry_hash NOT IN (
                 SELECT u.original_entry_hash
                 FROM UpdatedRecord u
                 CROSS JOIN Action ua ON u.action_hash = ua.hash
                 WHERE ua.author = ?2 AND u.original_entry_hash IS NOT NULL)
           AND a.entry_hash NOT IN (
                 SELECT d.deletes_entry_hash
                 FROM DeletedRecord d
                 CROSS JOIN Action da ON d.action_hash = da.hash
                 WHERE da.author = ?2 AND d.deletes_entry_hash IS NOT NULL)
         ORDER BY a.seq",
    )
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
        entries.push(super::entry::decode_entry_blob(&row.blob)?);
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
