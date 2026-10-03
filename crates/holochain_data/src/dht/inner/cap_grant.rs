//! Free-standing operations against the `CapGrant` table.

use crate::models::dht::{CapGrantRow, LiveCapGrantRow};
use holo_hash::{ActionHash, AgentPubKey};
use holochain_integrity_types::capability::{CapAccess, CapSecret};
use holochain_integrity_types::entry::Entry;
use sqlx::{Executor, Sqlite};

/// The derivation version of [`cap_grant_secret_key`], carried as the first
/// byte of every key.
///
/// Bump it whenever the preimage layout or the hash changes. A stored key
/// whose first byte is not this value is then treated exactly like a missing
/// key — read on the slow path, and re-keyed by the backfill — instead of
/// silently hiding its grant from every call.
pub const CAP_GRANT_SECRET_KEY_VERSION: u8 = 1;

// The "newer than current" bound is `VERSION + 1`.
const _: () = assert!(CAP_GRANT_SECRET_KEY_VERSION < u8::MAX);

/// Width of the `CapGrant.elohim_secret_key` lookup key, in bytes: the version
/// byte followed by a 32-byte digest.
pub const CAP_GRANT_SECRET_KEY_BYTES: usize = 33;

/// The `CapGrant.elohim_secret_key` lookup key for a grant of `author` carrying
/// `secret`: [`CAP_GRANT_SECRET_KEY_VERSION`] followed by blake2b-256 over
/// `author (36 raw bytes) || secret (64 bytes)`.
///
/// The plaintext secret is never written to the index. Binding the author into
/// the digest means two agents who happen to grant the same secret do not share
/// a key. Both inputs are fixed-width, so the concatenation is unambiguous.
///
/// The key only NARROWS which grant rows an authorisation read fetches. It is
/// never the authorisation decision: the fetched grant entry's real secret is
/// still compared by `CapGrant::is_valid`.
pub fn cap_grant_secret_key(
    author: &AgentPubKey,
    secret: &CapSecret,
) -> [u8; CAP_GRANT_SECRET_KEY_BYTES] {
    let mut preimage = Vec::with_capacity(36 + secret.as_ref().len());
    preimage.extend_from_slice(author.get_raw_36());
    preimage.extend_from_slice(secret.as_ref());
    let digest = holo_hash::blake2b_256(&preimage);
    let mut key = [0u8; CAP_GRANT_SECRET_KEY_BYTES];
    key[0] = CAP_GRANT_SECRET_KEY_VERSION;
    key[1..].copy_from_slice(&digest);
    key
}

/// The smallest key of the current derivation version: every stored key that
/// sorts below it is of an older version (or truncated).
fn current_version_floor() -> Vec<u8> {
    let mut floor = vec![0u8; CAP_GRANT_SECRET_KEY_BYTES];
    floor[0] = CAP_GRANT_SECRET_KEY_VERSION;
    floor
}

/// The smallest key of any NEWER derivation version: every stored key that
/// sorts at or above it was written by a binary with a later derivation.
fn newer_version_floor() -> Vec<u8> {
    vec![CAP_GRANT_SECRET_KEY_VERSION + 1]
}

// ELOHIM PATCH (per-call grant walk): the 0.7 `CapGrant` table is
// `(action_hash, cap_access, tag)` — it knows neither whose grant a row is nor
// which secret it carries, so authorising a secret-bearing zome call had to
// read every live grant of the access class for EVERY agent in the DNA's store
// and decode each one, only for the caller to keep the single grant whose
// secret matched. `elohim_author` and `elohim_secret_key` (see
// [`cap_grant_secret_key`]) let the read seek straight to the candidate rows.
//
// Applied idempotently at open rather than as a sqlx migration, for the same
// rollback-safety reason as `sync_queries::DHT_SYNC_INDEXES`: a migration an
// older binary does not know makes it refuse to open the database. Two
// nullable columns and one index are invisible to an older binary — its
// `INSERT INTO CapGrant (action_hash, cap_access, tag)` leaves both columns
// NULL, and a NULL column is a row the lookup still reads on today's path, so
// rows written by a rolled-back binary stay correct and are keyed by the next
// backfill.
//
// The columns carry the same `elohim_` prefix as the index, and for the same
// reason: an upstream migration that later adds an `author` column to
// `CapGrant` must not collide with one already present on every deployed
// database.
/// Columns added to `CapGrant` after migrations, as `(name, declared type)`.
pub(crate) const CAP_GRANT_LOOKUP_COLUMNS: &[(&str, &str)] =
    &[("elohim_author", "BLOB"), ("elohim_secret_key", "BLOB")];

/// The index that drives the live capability-grant lookup.
pub(crate) const CAP_GRANT_LOOKUP_INDEX: &str =
    "CREATE INDEX IF NOT EXISTS elohim_CapGrant_author_access_secret_idx
        ON CapGrant (elohim_author, cap_access, elohim_secret_key)";

/// Builds a statement around the predicate "this `CapGrant` row has no key of
/// the current derivation", placed between the two fragments given. `?1` is
/// the floor of the current key version and `?2` the floor of every newer one.
///
/// A row is un-keyed when its key is NULL, of an older version (or truncated:
/// it sorts below the current version's floor), of a newer version, or not the
/// width of a key. The last case is not seekable, so the authorisation read
/// does not cover it (see `LIVE_CAP_GRANT_ENTRIES_BY_SECRET_SQL`); the backfill
/// does, and re-keys it.
macro_rules! cap_grant_unkeyed_sql {
    ($before:literal, $after:literal) => {
        concat!(
            $before,
            "(elohim_secret_key IS NULL
               OR elohim_secret_key < ?1
               OR elohim_secret_key >= ?2
               OR length(elohim_secret_key) <> 33)",
            $after
        )
    };
}

/// Ensure the `CapGrant` lookup columns and their index exist.
///
/// Idempotent: a column that is already present is left alone (SQLite has no
/// `ADD COLUMN IF NOT EXISTS`, so presence is read from the table definition
/// first, and a concurrent opener winning the race is tolerated). `ADD COLUMN`
/// of a nullable column rewrites no rows. A fresh database and one that
/// predates the columns end in the same shape.
pub(crate) async fn ensure_cap_grant_lookup_schema(pool: &sqlx::Pool<Sqlite>) -> sqlx::Result<()> {
    for (name, ty) in CAP_GRANT_LOOKUP_COLUMNS {
        let present: Option<i64> =
            sqlx::query_scalar("SELECT 1 FROM pragma_table_info('CapGrant') WHERE name = ?")
                .bind(*name)
                .fetch_optional(pool)
                .await?;
        if present.is_some() {
            continue;
        }
        let stmt = format!("ALTER TABLE CapGrant ADD COLUMN {name} {ty}");
        match sqlx::query(sqlx::AssertSqlSafe(stmt)).execute(pool).await {
            Ok(_) => {}
            // Another handle on the same file added it between the probe and
            // the ALTER.
            Err(sqlx::Error::Database(e)) if e.message().contains("duplicate column name") => {}
            Err(e) => return Err(e),
        }
    }
    sqlx::query(CAP_GRANT_LOOKUP_INDEX).execute(pool).await?;
    Ok(())
}

/// Insert the `CapGrant` index row for a grant action of `author`.
///
/// `secret` is the grant's secret (`Transferable` / `Assigned`); `None` for an
/// `Unrestricted` grant, whose `elohim_secret_key` stays NULL.
pub(crate) async fn insert_cap_grant<'e, E>(
    executor: E,
    action_hash: &ActionHash,
    author: &AgentPubKey,
    cap_access: i64,
    secret: Option<&CapSecret>,
    tag: Option<&str>,
) -> sqlx::Result<()>
where
    E: Executor<'e, Database = Sqlite>,
{
    let secret_key = secret.map(|s| cap_grant_secret_key(author, s).to_vec());
    sqlx::query(
        "INSERT INTO CapGrant (action_hash, cap_access, tag, elohim_author, elohim_secret_key)
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(action_hash.get_raw_36())
    .bind(cap_access)
    .bind(tag)
    .bind(author.get_raw_36())
    .bind(secret_key)
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

/// Builds a live-grant statement around a candidate sub-select.
///
/// `?1` is the access class, `?2` the author; the candidate sub-select yields
/// the `action_hash` of each `CapGrant` row to consider and may use `?3`.
///
/// `CROSS JOIN Action` pins the candidate rows as the outer loop. With a plain
/// `JOIN` the planner serves `ORDER BY a.seq` from
/// `elohim_Action_author_seq_idx`, walking every action the author has written
/// and probing `CapGrant` once per action, so authorising a call costs the
/// length of the chain. Pinned, it reads the candidate grants and probes
/// `Action` by hash, then sorts those few rows. `CROSS JOIN` in SQLite
/// constrains the loop order and nothing else, so the result set and its order
/// are unchanged.
///
/// The revocation checks are correlated `NOT EXISTS` probes, one per candidate
/// grant, served by `elohim_UpdatedRecord_original_entry_idx` and
/// `elohim_DeletedRecord_deletes_entry_idx`. As uncorrelated `NOT IN` lists they
/// were materialised once per execution by walking every update and delete in
/// the store, for all authors, which was cheap only while the outer loop was the
/// author's whole chain. Both forms exclude exactly the same grants: the
/// compared columns are `NOT NULL`, so `NOT IN` has no NULL case to differ on.
macro_rules! live_cap_grant_sql {
    ($candidates:literal) => {
        concat!(
            "
         SELECT a.hash, a.author, a.seq, a.prev_hash, a.timestamp, a.action_type,
                a.action_data, a.signature, a.entry_hash, a.private_entry,
                a.record_validity,
                pe.blob AS blob
         FROM (",
            $candidates,
            ") cg
         CROSS JOIN Action a ON cg.action_hash = a.hash
         LEFT JOIN PrivateEntry pe ON pe.hash = a.entry_hash AND pe.author = ?2
         WHERE a.author = ?2
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
         ORDER BY a.seq"
        )
    };
}

/// The secret-keyed live-grant statement: `?1` access class, `?2` author, `?3`
/// the [`cap_grant_secret_key`] of `(author, secret)`, `?4` the floor of the
/// current key version, `?5` the floor of every newer version.
///
/// The candidates are the author's rows of the class keyed to `?3`, plus every
/// row of the class that cannot be ruled out by its key:
///
/// 1. `elohim_author = ?2 AND elohim_secret_key = ?3` — keyed to this secret;
/// 2. `elohim_author = ?2 AND elohim_secret_key IS NULL` — not keyed yet;
/// 3. `elohim_author = ?2 AND elohim_secret_key < ?4` — keyed by an OLDER
///    derivation (anything sorting below the current version's smallest key);
/// 4. `elohim_author = ?2 AND elohim_secret_key >= ?5` — keyed by a NEWER
///    derivation (a binary that was rolled back);
/// 5. `elohim_author IS NULL` — the row's author has not been filled in, so
///    nothing about it is trusted and it is read whatever its key says.
///
/// They are separate `UNION ALL` arms because that is the only shape the
/// planner serves from `elohim_CapGrant_author_access_secret_idx`: each arm is
/// one equality, `IS NULL` or range seek, whereas an `OR` form falls back to
/// reading the whole access class through `elohim_CapGrant_access_idx`. The
/// arms are disjoint, so no row is produced twice.
///
/// Arms 2–5 are what make CORRECTNESS INDEPENDENT OF THE BACKFILL AND OF THE
/// DERIVATION VERSION: a row whose columns have not been filled in (it predates
/// them, or was written by an older binary after a rollback), or whose key was
/// derived differently, is still read and decided exactly as before. Once the
/// backfill has run they match nothing and the statement reads only the rows
/// keyed to this secret.
///
/// One state is not covered: a key that carries the current version byte but
/// is simply WRONG. Either it is the right width and was derived for a
/// different secret, or it is the wrong width (truncated or over-long). Such a
/// row is hidden from its real secret — a denial of that one grant, never an
/// authorisation. The backfill re-keys the wrong-width case (it can see the
/// width); only a derivation-version bump re-keys a well-formed wrong key.
const LIVE_CAP_GRANT_ENTRIES_BY_SECRET_SQL: &str = live_cap_grant_sql!(
    "
            SELECT action_hash FROM CapGrant
             WHERE elohim_author = ?2 AND cap_access = ?1 AND elohim_secret_key = ?3
            UNION ALL
            SELECT action_hash FROM CapGrant
             WHERE elohim_author = ?2 AND cap_access = ?1 AND elohim_secret_key IS NULL
            UNION ALL
            SELECT action_hash FROM CapGrant
             WHERE elohim_author = ?2 AND cap_access = ?1 AND elohim_secret_key < ?4
            UNION ALL
            SELECT action_hash FROM CapGrant
             WHERE elohim_author = ?2 AND cap_access = ?1 AND elohim_secret_key >= ?5
            UNION ALL
            SELECT action_hash FROM CapGrant
             WHERE elohim_author IS NULL AND cap_access = ?1"
);

/// The whole-class live-grant statement: `?1` access class, `?2` author.
///
/// Used for `Unrestricted` grants, which carry no secret to key on. Scoped to
/// the author through the same index; the `elohim_author IS NULL` arm keeps
/// rows that have not been backfilled.
///
/// Its cost is the number of the AUTHOR'S live grants of the class (plus, until
/// the author backfill reaches them, every agent's rows with no author). It no
/// longer grows with other agents' grants, but it is not bounded: an author
/// holding `N` unrestricted grants pays for `N` on every call that presents no
/// secret.
const LIVE_CAP_GRANT_ENTRIES_BY_CLASS_SQL: &str = live_cap_grant_sql!(
    "
            SELECT action_hash FROM CapGrant
             WHERE elohim_author = ?2 AND cap_access = ?1
            UNION ALL
            SELECT action_hash FROM CapGrant
             WHERE elohim_author IS NULL AND cap_access = ?1"
);

/// The pre-keyed statement, kept verbatim as a differential-test oracle: every
/// live grant of the access class for the author, driven from
/// `elohim_CapGrant_access_idx` and ignoring the lookup columns entirely.
#[cfg(test)]
const LIVE_CAP_GRANT_ENTRIES_REFERENCE_SQL: &str =
    live_cap_grant_sql!("SELECT action_hash FROM CapGrant WHERE cap_access = ?1");

/// Decode the rows of a live-grant statement into grant entries.
///
/// Every row is decoded with the same decoder the per-row `get_action` used and
/// its decoded `entry_hash` is asserted equal to the column the joins were
/// driven from; any failure fails the whole read.
fn decode_live_cap_grant_rows(rows: Vec<LiveCapGrantRow>) -> sqlx::Result<Vec<Entry>> {
    let mut entries = Vec::with_capacity(rows.len());
    for row in rows {
        if let Some(entry) = decode_live_cap_grant_row(row)? {
            entries.push(entry);
        }
    }
    Ok(entries)
}

/// Decode one live-grant row: the action first (always), then the entry.
///
/// `Ok(None)` is the legitimate skip for an absent private entry, reached only
/// after the action has decoded cleanly.
fn decode_live_cap_grant_row(row: LiveCapGrantRow) -> sqlx::Result<Option<Entry>> {
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
    row.blob
        .map(|blob| super::entry::decode_entry_blob(&blob))
        .transpose()
}

/// The author's **live** capability-grant entries of one access class, in
/// source-chain order, resolved in a single query.
///
/// With `secret = Some(_)` only the grants that can carry that secret are read:
/// rows keyed to it (see [`cap_grant_secret_key`]) plus any row not keyed by
/// the current derivation. With `secret = None` every live grant of the class
/// is read. Either way the result is every matching live grant, never the
/// first: two grants may share a secret with different function sets or
/// assignees, and the caller's `CapGrant::is_valid` chooses among them.
///
/// Residual cost: the read is proportional to the number of the author's live
/// grants that SHARE the presented secret (each is fetched and decoded), plus
/// the author's rows not yet keyed. `N` grants minted with one secret cost `N`
/// rows per call; nothing here bounds `N`.
///
/// **The key is a filter, never the decision.** `elohim_secret_key` only
/// selects which rows are fetched; the grant entry's real secret is read from
/// the author's `PrivateEntry` and compared by the caller. A wrong
/// `elohim_author` / `elohim_secret_key` on a row can therefore only hide that
/// grant (deny), never authorise a call.
///
/// This is the set-based equivalent of the former three-step read
/// (`get_cap_grants_by_access` → per-row `get_action` → per-row update/delete
/// index probes → batched `get_entries_by_hashes`), narrowed to the grants a
/// secret can match. For the rows it reads it returns exactly the same entries,
/// in exactly the same order, at one query instead of `3N + ceil(N/500)`.
///
/// Equivalence, clause by clause:
/// - `cap_access = ? AND a.author = ? ORDER BY a.seq` is
///   [`get_cap_grants_by_access`]'s predicate and ordering, verbatim. The
///   `CapGrant.elohim_author` column narrows the rows read, but the `Action.author`
///   join predicate is still what decides whose grant a row is. Note
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
///   `live_cap_grant_sql`); `CROSS JOIN` inside each pins the index
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
/// # Failing closed on a corrupt grant
///
/// The old per-row `get_action` did NOT skip a corrupt action: its
/// `else { continue }` arm fires only when the row is MISSING, whereas a row
/// that fails to decode is an `sqlx::Error::Decode` propagated by `?`. That is
/// the safe direction and it is preserved for every row this read fetches: the
/// action columns are carried on each surviving row and decoded with the very
/// same `row_to_signed_action_hashed` the old path used (which validates both
/// the `ActionData` msgpack and the 64-byte signature length), and the decoded
/// `data.entry_hash()` is asserted equal to the `entry_hash` column the joins
/// were driven from. Trusting the column alone would have been a fail-open
/// inversion: `entry_hash` is a fixed-width value on the B-tree leaf while the
/// variable-length `action_data` spills to overflow pages, so one bad block can
/// corrupt the blob and leave the row perfectly readable. The same rule holds
/// when the private entry is missing or the indexed entry hash is NULL: neither
/// condition may filter a corrupt action before it is decoded.
///
/// Two deliberate differences from the load-every-grant read remain. Both are
/// strictly more available and neither can authorise anything that was not
/// already authorised:
///
/// - A corrupt action belonging to an ALREADY REVOKED grant does not error the
///   read, because the anti-joins filter that row out before anything is
///   decoded.
/// - **A corrupt UNRELATED live grant no longer denies a secret-bearing call.**
///   The load-every-grant read fetched and decoded every live grant of the
///   class, so ONE live secret-bearing grant that failed to decode failed the
///   whole read and denied every secret-bearing call for the author. Three
///   kinds of corruption did that:
///
///   1. an action that does not decode (`action_data` or `signature`);
///   2. a `PrivateEntry` blob that does not decode;
///   3. an `entry_hash` column that disagrees with the decoded action
///      (including a NULL column).
///
///   The keyed read fetches only the rows keyed to the presented secret, plus
///   the rows not keyed by the current derivation. So for each of the three:
///
///   - on a grant keyed to a DIFFERENT secret, it is never fetched, never
///     decoded, and no longer denies the call — this is the change;
///   - on a grant keyed to the PRESENTED secret, the read still fails closed;
///   - on a row that is NOT KEYED (NULL, or an older / newer derivation), the
///     read still fails closed for every secret, exactly as before.
///
///   The relaxation is therefore HISTORY-DEPENDENT. The backfill can only key a
///   row it can decode, so a grant that was already corrupt when the backfill
///   reached it stays un-keyed and keeps denying every secret-bearing call for
///   its author, as it does today; only a grant that was keyed while healthy
///   and corrupted afterwards stops denying unrelated calls. Rows the backfill
///   could not key are counted in its report (`left_unkeyed`) and in the
///   `hc.db.cap_grant.unkeyed` gauge, so a store carrying one is visible.
pub(crate) async fn get_live_cap_grant_entries<'e, E>(
    executor: E,
    author: AgentPubKey,
    cap_access: i64,
    secret: Option<&CapSecret>,
) -> sqlx::Result<Vec<Entry>>
where
    E: Executor<'e, Database = Sqlite>,
{
    let rows = fetch_live_cap_grant_rows(executor, &author, cap_access, secret).await?;
    decode_live_cap_grant_rows(rows)
}

/// The single statement behind [`get_live_cap_grant_entries`].
async fn fetch_live_cap_grant_rows<'e, E>(
    executor: E,
    author: &AgentPubKey,
    cap_access: i64,
    secret: Option<&CapSecret>,
) -> sqlx::Result<Vec<LiveCapGrantRow>>
where
    E: Executor<'e, Database = Sqlite>,
{
    let author_bytes = author.get_raw_36().to_vec();
    match secret {
        Some(secret) => {
            sqlx::query_as(LIVE_CAP_GRANT_ENTRIES_BY_SECRET_SQL)
                .bind(cap_access)
                .bind(author_bytes)
                .bind(cap_grant_secret_key(author, secret).to_vec())
                .bind(current_version_floor())
                .bind(newer_version_floor())
                .fetch_all(executor)
                .await
        }
        None => {
            sqlx::query_as(LIVE_CAP_GRANT_ENTRIES_BY_CLASS_SQL)
                .bind(cap_access)
                .bind(author_bytes)
                .fetch_all(executor)
                .await
        }
    }
}

/// The pre-keyed read, kept as a differential-test oracle: every live grant of
/// the class for the author, with the lookup columns ignored.
#[cfg(test)]
pub(crate) async fn get_live_cap_grant_entries_reference<'e, E>(
    executor: E,
    author: AgentPubKey,
    cap_access: i64,
) -> sqlx::Result<Vec<Entry>>
where
    E: Executor<'e, Database = Sqlite>,
{
    let rows: Vec<LiveCapGrantRow> = sqlx::query_as(LIVE_CAP_GRANT_ENTRIES_REFERENCE_SQL)
        .bind(cap_access)
        .bind(author.get_raw_36().to_vec())
        .fetch_all(executor)
        .await?;
    decode_live_cap_grant_rows(rows)
}

// ---------------------------------------------------------------------------
// Backfill of the lookup columns on rows that predate them.
// ---------------------------------------------------------------------------

/// Fill `CapGrant.elohim_author` from `Action` for up to `limit` rows that lack
/// it.
///
/// One statement, bounded by `limit` so the write lock is held briefly. Returns
/// the number of rows filled; `0` means nothing fillable is left. The `EXISTS`
/// guard keeps a row that cannot be filled — its action is absent, or its
/// author is not the 36 bytes of an agent key — from being re-selected forever;
/// such a row keeps a NULL author and stays on the read-everything path.
pub(crate) async fn backfill_cap_grant_authors<'e, E>(executor: E, limit: u32) -> sqlx::Result<u64>
where
    E: Executor<'e, Database = Sqlite>,
{
    let done = sqlx::query(
        "UPDATE CapGrant
            SET elohim_author =
                (SELECT a.author FROM Action a WHERE a.hash = CapGrant.action_hash)
          WHERE action_hash IN (
                SELECT cg.action_hash FROM CapGrant cg
                 WHERE cg.elohim_author IS NULL
                   AND EXISTS (SELECT 1 FROM Action a
                                WHERE a.hash = cg.action_hash AND length(a.author) = 36)
                 LIMIT ?)",
    )
    .bind(i64::from(limit))
    .execute(executor)
    .await?;
    Ok(done.rows_affected())
}

/// Secret-bearing `CapGrant` rows that have no key of the current derivation.
///
/// This is what the `hc.db.cap_grant.unkeyed` gauge reports. After a completed
/// backfill pass it is the number of rows that COULD NOT be keyed — each still
/// read, and decoded, by every secret-bearing authorisation of its author.
pub(crate) async fn count_cap_grants_unkeyed<'e, E>(executor: E) -> sqlx::Result<u64>
where
    E: Executor<'e, Database = Sqlite>,
{
    let count: i64 = sqlx::query_scalar(cap_grant_unkeyed_sql!(
        "SELECT COUNT(*) FROM CapGrant WHERE cap_access IN (1, 2) AND ",
        ""
    ))
    .bind(current_version_floor())
    .bind(newer_version_floor())
    .fetch_one(executor)
    .await?;
    Ok(count.max(0) as u64)
}

/// The statement behind [`get_cap_grants_missing_secret_key`]: `?1` / `?2` the
/// key-version floors (see `cap_grant_unkeyed_sql`), `?3` the cursor (an
/// `action_hash`, or the empty blob for "from the start"), `?4` the limit.
///
/// The unary `+` on `cap_access` takes that term away from the planner, which
/// leaves the cursor as the only indexable constraint: a batch is then a
/// primary-key range seek to the cursor followed by a walk that stops at the
/// limit. Left to choose, the planner reads the two secret-bearing classes
/// through `elohim_CapGrant_access_idx` and sorts every remaining row to honour
/// `ORDER BY action_hash` — the rest of the table, every batch. (`NOT INDEXED`
/// does not prevent that on this `WITHOUT ROWID` table.)
const CAP_GRANTS_MISSING_SECRET_KEY_SQL: &str = cap_grant_unkeyed_sql!(
    "
         SELECT a.hash, a.author, a.seq, a.prev_hash, a.timestamp, a.action_type,
                a.action_data, a.signature, a.entry_hash, a.private_entry,
                a.record_validity,
                pe.blob AS blob
           FROM (SELECT action_hash FROM CapGrant
                  WHERE +cap_access IN (1, 2)
                    AND action_hash > ?3
                    AND ",
    "
                  ORDER BY action_hash
                  LIMIT ?4) cg
           CROSS JOIN Action a ON a.hash = cg.action_hash
           LEFT JOIN PrivateEntry pe ON pe.hash = a.entry_hash AND pe.author = a.author"
);

/// Up to `limit` secret-bearing grant rows that have no key of the current
/// derivation, after `cursor` in `action_hash` order, each with its action
/// columns and the grant entry blob read from the ROW'S OWN author's
/// `PrivateEntry`.
pub(crate) async fn get_cap_grants_missing_secret_key<'e, E>(
    executor: E,
    cursor: Option<&[u8]>,
    limit: u32,
) -> sqlx::Result<Vec<LiveCapGrantRow>>
where
    E: Executor<'e, Database = Sqlite>,
{
    sqlx::query_as(CAP_GRANTS_MISSING_SECRET_KEY_SQL)
        .bind(current_version_floor())
        .bind(newer_version_floor())
        // Every action hash sorts after the empty blob, so no cursor means "from
        // the start" and the predicate stays a primary-key range seek.
        .bind(cursor.unwrap_or(&[]))
        .bind(i64::from(limit))
        .fetch_all(executor)
        .await
}

/// The key to store for a row returned by
/// [`get_cap_grants_missing_secret_key`], or `None` to leave the row un-keyed.
///
/// A row is left un-keyed — and therefore on the read-every-un-keyed-row path,
/// which is slow but correct — whenever its key cannot be derived with
/// certainty: a hash or key column is not 36 bytes, the action does not decode,
/// its decoded entry hash disagrees with the column the entry was joined on,
/// the private entry is missing or does not decode, or the entry is not a
/// secret-bearing grant.
///
/// The widths are checked here, before any hash type is built from the bytes:
/// `HoloHash::from_raw_36` only `debug_assert`s its length, so a malformed
/// column would panic this task in a debug build and, in a release build, have
/// a key derived over bytes that are not an agent key.
pub(crate) fn derive_cap_grant_secret_key(
    row: LiveCapGrantRow,
) -> Option<[u8; CAP_GRANT_SECRET_KEY_BYTES]> {
    const RAW_36: usize = 36;
    let action = &row.action;
    let well_formed = action.hash.len() == RAW_36
        && action.author.len() == RAW_36
        && action.prev_hash.as_ref().is_none_or(|h| h.len() == RAW_36)
        && action.entry_hash.as_ref().is_none_or(|h| h.len() == RAW_36);
    if !well_formed {
        return None;
    }
    let author = AgentPubKey::from_raw_36(row.action.author.clone());
    let entry = decode_live_cap_grant_row(row).ok()??;
    let secret = match entry {
        Entry::CapGrant(grant) => match grant.access {
            CapAccess::Transferable { secret } | CapAccess::Assigned { secret, .. } => secret,
            CapAccess::Unrestricted => return None,
        },
        _ => return None,
    };
    Some(cap_grant_secret_key(&author, &secret))
}

/// Store `secret_key` on a row that still has no key of the current derivation.
/// A row keyed in the meantime is left untouched.
pub(crate) async fn set_cap_grant_secret_key<'e, E>(
    executor: E,
    action_hash: &[u8],
    secret_key: &[u8; CAP_GRANT_SECRET_KEY_BYTES],
) -> sqlx::Result<u64>
where
    E: Executor<'e, Database = Sqlite>,
{
    let done = sqlx::query(cap_grant_unkeyed_sql!(
        "UPDATE CapGrant SET elohim_secret_key = ?3 WHERE action_hash = ?4 AND ",
        ""
    ))
    .bind(current_version_floor())
    .bind(newer_version_floor())
    .bind(secret_key.as_slice())
    .bind(action_hash)
    .execute(executor)
    .await?;
    Ok(done.rows_affected())
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
    use super::*;
    use crate::dht::{
        CapGrantBackfillConfig, CapGrantBackfillEvent, CapGrantBackfillReport, InsertDeletedRecord,
        InsertUpdatedRecord,
    };
    use crate::handles::{DbWrite, TxWrite};
    use crate::kind::Dht;
    use crate::test_open_db;
    use holo_hash::{DnaHash, EntryHash, HoloHashed};
    use holochain_integrity_types::action::{
        Action, ActionData, ActionHeader, CreateData, DeleteData, EntryType, RecordValidity,
        UpdateData,
    };
    use holochain_integrity_types::capability::{GrantedFunctions, ZomeCallCapGrant};
    use holochain_integrity_types::record::SignedHashed;
    use holochain_integrity_types::signature::Signature;
    use holochain_timestamp::Timestamp;
    use holochain_zome_types::prelude::SignedActionHashed;
    use std::collections::BTreeSet;
    use std::sync::Arc;
    use std::time::Duration;

    const LOOKUP_INDEX: &str = "elohim_CapGrant_author_access_secret_idx";

    // -----------------------------------------------------------------------
    // Fixtures
    // -----------------------------------------------------------------------

    async fn open() -> DbWrite<Dht> {
        test_open_db(Dht::new(Arc::new(DnaHash::from_raw_36(vec![0u8; 36]))))
            .await
            .unwrap()
    }

    fn agent(n: u8) -> AgentPubKey {
        AgentPubKey::from_raw_36(vec![n; 36])
    }

    /// A distinct secret per `n` — injective, `n` leads the bytes.
    fn secret(n: u64) -> CapSecret {
        let mut bytes = [0xA5u8; 64];
        bytes[..8].copy_from_slice(&n.to_le_bytes());
        CapSecret::from(bytes)
    }

    fn raw36(kind: u8, id: u32) -> Vec<u8> {
        let mut v = vec![kind; 36];
        v[1..5].copy_from_slice(&id.to_le_bytes());
        v
    }

    fn signed(author: &AgentPubKey, id: u32, data: ActionData) -> SignedActionHashed {
        let action = Action {
            header: ActionHeader {
                author: author.clone(),
                timestamp: Timestamp::from_micros(1_000_000 + i64::from(id)),
                // `id` is unique across the whole fixture, so `seq` is unique
                // per author and `ORDER BY seq` is total.
                action_seq: id,
                prev_action: Some(ActionHash::from_raw_36(vec![0xEE; 36])),
            },
            data,
        };
        SignedHashed::with_presigned(
            HoloHashed::with_pre_hashed(action, ActionHash::from_raw_36(raw36(1, id))),
            Signature([7; 64]),
        )
    }

    /// How a fixture grant's `CapGrant` row is written.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Keying {
        /// Through `insert_cap_grant`: `author` and `secret_key` populated.
        Keyed,
        /// `author` populated, `secret_key` NULL (author backfill done, key
        /// backfill pending).
        AuthorOnly,
        /// Exactly what a binary that predates the columns writes: both NULL.
        Legacy,
    }

    /// Whether a fixture grant's private entry is written.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Blob {
        Present,
        Absent,
    }

    #[derive(Clone, Debug)]
    struct Put {
        action: ActionHash,
        entry_hash: EntryHash,
        entry: Entry,
    }

    fn class_of(access: &CapAccess) -> i64 {
        match access {
            CapAccess::Unrestricted => 0,
            CapAccess::Transferable { .. } => 1,
            CapAccess::Assigned { .. } => 2,
        }
    }

    fn secret_of(entry: &Entry) -> Option<CapSecret> {
        match entry {
            Entry::CapGrant(g) => match &g.access {
                CapAccess::Unrestricted => None,
                CapAccess::Transferable { secret } | CapAccess::Assigned { secret, .. } => {
                    Some(*secret)
                }
            },
            _ => None,
        }
    }

    struct Fixture {
        db: DbWrite<Dht>,
        next_id: u32,
    }

    impl Fixture {
        async fn new() -> Self {
            Self {
                db: open().await,
                next_id: 1,
            }
        }

        fn id(&mut self) -> u32 {
            self.next_id += 1;
            self.next_id
        }

        /// Write the action, private entry and `CapGrant` row of one grant.
        async fn grant_with(
            &mut self,
            tx: &mut TxWrite<Dht>,
            author: &AgentPubKey,
            access: CapAccess,
            keying: Keying,
            blob: Blob,
            original: Option<&Put>,
        ) -> Put {
            let id = self.id();
            let entry = Entry::CapGrant(ZomeCallCapGrant::new(
                format!("grant-{id}"),
                access.clone(),
                GrantedFunctions::All,
            ));
            let entry_hash = EntryHash::from_raw_36(raw36(2, id));
            let data = match original {
                None => ActionData::Create(CreateData {
                    entry_type: EntryType::CapGrant,
                    entry_hash: entry_hash.clone(),
                }),
                Some(o) => ActionData::Update(UpdateData {
                    original_action_address: o.action.clone(),
                    original_entry_address: o.entry_hash.clone(),
                    entry_type: EntryType::CapGrant,
                    entry_hash: entry_hash.clone(),
                }),
            };
            let sah = signed(author, id, data);
            tx.insert_action(&sah, Some(RecordValidity::Accepted))
                .await
                .unwrap();
            if let Some(o) = original {
                tx.insert_updated_record_index(InsertUpdatedRecord {
                    action_hash: sah.as_hash(),
                    original_action_hash: &o.action,
                    original_entry_hash: &o.entry_hash,
                })
                .await
                .unwrap();
            }
            if blob == Blob::Present {
                tx.insert_private_entry(&entry_hash, author, &entry)
                    .await
                    .unwrap();
            }
            let class = class_of(&access);
            let tag = format!("grant-{id}");
            match keying {
                Keying::Keyed => {
                    tx.insert_cap_grant(
                        sah.as_hash(),
                        author,
                        class,
                        secret_of(&entry).as_ref(),
                        Some(&tag),
                    )
                    .await
                    .unwrap();
                }
                Keying::AuthorOnly => {
                    sqlx::query(
                        "INSERT INTO CapGrant (action_hash, cap_access, tag, elohim_author)
                         VALUES (?, ?, ?, ?)",
                    )
                    .bind(sah.as_hash().get_raw_36())
                    .bind(class)
                    .bind(&tag)
                    .bind(author.get_raw_36())
                    .execute(tx.conn_mut())
                    .await
                    .unwrap();
                }
                Keying::Legacy => {
                    // The statement the pre-column binary runs, verbatim.
                    sqlx::query(
                        "INSERT INTO CapGrant (action_hash, cap_access, tag) VALUES (?, ?, ?)",
                    )
                    .bind(sah.as_hash().get_raw_36())
                    .bind(class)
                    .bind(&tag)
                    .execute(tx.conn_mut())
                    .await
                    .unwrap();
                }
            }
            Put {
                action: sah.as_hash().clone(),
                entry_hash,
                entry,
            }
        }

        async fn grant(
            &mut self,
            tx: &mut TxWrite<Dht>,
            author: &AgentPubKey,
            access: CapAccess,
            keying: Keying,
        ) -> Put {
            self.grant_with(tx, author, access, keying, Blob::Present, None)
                .await
        }

        /// A `Delete` authored by `by` naming `target`, with its index row.
        async fn delete(&mut self, tx: &mut TxWrite<Dht>, by: &AgentPubKey, target: &Put) {
            let id = self.id();
            let sah = signed(
                by,
                id,
                ActionData::Delete(DeleteData {
                    deletes_address: target.action.clone(),
                    deletes_entry_address: target.entry_hash.clone(),
                }),
            );
            tx.insert_action(&sah, Some(RecordValidity::Accepted))
                .await
                .unwrap();
            tx.insert_deleted_record_index(InsertDeletedRecord {
                action_hash: sah.as_hash(),
                deletes_action_hash: &target.action,
                deletes_entry_hash: &target.entry_hash,
            })
            .await
            .unwrap();
        }
    }

    async fn keyed(
        db: &DbWrite<Dht>,
        author: &AgentPubKey,
        class: i64,
        secret: Option<&CapSecret>,
    ) -> sqlx::Result<Vec<Entry>> {
        get_live_cap_grant_entries(db.pool(), author.clone(), class, secret).await
    }

    async fn reference(
        db: &DbWrite<Dht>,
        author: &AgentPubKey,
        class: i64,
    ) -> sqlx::Result<Vec<Entry>> {
        get_live_cap_grant_entries_reference(db.pool(), author.clone(), class).await
    }

    /// `(authors_filled, secret_keys_filled, left_unkeyed)`.
    fn counts(report: &CapGrantBackfillReport) -> (u64, u64, u64) {
        (
            report.authors_filled,
            report.secret_keys_filled,
            report.left_unkeyed,
        )
    }

    fn carrying(entries: &[Entry], secret: &CapSecret) -> Vec<Entry> {
        entries
            .iter()
            .filter(|e| secret_of(e).as_ref() == Some(secret))
            .cloned()
            .collect()
    }

    /// `(author, secret_key)` as stored on the row of `action`.
    async fn stored(db: &DbWrite<Dht>, action: &ActionHash) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
        sqlx::query_as(
            "SELECT elohim_author, elohim_secret_key FROM CapGrant WHERE action_hash = ?",
        )
        .bind(action.get_raw_36())
        .fetch_one(db.pool())
        .await
        .unwrap()
    }

    async fn plan(db: &DbWrite<Dht>, sql: &str, with_key: bool) -> Vec<String> {
        let explain = format!("EXPLAIN QUERY PLAN {sql}");
        let mut q = sqlx::query_as::<_, (i64, i64, i64, String)>(sqlx::AssertSqlSafe(explain))
            .bind(1_i64)
            .bind(vec![0u8; 36]);
        if with_key {
            q = q
                .bind(vec![0u8; 33])
                .bind(current_version_floor())
                .bind(newer_version_floor());
        }
        q.fetch_all(db.pool())
            .await
            .unwrap()
            .into_iter()
            .map(|(_, _, _, detail)| detail)
            .collect()
    }

    /// Statement and virtual-machine-step counters read from SQLite itself.
    ///
    /// sqlx exposes no statement counter, so the counters are taken from the
    /// engine: `sqlite3_trace_v2` reports each statement as it starts
    /// (`SQLITE_TRACE_STMT`) and as it finishes (`SQLITE_TRACE_PROFILE`), and
    /// `sqlite3_stmt_status(.., SQLITE_STMTSTATUS_VM_STEP, ..)` gives the
    /// number of bytecode operations the finished statement executed — the
    /// engine's own measure of the work a statement did, independent of the
    /// host's load.
    mod probe {
        use libsqlite3_sys as ffi;
        use std::os::raw::{c_int, c_uint, c_void};
        use std::sync::atomic::{AtomicU64, Ordering};

        #[derive(Default)]
        pub(super) struct Counters {
            statements: AtomicU64,
            vm_steps: AtomicU64,
        }

        impl Counters {
            pub(super) fn statements(&self) -> u64 {
                self.statements.load(Ordering::SeqCst)
            }
            pub(super) fn vm_steps(&self) -> u64 {
                self.vm_steps.load(Ordering::SeqCst)
            }
        }

        unsafe extern "C" fn on_trace(
            kind: c_uint,
            ctx: *mut c_void,
            p: *mut c_void,
            _x: *mut c_void,
        ) -> c_int {
            // SAFETY: `ctx` is the leaked `Counters` registered below, which
            // lives for the rest of the process.
            let counters = unsafe { &*(ctx as *const Counters) };
            if kind == ffi::SQLITE_TRACE_STMT {
                counters.statements.fetch_add(1, Ordering::SeqCst);
            } else if kind == ffi::SQLITE_TRACE_PROFILE {
                // SAFETY: for `SQLITE_TRACE_PROFILE`, `p` is the prepared
                // statement that just finished. The counter is read and reset,
                // so a cached statement reports each run separately.
                let steps = unsafe {
                    ffi::sqlite3_stmt_status(
                        p as *mut ffi::sqlite3_stmt,
                        ffi::SQLITE_STMTSTATUS_VM_STEP,
                        1,
                    )
                };
                counters.vm_steps.fetch_add(steps as u64, Ordering::SeqCst);
            }
            0
        }

        /// Start counting on `conn`. The counters are leaked on purpose: the
        /// connection may outlive the test inside the pool.
        pub(super) async fn install(conn: &mut sqlx::SqliteConnection) -> &'static Counters {
            let counters: &'static Counters = Box::leak(Box::default());
            let mut handle = conn.lock_handle().await.unwrap();
            // SAFETY: the handle is locked for the duration of the call, the
            // callback is a plain `extern "C"` function, and the context
            // pointer is `'static`.
            let rc = unsafe {
                ffi::sqlite3_trace_v2(
                    handle.as_raw_handle().as_ptr(),
                    ffi::SQLITE_TRACE_STMT | ffi::SQLITE_TRACE_PROFILE,
                    Some(on_trace),
                    counters as *const Counters as *mut c_void,
                )
            };
            assert_eq!(rc, ffi::SQLITE_OK);
            counters
        }

        /// Wait until the connection's worker is idle, so every statement that
        /// was issued has also been reset and profiled.
        pub(super) async fn settle(conn: &mut sqlx::SqliteConnection) {
            drop(conn.lock_handle().await.unwrap());
        }
    }

    /// What one secret-bearing authorisation read cost.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct Cost {
        /// Statements issued across both secret-bearing access classes.
        statements: u64,
        /// SQLite bytecode operations executed by those statements.
        vm_steps: u64,
        /// Grant rows the statements returned.
        rows_read: usize,
        /// Grant entries decoded from those rows.
        entries_decoded: usize,
    }

    /// Run the secret-bearing lookup (both classes, as `valid_cap_grants`
    /// does) on one traced connection and report what it cost.
    async fn measure(
        db: &DbWrite<Dht>,
        author: &AgentPubKey,
        secret: &CapSecret,
        use_reference: bool,
    ) -> Cost {
        let mut conn = db.pool().acquire().await.unwrap();
        let counters = probe::install(&mut conn).await;
        let mut rows_read = 0;
        let mut entries_decoded = 0;
        for class in [1_i64, 2] {
            let rows: Vec<LiveCapGrantRow> = if use_reference {
                sqlx::query_as(LIVE_CAP_GRANT_ENTRIES_REFERENCE_SQL)
                    .bind(class)
                    .bind(author.get_raw_36().to_vec())
                    .fetch_all(&mut *conn)
                    .await
                    .unwrap()
            } else {
                fetch_live_cap_grant_rows(&mut *conn, author, class, Some(secret))
                    .await
                    .unwrap()
            };
            rows_read += rows.len();
            entries_decoded += decode_live_cap_grant_rows(rows).unwrap().len();
        }
        probe::settle(&mut conn).await;
        Cost {
            statements: counters.statements(),
            vm_steps: counters.vm_steps(),
            rows_read,
            entries_decoded,
        }
    }

    /// `own` keyed grants for `agent(1)` plus `foreign` keyed grants spread
    /// over five other agents. Grant `i` of an author alternates between the
    /// two secret-bearing classes and carries `secret(i)`, so every author
    /// holds a grant with the probed secret.
    async fn populated(own: u32, foreign: u32) -> DbWrite<Dht> {
        let mut fx = Fixture::new().await;
        let mut tx = fx.db.begin().await.unwrap();
        let put = async |fx: &mut Fixture, tx: &mut TxWrite<Dht>, who: u8, i: u32| {
            let s = secret(u64::from(i));
            let access = if i.is_multiple_of(2) {
                CapAccess::Transferable { secret: s }
            } else {
                CapAccess::Assigned {
                    secret: s,
                    assignees: BTreeSet::from([agent(200)]),
                }
            };
            fx.grant(tx, &agent(who), access, Keying::Keyed).await;
        };
        for i in 0..own {
            put(&mut fx, &mut tx, 1, i).await;
        }
        for i in 0..foreign {
            put(&mut fx, &mut tx, 2 + (i % 5) as u8, i / 5).await;
        }
        tx.commit().await.unwrap();
        fx.db
    }

    // -----------------------------------------------------------------------
    // Key derivation and the write path
    // -----------------------------------------------------------------------

    /// Golden vector. The expected bytes are written out literally — computed
    /// once, independently (`hashlib.blake2b(author + secret, digest_size=32)`)
    /// — so that ANY change to the derivation (preimage order, widths, hash,
    /// version byte) fails here instead of silently hiding every stored grant
    /// from its secret. If this test must change, bump
    /// `CAP_GRANT_SECRET_KEY_VERSION` in the same commit.
    #[test]
    fn secret_key_derivation_matches_the_golden_vector() {
        let author = AgentPubKey::from_raw_36(vec![0x11; 36]);
        let mut secret_bytes = [0u8; 64];
        for (i, b) in secret_bytes.iter_mut().enumerate() {
            *b = i as u8;
        }
        let secret = CapSecret::from(secret_bytes);
        const EXPECTED: [u8; 33] = [
            // version
            0x01, // blake2b-256(0x11 * 36 || 0x00..=0x3f)
            0x5a, 0xbf, 0x59, 0x51, 0xa1, 0xd6, 0x37, 0xfa, 0xad, 0x9e, 0xab, 0x20, 0x5a, 0x8a,
            0x66, 0xff, 0x3b, 0x85, 0xbd, 0xed, 0x22, 0x02, 0x3d, 0x2e, 0xaf, 0xc2, 0x2b, 0x04,
            0x9f, 0x07, 0x1c, 0xad,
        ];
        assert_eq!(cap_grant_secret_key(&author, &secret), EXPECTED);
        assert_eq!(CAP_GRANT_SECRET_KEY_VERSION, 1);
        assert_eq!(CAP_GRANT_SECRET_KEY_BYTES, 33);
    }

    #[test]
    fn secret_key_is_a_full_width_digest_bound_to_author_and_secret() {
        let key = cap_grant_secret_key(&agent(1), &secret(1));
        assert_eq!(key.len(), 33);
        assert_eq!(key[0], CAP_GRANT_SECRET_KEY_VERSION);

        let mut preimage = agent(1).get_raw_36().to_vec();
        preimage.extend_from_slice(secret(1).as_ref());
        assert_eq!(key[1..].to_vec(), holo_hash::blake2b_256(&preimage));

        // The version floors bracket exactly the current version's keys.
        assert!(current_version_floor().as_slice() <= key.as_slice());
        assert!(key.as_slice() < newer_version_floor().as_slice());
        assert!([0xffu8; 33].as_slice() >= newer_version_floor().as_slice());

        assert_ne!(key, cap_grant_secret_key(&agent(2), &secret(1)));
        assert_ne!(key, cap_grant_secret_key(&agent(1), &secret(2)));
        // Never the plaintext, in whole or in part.
        let plain = secret(1);
        assert!(!plain.as_ref().windows(32).any(|w| w == key.as_slice()));
    }

    #[tokio::test]
    async fn insert_populates_author_and_secret_key() {
        let mut fx = Fixture::new().await;
        let mut tx = fx.db.begin().await.unwrap();
        let transferable = fx
            .grant(
                &mut tx,
                &agent(1),
                CapAccess::Transferable { secret: secret(9) },
                Keying::Keyed,
            )
            .await;
        let assigned = fx
            .grant(
                &mut tx,
                &agent(1),
                CapAccess::Assigned {
                    secret: secret(10),
                    assignees: BTreeSet::from([agent(3)]),
                },
                Keying::Keyed,
            )
            .await;
        let unrestricted = fx
            .grant(&mut tx, &agent(1), CapAccess::Unrestricted, Keying::Keyed)
            .await;
        tx.commit().await.unwrap();

        let author = Some(agent(1).get_raw_36().to_vec());
        assert_eq!(
            stored(&fx.db, &transferable.action).await,
            (
                author.clone(),
                Some(cap_grant_secret_key(&agent(1), &secret(9)).to_vec())
            )
        );
        assert_eq!(
            stored(&fx.db, &assigned.action).await,
            (
                author.clone(),
                Some(cap_grant_secret_key(&agent(1), &secret(10)).to_vec())
            )
        );
        // An unrestricted grant has no secret to key on.
        assert_eq!(stored(&fx.db, &unrestricted.action).await, (author, None));
    }

    // -----------------------------------------------------------------------
    // Schema step
    // -----------------------------------------------------------------------

    async fn cap_grant_shape(db: &DbWrite<Dht>) -> (Vec<(String, String, i64, i64)>, Vec<String>) {
        let columns = sqlx::query_as(
            "SELECT name, type, \"notnull\", pk FROM pragma_table_info('CapGrant') ORDER BY cid",
        )
        .fetch_all(db.pool())
        .await
        .unwrap();
        let indexes = sqlx::query_scalar(
            "SELECT sql FROM sqlite_master
              WHERE type = 'index' AND tbl_name = 'CapGrant' AND sql IS NOT NULL
              ORDER BY name",
        )
        .fetch_all(db.pool())
        .await
        .unwrap();
        (columns, indexes)
    }

    /// Running the schema step on a database that already has the columns and
    /// the index changes nothing and does not fail.
    #[tokio::test]
    async fn lookup_schema_step_is_idempotent() {
        let db = open().await;
        let before = cap_grant_shape(&db).await;
        assert_eq!(
            before.0.iter().map(|c| c.0.as_str()).collect::<Vec<_>>(),
            [
                "action_hash",
                "cap_access",
                "tag",
                "elohim_author",
                "elohim_secret_key"
            ]
        );
        assert!(before.1.iter().any(|sql| sql.contains(LOOKUP_INDEX)));
        for _ in 0..3 {
            ensure_cap_grant_lookup_schema(db.pool()).await.unwrap();
        }
        assert_eq!(cap_grant_shape(&db).await, before);
    }

    /// A database created before the columns existed gains them on open,
    /// keeps its rows (with both columns NULL), and ends in exactly the shape
    /// of a fresh database.
    #[tokio::test]
    async fn legacy_database_ends_in_the_same_shape_as_a_fresh_one() {
        let fresh = cap_grant_shape(&open().await).await;

        let mut fx = Fixture::new().await;
        // Put the table back into the shape the 0.7 migration creates.
        for stmt in [
            "DROP INDEX elohim_CapGrant_author_access_secret_idx",
            "ALTER TABLE CapGrant DROP COLUMN elohim_secret_key",
            "ALTER TABLE CapGrant DROP COLUMN elohim_author",
        ] {
            sqlx::query(stmt).execute(fx.db.pool()).await.unwrap();
        }
        assert_eq!(
            cap_grant_shape(&fx.db).await.0.len(),
            3,
            "fixture must start from the pre-column table"
        );
        let author = agent(1);
        let id = fx.id();
        let sah = signed(
            &author,
            id,
            ActionData::Create(CreateData {
                entry_type: EntryType::CapGrant,
                entry_hash: EntryHash::from_raw_36(raw36(2, id)),
            }),
        );
        fx.db.insert_action(&sah, None).await.unwrap();
        sqlx::query("INSERT INTO CapGrant (action_hash, cap_access, tag) VALUES (?, 1, 'old')")
            .bind(sah.as_hash().get_raw_36())
            .execute(fx.db.pool())
            .await
            .unwrap();

        ensure_cap_grant_lookup_schema(fx.db.pool()).await.unwrap();
        assert_eq!(cap_grant_shape(&fx.db).await, fresh);
        assert_eq!(stored(&fx.db, sah.as_hash()).await, (None, None));

        // And again, now that the columns exist.
        ensure_cap_grant_lookup_schema(fx.db.pool()).await.unwrap();
        assert_eq!(cap_grant_shape(&fx.db).await, fresh);
    }

    // -----------------------------------------------------------------------
    // Query plan and cost
    // -----------------------------------------------------------------------

    /// Authorising a zome call must cost the grants that can match, not the
    /// author's history, not the author's other grants, and not other agents'
    /// grants.
    ///
    /// The lookup runs on every zome call signed by a key other than the
    /// author's. Left to itself the planner serves `ORDER BY a.seq` from
    /// `elohim_Action_author_seq_idx`: it walks every action the author ever
    /// wrote and probes `CapGrant` once per action (about 250 ms per access
    /// class on a 19 081-action chain). Driven from the access-class index
    /// alone it reads every agent's grants of the class (9 316–20 298 rows,
    /// ~2.8 s, on hosted-agent stores).
    ///
    /// The assertions describe the property, not one planner's shape. Depending
    /// on the SQLite version the candidate sub-select is either flattened into
    /// the outer query (one copy of the joins per arm, merged) or run as a
    /// co-routine whose rows the outer query walks (`SCAN cg`). Both are fine:
    /// what matters is that every read of the `CapGrant` TABLE is a seek on the
    /// lookup index, that `Action` is only ever probed by primary key, and that
    /// no base table is scanned. Walking the co-routine's own output — the
    /// handful of candidate rows — is not a table scan.
    #[tokio::test]
    async fn live_cap_grant_lookup_is_driven_by_the_author_access_secret_index() {
        let db = open().await;
        let engine: String = sqlx::query_scalar("SELECT sqlite_version()")
            .fetch_one(db.pool())
            .await
            .unwrap();
        for (name, sql, with_key, arms) in [
            ("by secret", LIVE_CAP_GRANT_ENTRIES_BY_SECRET_SQL, true, 5),
            ("by class", LIVE_CAP_GRANT_ENTRIES_BY_CLASS_SQL, false, 2),
        ] {
            let plan = plan(&db, sql, with_key).await;
            eprintln!("cap-grant lookup plan [{name}] on SQLite {engine}:");
            for line in &plan {
                eprintln!("    {line}");
            }
            // Reads of the CapGrant table itself (never the `cg` alias, which
            // names the candidate sub-select's output).
            let grant_reads: Vec<&String> = plan
                .iter()
                .filter(|d| d.starts_with("SEARCH CapGrant ") || d.starts_with("SCAN CapGrant"))
                .collect();
            assert_eq!(
                grant_reads.len(),
                arms,
                "{name}: one CapGrant read per candidate arm, plan: {plan:?}"
            );
            for read in &grant_reads {
                assert!(
                    read.starts_with("SEARCH CapGrant ") && read.contains(LOOKUP_INDEX),
                    "{name}: every arm must seek {LOOKUP_INDEX}, plan: {plan:?}"
                );
            }
            // The only thing that may be walked end to end is the candidate
            // sub-select's own output.
            for scan in plan.iter().filter(|d| d.starts_with("SCAN")) {
                assert!(
                    scan == "SCAN cg" || scan.starts_with("SCAN cg "),
                    "{name}: a base table is scanned ({scan}), plan: {plan:?}"
                );
            }
            let action_reads: Vec<usize> = plan
                .iter()
                .enumerate()
                .filter(|(_, d)| d.starts_with("SEARCH a "))
                .map(|(i, _)| i)
                .collect();
            assert!(!action_reads.is_empty(), "{name}: the plan reads Action");
            for i in &action_reads {
                assert!(
                    plan[*i].contains("PRIMARY KEY"),
                    "{name}: Action must be probed by hash, not walked by author, plan: {plan:?}"
                );
            }
            let first_grant = plan
                .iter()
                .position(|d| d.starts_with("SEARCH CapGrant "))
                .unwrap();
            assert!(
                first_grant < action_reads[0],
                "{name}: CapGrant must be the outer loop, plan: {plan:?}"
            );
            // The revocation checks must probe by entry hash per candidate.
            for (alias, index) in [
                ("u", "elohim_UpdatedRecord_original_entry_idx"),
                ("d", "elohim_DeletedRecord_deletes_entry_idx"),
            ] {
                assert!(
                    plan.iter()
                        .any(|d| d.starts_with(&format!("SEARCH {alias} ")) && d.contains(index)),
                    "{name}: {alias} must be probed through {index}, plan: {plan:?}"
                );
            }
        }
    }

    /// The same secret-keyed lookup issues the same number of statements, runs
    /// the same number of SQLite operations, and reads and decodes the same
    /// number of grant rows whether the author holds 10 grants or 5 000, and
    /// whether or not 5 000 more belong to other agents in the same database.
    #[tokio::test]
    async fn secret_keyed_lookup_cost_is_independent_of_grant_count_and_of_other_authors() {
        let author = agent(1);
        let probe_secret = secret(4);

        let mut keyed_costs = Vec::new();
        let mut reference_costs = Vec::new();
        for (label, own, foreign) in [
            ("10 own grants", 10, 0),
            ("5000 own grants", 5_000, 0),
            ("5000 own + 5000 foreign grants", 5_000, 5_000),
        ] {
            let db = populated(own, foreign).await;
            let cost = measure(&db, &author, &probe_secret, false).await;
            let old = measure(&db, &author, &probe_secret, true).await;
            eprintln!("cap-grant lookup cost [{label}]: keyed {cost:?}; reference {old:?}");
            keyed_costs.push((label, cost));
            reference_costs.push((label, old));
        }

        let (_, small) = keyed_costs[0];
        assert_eq!(
            small.statements, 2,
            "one statement per secret-bearing class"
        );
        assert_eq!(small.rows_read, 1, "only the grant keyed to the secret");
        assert_eq!(small.entries_decoded, 1);
        for (label, cost) in &keyed_costs[1..] {
            assert_eq!(
                (cost.statements, cost.rows_read, cost.entries_decoded),
                (small.statements, small.rows_read, small.entries_decoded),
                "{label}: statements and rows must equal the 10-grant cost"
            );
            // The executed-operation count is flat too. It is not asserted
            // bit-for-bit: where a range arm's seek lands next to another
            // agent's index entries it takes one more step to find its range
            // empty (measured: 281, 281 and 282 operations). A handful of
            // operations is the tolerance; the pre-keyed read on the same
            // stores runs 335 039 and 365 039.
            assert!(
                cost.vm_steps.abs_diff(small.vm_steps) <= 8,
                "{label}: {} operations against {} at 10 grants",
                cost.vm_steps,
                small.vm_steps
            );
        }

        // The pre-keyed read on the very same stores, for contrast: it reads
        // every live grant of the author, so its cost follows the grant count.
        assert_eq!(reference_costs[0].1.rows_read, 10);
        assert_eq!(reference_costs[1].1.rows_read, 5_000);
        assert!(reference_costs[1].1.vm_steps > 100 * small.vm_steps);
        assert!(
            reference_costs[2].1.vm_steps > reference_costs[1].1.vm_steps,
            "the pre-keyed read also pays for other agents' grants"
        );
    }

    /// RESIDUAL COST, pinned so it is not mistaken for a bug: the keyed read
    /// costs the number of the author's live grants that SHARE the presented
    /// secret. Every one of them is a legitimate candidate — they may differ in
    /// functions or assignees, and `CapGrant::is_valid` chooses — so every one
    /// is fetched and decoded. An author who mints `N` live grants with one
    /// secret pays for `N` on each call presenting it; nothing bounds `N`.
    /// Other secrets, and other agents, still cost nothing.
    #[tokio::test]
    async fn lookup_cost_follows_the_number_of_live_grants_sharing_the_secret() {
        let author = agent(1);
        let shared = secret(1_000_000);
        let mut costs = Vec::new();
        for sharing in [1_u32, 50, 500] {
            let mut fx = Fixture::new().await;
            let mut tx = fx.db.begin().await.unwrap();
            for i in 0..1_000u32 {
                // Decoys: the author's other secrets, and the shared secret
                // under another agent.
                let access = CapAccess::Transferable {
                    secret: secret(u64::from(i)),
                };
                fx.grant(&mut tx, &author, access, Keying::Keyed).await;
                let access = CapAccess::Transferable { secret: shared };
                fx.grant(&mut tx, &agent(2), access, Keying::Keyed).await;
            }
            for _ in 0..sharing {
                let access = CapAccess::Transferable { secret: shared };
                fx.grant(&mut tx, &author, access, Keying::Keyed).await;
            }
            tx.commit().await.unwrap();
            let cost = measure(&fx.db, &author, &shared, false).await;
            eprintln!("cap-grant lookup cost [{sharing} live grants share the secret]: {cost:?}");
            assert_eq!(cost.statements, 2);
            assert_eq!(cost.rows_read, sharing as usize);
            assert_eq!(cost.entries_decoded, sharing as usize);
            costs.push(cost);
        }
        assert!(costs[0].vm_steps < costs[1].vm_steps && costs[1].vm_steps < costs[2].vm_steps);
    }

    // -----------------------------------------------------------------------
    // Differential equivalence, across backfill states
    // -----------------------------------------------------------------------

    struct Lcg(u64);

    impl Lcg {
        fn below(&mut self, n: u64) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (self.0 >> 11) % n
        }
    }

    const SECRET_POOL: u64 = 12;
    const AUTHORS: [u8; 3] = [1, 2, 3];

    fn random_access(rng: &mut Lcg) -> CapAccess {
        // A small pool, so secrets are shared between grants, between classes
        // and between authors.
        let s = secret(rng.below(SECRET_POOL));
        match rng.below(3) {
            0 => CapAccess::Unrestricted,
            1 => CapAccess::Transferable { secret: s },
            _ => CapAccess::Assigned {
                secret: s,
                assignees: BTreeSet::from([agent(100 + rng.below(4) as u8)]),
            },
        }
    }

    fn random_keying(rng: &mut Lcg) -> Keying {
        match rng.below(3) {
            0 => Keying::Keyed,
            1 => Keying::AuthorOnly,
            _ => Keying::Legacy,
        }
    }

    /// A mixed population over three authors sharing one database: every access
    /// class, shared secrets, every keying state, grants deleted and updated by
    /// their author, and `Delete`s / `Update`s authored by OTHER agents that
    /// name a grant's entry hash and must revoke nothing.
    async fn random_population(seed: u64, count: u32, keying: Option<Keying>) -> Fixture {
        let mut fx = Fixture::new().await;
        random_population_into(&mut fx, seed, count, keying).await;
        fx
    }

    /// [`random_population`] written into an existing fixture; returns every
    /// grant created (by author), revoked or not.
    async fn random_population_into(
        fx: &mut Fixture,
        seed: u64,
        count: u32,
        keying: Option<Keying>,
    ) -> Vec<(u8, Put)> {
        let mut rng = Lcg(seed);
        let mut tx = fx.db.begin().await.unwrap();
        let mut puts: Vec<(u8, Put)> = Vec::new();
        for _ in 0..count {
            let who = AUTHORS[rng.below(3) as usize];
            let access = random_access(&mut rng);
            let k = keying.unwrap_or_else(|| random_keying(&mut rng));
            let put = fx.grant(&mut tx, &agent(who), access, k).await;
            puts.push((who, put));
        }
        for (who, put) in puts.clone() {
            let other = AUTHORS[(AUTHORS.iter().position(|a| *a == who).unwrap() + 1) % 3];
            match rng.below(8) {
                0 => fx.delete(&mut tx, &agent(who), &put).await,
                1 => {
                    let access = random_access(&mut rng);
                    let k = keying.unwrap_or_else(|| random_keying(&mut rng));
                    fx.grant_with(&mut tx, &agent(who), access, k, Blob::Present, Some(&put))
                        .await;
                }
                // Foreign revocation attempts.
                2 => fx.delete(&mut tx, &agent(other), &put).await,
                3 => {
                    let access = random_access(&mut rng);
                    let k = keying.unwrap_or_else(|| random_keying(&mut rng));
                    fx.grant_with(&mut tx, &agent(other), access, k, Blob::Present, Some(&put))
                        .await;
                }
                _ => {}
            }
        }
        tx.commit().await.unwrap();
        puts
    }

    fn is_subsequence(needle: &[Entry], haystack: &[Entry]) -> bool {
        let mut it = haystack.iter();
        needle.iter().all(|n| it.any(|h| h == n))
    }

    /// Compare the keyed read against the pre-keyed oracle for every author,
    /// class and probe secret. Returns how many grants were matched in total,
    /// so a caller can assert the population was not vacuous.
    ///
    /// The decision-relevant property holds in EVERY backfill state: the
    /// grants carrying the probed secret are the same, in the same order —
    /// that is exactly the set `CapGrant::is_valid` can accept. When
    /// `fully_keyed`, the keyed read must return nothing else at all.
    async fn assert_matches_reference(db: &DbWrite<Dht>, fully_keyed: bool, stage: &str) -> usize {
        let mut matched = 0;
        for who in AUTHORS {
            let author = agent(who);
            // Unrestricted: the class read is unchanged in content.
            assert_eq!(
                keyed(db, &author, 0, None).await.unwrap(),
                reference(db, &author, 0).await.unwrap(),
                "{stage}: unrestricted grants of agent {who}"
            );
            for class in [1_i64, 2] {
                let all = reference(db, &author, class).await.unwrap();
                // One secret beyond the pool: carried by no grant.
                for n in 0..=SECRET_POOL {
                    let probe = secret(n);
                    let got = keyed(db, &author, class, Some(&probe)).await.unwrap();
                    let expected = carrying(&all, &probe);
                    assert_eq!(
                        carrying(&got, &probe),
                        expected,
                        "{stage}: agent {who} class {class} secret {n}"
                    );
                    assert!(
                        is_subsequence(&got, &all),
                        "{stage}: agent {who} class {class} secret {n}: the keyed read \
                         returned a grant the reference does not consider live"
                    );
                    if fully_keyed {
                        assert_eq!(
                            got, expected,
                            "{stage}: agent {who} class {class} secret {n}: a fully keyed \
                             store must read only the grants carrying the secret"
                        );
                    }
                    matched += expected.len();
                }
            }
        }
        matched
    }

    async fn unkeyed_counts(db: &DbWrite<Dht>) -> (i64, i64) {
        sqlx::query_as(
            "SELECT (SELECT COUNT(*) FROM CapGrant WHERE elohim_author IS NULL),
                    (SELECT COUNT(*) FROM CapGrant
                      WHERE elohim_secret_key IS NULL AND cap_access IN (1, 2))",
        )
        .fetch_one(db.pool())
        .await
        .unwrap()
    }

    /// Randomised equivalence against the kept pre-keyed read, re-checked as
    /// the same store moves through every backfill state: mixed as written,
    /// authors filled, keys partly filled, fully filled, and filled again.
    #[tokio::test]
    async fn keyed_lookup_matches_reference_over_random_population_in_every_backfill_state() {
        for seed in [0x00C0_FFEE_u64, 0x5EED_0002, 0x5EED_0003] {
            let fx = random_population(seed, 240, None).await;
            let db = &fx.db;

            let matched = assert_matches_reference(db, false, "as written").await;
            assert!(
                matched > 40,
                "seed {seed:#x}: vacuous population ({matched})"
            );

            // Authors only.
            while db.backfill_cap_grant_authors_batch(17).await.unwrap() > 0 {}
            assert_eq!(unkeyed_counts(db).await.0, 0);
            assert!(unkeyed_counts(db).await.1 > 0);
            assert_eq!(
                assert_matches_reference(db, false, "authors filled").await,
                matched
            );

            // One small batch of keys: partially backfilled.
            let before = unkeyed_counts(db).await.1;
            let batch = db
                .backfill_cap_grant_secret_keys_batch(None, 7)
                .await
                .unwrap();
            assert_eq!(batch.keyed, 7);
            assert_eq!(unkeyed_counts(db).await.1, before - 7);
            assert_eq!(
                assert_matches_reference(db, false, "keys partly filled").await,
                matched
            );

            // Everything.
            let report = db
                .backfill_cap_grant_lookup_keys(11, Duration::ZERO)
                .await
                .unwrap();
            assert_eq!(report.secret_keys_filled as i64, before - 7);
            assert_eq!(report.left_unkeyed, 0);
            assert_eq!(unkeyed_counts(db).await, (0, 0));
            assert_eq!(
                assert_matches_reference(db, true, "fully filled").await,
                matched
            );

            // Again: nothing to do, nothing changes.
            let again = db
                .backfill_cap_grant_lookup_keys(11, Duration::ZERO)
                .await
                .unwrap();
            assert_eq!(counts(&again), (0, 0, 0));
            assert_eq!(
                assert_matches_reference(db, true, "filled twice").await,
                matched
            );
        }
    }

    /// A store written entirely by a binary that predates the columns — every
    /// row NULL in both — authorises exactly as before, and gives the same
    /// answers after the backfill.
    #[tokio::test]
    async fn unbackfilled_database_authorises_exactly_as_before() {
        let fx = random_population(0x01D_DA7A, 240, Some(Keying::Legacy)).await;
        let db = &fx.db;
        let (no_author, no_key) = unkeyed_counts(db).await;
        assert!(no_author > 240 && no_key > 100);

        // With nothing keyed the keyed read returns the whole live class,
        // exactly the reference's rows in the reference's order.
        for who in AUTHORS {
            for class in [1_i64, 2] {
                assert_eq!(
                    keyed(db, &agent(who), class, Some(&secret(3)))
                        .await
                        .unwrap(),
                    reference(db, &agent(who), class).await.unwrap()
                );
            }
        }
        let matched = assert_matches_reference(db, false, "legacy").await;
        assert!(matched > 40);

        db.backfill_cap_grant_lookup_keys(64, Duration::ZERO)
            .await
            .unwrap();
        assert_eq!(unkeyed_counts(db).await, (0, 0));
        assert_eq!(
            assert_matches_reference(db, true, "legacy, backfilled").await,
            matched
        );
    }

    // -----------------------------------------------------------------------
    // Targeted security properties
    // -----------------------------------------------------------------------

    /// Every live grant carrying the secret is returned, in chain order — two
    /// grants may share a secret and `CapGrant::is_valid` chooses.
    #[tokio::test]
    async fn every_grant_sharing_a_secret_is_returned_in_seq_order() {
        let mut fx = Fixture::new().await;
        let s = secret(1);
        let mut tx = fx.db.begin().await.unwrap();
        let mut expected = Vec::new();
        for _ in 0..3 {
            let p = fx
                .grant(
                    &mut tx,
                    &agent(1),
                    CapAccess::Transferable { secret: s },
                    Keying::Keyed,
                )
                .await;
            expected.push(p.entry);
            // Decoys: another secret, and the same secret under another agent.
            fx.grant(
                &mut tx,
                &agent(1),
                CapAccess::Transferable { secret: secret(2) },
                Keying::Keyed,
            )
            .await;
            fx.grant(
                &mut tx,
                &agent(2),
                CapAccess::Transferable { secret: s },
                Keying::Keyed,
            )
            .await;
        }
        tx.commit().await.unwrap();
        assert_eq!(
            keyed(&fx.db, &agent(1), 1, Some(&s)).await.unwrap(),
            expected
        );
    }

    /// A `Delete` or `Update` authored by another agent that names a grant's
    /// entry hash revokes nothing; the author's own does.
    #[tokio::test]
    async fn only_the_authors_own_delete_or_update_revokes() {
        for keying in [Keying::Keyed, Keying::AuthorOnly, Keying::Legacy] {
            let mut fx = Fixture::new().await;
            let (owner, foreign) = (agent(1), agent(2));
            let mut tx = fx.db.begin().await.unwrap();
            let mut grants = Vec::new();
            for n in 0..4 {
                let access = CapAccess::Transferable { secret: secret(n) };
                grants.push(fx.grant(&mut tx, &owner, access, keying).await);
            }
            // Foreign attempts on grants 0 and 1.
            fx.delete(&mut tx, &foreign, &grants[0]).await;
            fx.grant_with(
                &mut tx,
                &foreign,
                CapAccess::Transferable { secret: secret(50) },
                keying,
                Blob::Present,
                Some(&grants[1]),
            )
            .await;
            tx.commit().await.unwrap();
            for (n, grant) in grants.iter().enumerate() {
                let probe = secret(n as u64);
                let got = keyed(&fx.db, &owner, 1, Some(&probe)).await.unwrap();
                assert_eq!(
                    carrying(&got, &probe),
                    vec![grant.entry.clone()],
                    "{keying:?}: grant {n} must survive a foreign revocation"
                );
            }

            // The owner's own on grants 2 and 3.
            let mut tx = fx.db.begin().await.unwrap();
            fx.delete(&mut tx, &owner, &grants[2]).await;
            let replacement = fx
                .grant_with(
                    &mut tx,
                    &owner,
                    CapAccess::Transferable { secret: secret(60) },
                    keying,
                    Blob::Present,
                    Some(&grants[3]),
                )
                .await;
            tx.commit().await.unwrap();
            for n in [2_u64, 3] {
                let probe = secret(n);
                let got = keyed(&fx.db, &owner, 1, Some(&probe)).await.unwrap();
                assert!(
                    carrying(&got, &probe).is_empty(),
                    "{keying:?}: grant {n} must be revoked by its author"
                );
            }
            let got = keyed(&fx.db, &owner, 1, Some(&secret(60))).await.unwrap();
            assert_eq!(carrying(&got, &secret(60)), vec![replacement.entry]);
        }
    }

    /// The stored key narrows the read and decides nothing. A row whose
    /// `secret_key` is WRONG — here, a grant for one secret filed under another
    /// secret's key — is fetched for the wrong secret, but the entry it yields
    /// still carries its real secret, which is what the caller compares.
    #[tokio::test]
    async fn stored_secret_key_is_never_trusted_as_the_secret() {
        let mut fx = Fixture::new().await;
        let author = agent(1);
        let (real, presented) = (secret(1), secret(2));
        let mut tx = fx.db.begin().await.unwrap();
        let grant = fx
            .grant(
                &mut tx,
                &author,
                CapAccess::Transferable { secret: real },
                Keying::Keyed,
            )
            .await;
        tx.commit().await.unwrap();
        sqlx::query("UPDATE CapGrant SET elohim_secret_key = ? WHERE action_hash = ?")
            .bind(cap_grant_secret_key(&author, &presented).to_vec())
            .bind(grant.action.get_raw_36())
            .execute(fx.db.pool())
            .await
            .unwrap();

        let got = keyed(&fx.db, &author, 1, Some(&presented)).await.unwrap();
        assert_eq!(
            got,
            vec![grant.entry.clone()],
            "the mis-keyed row is fetched"
        );
        assert_eq!(
            secret_of(&got[0]),
            Some(real),
            "and it still says which secret it really carries"
        );
        assert!(carrying(&got, &presented).is_empty());
        // Hidden from its real secret: a wrong key can only deny.
        assert!(keyed(&fx.db, &author, 1, Some(&real))
            .await
            .unwrap()
            .is_empty());
    }

    /// A row whose `author` column names the wrong agent cannot hand that
    /// agent the grant: the `Action.author` join still decides.
    #[tokio::test]
    async fn stored_author_is_never_trusted_as_the_author() {
        let mut fx = Fixture::new().await;
        let (owner, other) = (agent(1), agent(2));
        let s = secret(1);
        let mut tx = fx.db.begin().await.unwrap();
        let grant = fx
            .grant(
                &mut tx,
                &owner,
                CapAccess::Transferable { secret: s },
                Keying::Keyed,
            )
            .await;
        // The same entry content under the other agent's private store, so
        // only the author predicate stands between them and the grant.
        tx.insert_private_entry(&grant.entry_hash, &other, &grant.entry)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        sqlx::query(
            "UPDATE CapGrant SET elohim_author = ?, elohim_secret_key = ? WHERE action_hash = ?",
        )
        .bind(other.get_raw_36())
        .bind(cap_grant_secret_key(&other, &s).to_vec())
        .bind(grant.action.get_raw_36())
        .execute(fx.db.pool())
        .await
        .unwrap();
        assert!(keyed(&fx.db, &other, 1, Some(&s)).await.unwrap().is_empty());
    }

    async fn corrupt(db: &DbWrite<Dht>, action: &ActionHash, how: &str) {
        let sql = match how {
            "action_data" => "UPDATE Action SET action_data = X'FFFFFFFFFFFFFFFF' WHERE hash = ?",
            "signature" => "UPDATE Action SET signature = X'000000' WHERE hash = ?",
            "null_entry_hash" => "UPDATE Action SET entry_hash = NULL WHERE hash = ?",
            _ => unreachable!(),
        };
        sqlx::query(sql)
            .bind(action.get_raw_36())
            .execute(db.pool())
            .await
            .unwrap();
    }

    /// A corrupt action on the grant the secret is keyed to fails the read
    /// closed, however it is corrupt.
    #[tokio::test]
    async fn corrupt_action_on_the_matched_grant_fails_closed() {
        for how in ["action_data", "signature", "null_entry_hash"] {
            let mut fx = Fixture::new().await;
            let author = agent(1);
            let s = secret(1);
            let mut tx = fx.db.begin().await.unwrap();
            let first = fx
                .grant(
                    &mut tx,
                    &author,
                    CapAccess::Transferable { secret: s },
                    Keying::Keyed,
                )
                .await;
            // A second, intact grant with the same secret must not rescue it.
            fx.grant(
                &mut tx,
                &author,
                CapAccess::Transferable { secret: s },
                Keying::Keyed,
            )
            .await;
            tx.commit().await.unwrap();
            assert_eq!(keyed(&fx.db, &author, 1, Some(&s)).await.unwrap().len(), 2);

            corrupt(&fx.db, &first.action, how).await;
            let got = keyed(&fx.db, &author, 1, Some(&s)).await;
            assert!(
                matches!(got, Err(sqlx::Error::Decode(_))),
                "{how}: must deny, got {got:?}"
            );
        }
    }

    /// THE ONE DELIBERATE BEHAVIOUR CHANGE. A corrupt action on a live grant
    /// keyed to a DIFFERENT secret used to fail every secret-bearing read for
    /// the author (the reference still does); the keyed read never fetches it.
    /// A corrupt action on a row that is not keyed yet still fails closed.
    #[tokio::test]
    async fn corrupt_action_on_an_unrelated_keyed_grant_no_longer_denies() {
        for how in ["action_data", "signature", "null_entry_hash"] {
            let mut fx = Fixture::new().await;
            let author = agent(1);
            let mut tx = fx.db.begin().await.unwrap();
            let unrelated = fx
                .grant(
                    &mut tx,
                    &author,
                    CapAccess::Transferable { secret: secret(1) },
                    Keying::Keyed,
                )
                .await;
            let wanted = fx
                .grant(
                    &mut tx,
                    &author,
                    CapAccess::Transferable { secret: secret(2) },
                    Keying::Keyed,
                )
                .await;
            tx.commit().await.unwrap();
            corrupt(&fx.db, &unrelated.action, how).await;

            assert!(
                reference(&fx.db, &author, 1).await.is_err(),
                "{how}: the load-every-grant read denies"
            );
            assert_eq!(
                keyed(&fx.db, &author, 1, Some(&secret(2))).await.unwrap(),
                vec![wanted.entry.clone()],
                "{how}: the keyed read is not denied by a grant it never fetches"
            );
            assert!(
                keyed(&fx.db, &author, 1, Some(&secret(1))).await.is_err(),
                "{how}: the corrupt grant's own secret is still denied"
            );

            // Un-key the corrupt row: it is back on the read-everything path
            // and denies every secret again.
            sqlx::query("UPDATE CapGrant SET elohim_secret_key = NULL WHERE action_hash = ?")
                .bind(unrelated.action.get_raw_36())
                .execute(fx.db.pool())
                .await
                .unwrap();
            assert!(
                keyed(&fx.db, &author, 1, Some(&secret(2))).await.is_err(),
                "{how}: an un-keyed corrupt grant still fails closed"
            );
        }
    }

    /// A matched grant whose private entry is absent is skipped (after its
    /// action decodes), and a row in the PUBLIC `Entry` table at that entry
    /// hash is never read in its place — for both statements.
    #[tokio::test]
    async fn missing_private_entry_is_skipped_and_the_public_table_is_never_read() {
        let mut fx = Fixture::new().await;
        let author = agent(1);
        let s = secret(1);
        let mut tx = fx.db.begin().await.unwrap();
        let keyed_grant = fx
            .grant_with(
                &mut tx,
                &author,
                CapAccess::Transferable { secret: s },
                Keying::Keyed,
                Blob::Absent,
                None,
            )
            .await;
        let unrestricted = fx
            .grant_with(
                &mut tx,
                &author,
                CapAccess::Unrestricted,
                Keying::Keyed,
                Blob::Absent,
                None,
            )
            .await;
        tx.commit().await.unwrap();

        // A grant-anyone-anything blob in the public table at both hashes.
        let open_grant = Entry::CapGrant(ZomeCallCapGrant::new(
            "public-row".into(),
            CapAccess::Unrestricted,
            GrantedFunctions::All,
        ));
        for put in [&keyed_grant, &unrestricted] {
            fx.db
                .insert_entry(&put.entry_hash, &open_grant)
                .await
                .unwrap();
        }

        assert!(keyed(&fx.db, &author, 1, Some(&s))
            .await
            .unwrap()
            .is_empty());
        assert!(keyed(&fx.db, &author, 0, None).await.unwrap().is_empty());

        // Absence does not excuse corruption: the action is decoded first.
        corrupt(&fx.db, &keyed_grant.action, "action_data").await;
        assert!(keyed(&fx.db, &author, 1, Some(&s)).await.is_err());
    }

    // -----------------------------------------------------------------------
    // Backfill
    // -----------------------------------------------------------------------

    /// The backfill keys every row it can derive a key for, by the row's TRUE
    /// author, and leaves every other row NULL — on the slow, correct path.
    /// Run again it changes nothing.
    #[tokio::test]
    async fn backfill_keys_what_it_can_and_leaves_the_rest_null() {
        let mut fx = Fixture::new().await;
        let (a, b, c, d) = (agent(1), agent(2), agent(3), agent(4));
        let shared = secret(1);
        let t = |secret| CapAccess::Transferable { secret };
        let mut tx = fx.db.begin().await.unwrap();
        let a_grant = fx.grant(&mut tx, &a, t(shared), Keying::Legacy).await;
        let b_grant = fx.grant(&mut tx, &b, t(shared), Keying::Legacy).await;
        let a_assigned = fx
            .grant(
                &mut tx,
                &a,
                CapAccess::Assigned {
                    secret: secret(2),
                    assignees: BTreeSet::from([b.clone()]),
                },
                Keying::AuthorOnly,
            )
            .await;
        let a_unrestricted = fx
            .grant(&mut tx, &a, CapAccess::Unrestricted, Keying::Legacy)
            .await;
        // Rows no key can be derived for.
        let no_blob = fx
            .grant_with(
                &mut tx,
                &a,
                t(secret(3)),
                Keying::Legacy,
                Blob::Absent,
                None,
            )
            .await;
        let bad_blob = fx
            .grant_with(
                &mut tx,
                &d,
                t(secret(4)),
                Keying::Legacy,
                Blob::Absent,
                None,
            )
            .await;
        sqlx::query("INSERT INTO PrivateEntry (hash, author, blob) VALUES (?, ?, X'C1C1C1')")
            .bind(bad_blob.entry_hash.get_raw_36())
            .bind(d.get_raw_36())
            .execute(tx.conn_mut())
            .await
            .unwrap();
        // The entry exists, but only in ANOTHER agent's private store.
        let foreign_blob = fx
            .grant_with(
                &mut tx,
                &a,
                t(secret(5)),
                Keying::Legacy,
                Blob::Absent,
                None,
            )
            .await;
        tx.insert_private_entry(&foreign_blob.entry_hash, &b, &foreign_blob.entry)
            .await
            .unwrap();
        let bad_action = fx.grant(&mut tx, &c, t(secret(6)), Keying::Legacy).await;
        tx.commit().await.unwrap();
        corrupt(&fx.db, &bad_action.action, "action_data").await;

        let report = fx
            .db
            .backfill_cap_grant_lookup_keys(2, Duration::ZERO)
            .await
            .unwrap();
        assert_eq!(counts(&report), (7, 3, 4));
        assert_eq!(fx.db.as_ref().count_cap_grants_unkeyed().await.unwrap(), 4);

        let key = |who: &AgentPubKey, s: &CapSecret| Some(cap_grant_secret_key(who, s).to_vec());
        let by = |who: &AgentPubKey| Some(who.get_raw_36().to_vec());
        assert_eq!(
            stored(&fx.db, &a_grant.action).await,
            (by(&a), key(&a, &shared))
        );
        assert_eq!(
            stored(&fx.db, &b_grant.action).await,
            (by(&b), key(&b, &shared))
        );
        assert_eq!(
            stored(&fx.db, &a_assigned.action).await,
            (by(&a), key(&a, &secret(2)))
        );
        assert_eq!(stored(&fx.db, &a_unrestricted.action).await, (by(&a), None));
        for put in [&no_blob, &foreign_blob] {
            assert_eq!(stored(&fx.db, &put.action).await, (by(&a), None));
        }
        assert_eq!(stored(&fx.db, &bad_blob.action).await, (by(&d), None));
        assert_eq!(stored(&fx.db, &bad_action.action).await, (by(&c), None));

        // Idempotent: the rows that could not be keyed are looked at again and
        // left alone again.
        let again = fx
            .db
            .backfill_cap_grant_lookup_keys(2, Duration::ZERO)
            .await
            .unwrap();
        assert_eq!(counts(&again), (0, 0, 4));

        // The un-keyable rows of `a` are still read by every secret-bearing
        // lookup of `a`, exactly as before the columns existed; `b` reads only
        // its own keyed grant.
        assert_eq!(
            keyed(&fx.db, &b, 1, Some(&shared)).await.unwrap(),
            vec![b_grant.entry.clone()]
        );
        let got = keyed(&fx.db, &a, 1, Some(&shared)).await.unwrap();
        assert_eq!(carrying(&got, &shared), vec![a_grant.entry.clone()]);
        // `c`'s only grant has a corrupt action, and `d`'s an undecodable entry.
        // Neither could be keyed, so both are still read by every
        // secret-bearing lookup of their author and still fail it closed —
        // whatever secret is presented, exactly as the reference does.
        for (who, own) in [(&c, secret(6)), (&d, secret(4))] {
            for probe in [own, secret(99)] {
                assert!(keyed(&fx.db, who, 1, Some(&probe)).await.is_err());
            }
            assert!(reference(&fx.db, who, 1).await.is_err());
        }
    }

    /// The key backfill is resumable from nothing: interrupted after any
    /// batch, a later run that starts over finishes the job, because finished
    /// rows are no longer selected.
    #[tokio::test]
    async fn backfill_resumes_after_an_interrupted_run() {
        let fx = random_population(0x00AB_CDEF, 120, Some(Keying::Legacy)).await;
        let db = &fx.db;
        let total = unkeyed_counts(db).await.1;
        assert!(total > 20);

        // An "interrupted" run: two batches, then the cursor is lost.
        let first = db
            .backfill_cap_grant_secret_keys_batch(None, 5)
            .await
            .unwrap();
        let second = db
            .backfill_cap_grant_secret_keys_batch(first.next_cursor.as_deref(), 5)
            .await
            .unwrap();
        assert_eq!((first.keyed, second.keyed), (5, 5));
        assert_eq!(unkeyed_counts(db).await.1, total - 10);

        let report = db
            .backfill_cap_grant_lookup_keys(5, Duration::ZERO)
            .await
            .unwrap();
        assert_eq!(report.secret_keys_filled as i64, total - 10);
        assert_eq!(unkeyed_counts(db).await, (0, 0));
    }

    /// A key-backfill batch seeks to its cursor in primary-key order and stops
    /// at its limit; it never sorts, and never walks, the rest of the table.
    #[tokio::test]
    async fn key_backfill_batch_is_a_primary_key_range_walk() {
        let db = open().await;
        let explain = format!("EXPLAIN QUERY PLAN {CAP_GRANTS_MISSING_SECRET_KEY_SQL}");
        let plan: Vec<String> =
            sqlx::query_as::<_, (i64, i64, i64, String)>(sqlx::AssertSqlSafe(explain))
                .bind(current_version_floor())
                .bind(newer_version_floor())
                .bind(vec![0u8; 36])
                .bind(256_i64)
                .fetch_all(db.pool())
                .await
                .unwrap()
                .into_iter()
                .map(|(_, _, _, detail)| detail)
                .collect();
        assert!(
            plan.iter()
                .any(|d| d.starts_with("SEARCH CapGrant USING PRIMARY KEY (action_hash>?")),
            "CapGrant must be range-sought by primary key, plan: {plan:?}"
        );
        assert!(
            !plan.iter().any(|d| d.contains("TEMP B-TREE")),
            "the batch must not sort, plan: {plan:?}"
        );
        // Only the limited candidate sub-select's own output may be walked.
        for scan in plan.iter().filter(|d| d.starts_with("SCAN")) {
            assert!(
                scan == "SCAN cg" || scan.starts_with("SCAN cg "),
                "a base table is scanned ({scan}), plan: {plan:?}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // The whole fail-closed change, both sides
    // -----------------------------------------------------------------------

    /// Every way one live grant can fail to decode.
    const CORRUPTIONS: [&str; 5] = [
        // (a) the action does not decode
        "action_data",
        "signature",
        // (b) the private entry blob does not decode
        "entry_blob",
        // (c) the entry_hash column disagrees with the decoded action
        "entry_hash_mismatch",
        "null_entry_hash",
    ];

    async fn corrupt_grant(db: &DbWrite<Dht>, author: &AgentPubKey, put: &Put, how: &str) {
        match how {
            "entry_blob" => {
                let done = sqlx::query(
                    "UPDATE PrivateEntry SET blob = X'C1C1C1' WHERE hash = ? AND author = ?",
                )
                .bind(put.entry_hash.get_raw_36())
                .bind(author.get_raw_36())
                .execute(db.pool())
                .await
                .unwrap();
                assert_eq!(done.rows_affected(), 1);
            }
            "entry_hash_mismatch" => {
                // A different, well-formed entry hash. A private entry is put
                // there too, so the only thing wrong with the row is that the
                // column no longer agrees with the action it sits on.
                let elsewhere = EntryHash::from_raw_36(vec![0xEA; 36]);
                db.insert_private_entry(&elsewhere, author, &put.entry)
                    .await
                    .unwrap();
                sqlx::query("UPDATE Action SET entry_hash = ? WHERE hash = ?")
                    .bind(elsewhere.get_raw_36())
                    .bind(put.action.get_raw_36())
                    .execute(db.pool())
                    .await
                    .unwrap();
            }
            other => corrupt(db, &put.action, other).await,
        }
    }

    /// How the corrupt grant's row is keyed when the unrelated call arrives.
    #[derive(Clone, Copy, Debug)]
    enum VictimKey {
        /// Keyed, by the current derivation, to its own (different) secret.
        Current,
        /// Not keyed at all.
        Null,
        /// Keyed by an older derivation.
        OlderVersion,
        /// Keyed by a newer derivation.
        NewerVersion,
    }

    /// THE WHOLE FAIL-CLOSED CHANGE, both sides, for every kind of corruption.
    ///
    /// Before the keyed read, one live secret-bearing grant that failed to
    /// decode — a corrupt action, an undecodable private entry, or an
    /// `entry_hash` column disagreeing with its action — failed every
    /// secret-bearing authorisation read of its author (the reference still
    /// does). Now:
    ///
    /// - on a grant KEYED to a different secret it is never fetched: the
    ///   unrelated call is no longer denied (the change);
    /// - on the grant the presented secret is keyed to, the read fails closed;
    /// - on a row that is NOT keyed by the current derivation (NULL, older or
    ///   newer version) the read fails closed for every secret, as before.
    #[tokio::test]
    async fn corrupt_grant_denies_unless_it_is_keyed_to_another_secret() {
        for how in CORRUPTIONS {
            for victim_key in [
                VictimKey::Current,
                VictimKey::Null,
                VictimKey::OlderVersion,
                VictimKey::NewerVersion,
            ] {
                let case = format!("{how} / {victim_key:?}");
                let mut fx = Fixture::new().await;
                let author = agent(1);
                let (victim_secret, wanted_secret) = (secret(1), secret(2));
                let mut tx = fx.db.begin().await.unwrap();
                let victim = fx
                    .grant(
                        &mut tx,
                        &author,
                        CapAccess::Transferable {
                            secret: victim_secret,
                        },
                        Keying::Keyed,
                    )
                    .await;
                let wanted = fx
                    .grant(
                        &mut tx,
                        &author,
                        CapAccess::Transferable {
                            secret: wanted_secret,
                        },
                        Keying::Keyed,
                    )
                    .await;
                tx.commit().await.unwrap();

                let mut key = cap_grant_secret_key(&author, &victim_secret).to_vec();
                let stored_key = match victim_key {
                    VictimKey::Current => Some(key),
                    VictimKey::Null => None,
                    VictimKey::OlderVersion => {
                        key[0] = CAP_GRANT_SECRET_KEY_VERSION - 1;
                        Some(key)
                    }
                    VictimKey::NewerVersion => {
                        key[0] = CAP_GRANT_SECRET_KEY_VERSION + 1;
                        Some(key)
                    }
                };
                sqlx::query("UPDATE CapGrant SET elohim_secret_key = ? WHERE action_hash = ?")
                    .bind(stored_key)
                    .bind(victim.action.get_raw_36())
                    .execute(fx.db.pool())
                    .await
                    .unwrap();

                // Healthy, every keying reads the wanted grant for its secret.
                let healthy = keyed(&fx.db, &author, 1, Some(&wanted_secret))
                    .await
                    .unwrap();
                assert_eq!(
                    carrying(&healthy, &wanted_secret),
                    vec![wanted.entry.clone()]
                );

                corrupt_grant(&fx.db, &author, &victim, how).await;

                // The load-every-grant read: deny-all, whatever the keying.
                assert!(
                    reference(&fx.db, &author, 1).await.is_err(),
                    "{case}: the reference must deny"
                );
                // The corrupt grant's own secret: always denied.
                assert!(
                    keyed(&fx.db, &author, 1, Some(&victim_secret))
                        .await
                        .is_err(),
                    "{case}: the matched corrupt grant must fail closed"
                );
                // The unrelated secret.
                let unrelated = keyed(&fx.db, &author, 1, Some(&wanted_secret)).await;
                match victim_key {
                    VictimKey::Current => assert_eq!(
                        unrelated.unwrap(),
                        vec![wanted.entry.clone()],
                        "{case}: a corrupt grant keyed to another secret must not deny"
                    ),
                    _ => assert!(
                        unrelated.is_err(),
                        "{case}: an un-keyed corrupt grant must still fail closed"
                    ),
                }

                // History-dependence: the backfill cannot key a row it cannot
                // decode, so an un-keyed corrupt grant stays un-keyed, is
                // counted, and keeps denying.
                let report = fx
                    .db
                    .backfill_cap_grant_lookup_keys(8, Duration::ZERO)
                    .await
                    .unwrap();
                let unkeyed = fx.db.as_ref().count_cap_grants_unkeyed().await.unwrap();
                let unrelated = keyed(&fx.db, &author, 1, Some(&wanted_secret)).await;
                match victim_key {
                    VictimKey::Current => {
                        assert_eq!((report.left_unkeyed, unkeyed), (0, 0), "{case}");
                        assert!(unrelated.is_ok(), "{case}");
                    }
                    _ => {
                        assert_eq!((report.left_unkeyed, unkeyed), (1, 1), "{case}");
                        assert_eq!(report.secret_keys_filled, 0, "{case}");
                        assert!(
                            unrelated.is_err(),
                            "{case}: the backfill must not make a corrupt grant stop denying"
                        );
                    }
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Derivation version
    // -----------------------------------------------------------------------

    /// A stored key that is not of the current derivation is treated exactly
    /// like a missing key: the row is read for EVERY secret (the slow path), it
    /// is counted as un-keyed, and the backfill re-keys it — after which it is
    /// read only for its own secret.
    #[tokio::test]
    async fn key_of_another_derivation_version_is_read_like_null_and_rekeyed() {
        let author = agent(1);
        let (own, other) = (secret(1), secret(2));
        let current = cap_grant_secret_key(&author, &own).to_vec();
        let with_version = |v: u8| {
            let mut key = current.clone();
            key[0] = v;
            key
        };
        for (label, stale, read_as_unkeyed) in [
            ("NULL", None, true),
            ("older version", Some(with_version(0)), true),
            ("newer version", Some(with_version(2)), true),
            ("far newer version", Some(with_version(0xFF)), true),
            ("version byte only", Some(vec![1u8]), true),
            // Current version byte but the wrong width: the read cannot tell
            // these from another secret's key, so the grant is hidden (a denial,
            // never an authorisation) until the backfill re-keys it.
            ("truncated", Some(current[..20].to_vec()), false),
            ("empty", Some(Vec::new()), true),
            // Current version byte but one byte too long: the read cannot tell
            // it from another secret's key, so the grant is hidden (a denial,
            // never an authorisation) until the backfill re-keys it.
            (
                "over-long",
                Some([current.as_slice(), &[0u8]].concat()),
                false,
            ),
        ] {
            let mut fx = Fixture::new().await;
            let mut tx = fx.db.begin().await.unwrap();
            let grant = fx
                .grant(
                    &mut tx,
                    &author,
                    CapAccess::Transferable { secret: own },
                    Keying::Keyed,
                )
                .await;
            tx.commit().await.unwrap();
            sqlx::query("UPDATE CapGrant SET elohim_secret_key = ? WHERE action_hash = ?")
                .bind(stale)
                .bind(grant.action.get_raw_36())
                .execute(fx.db.pool())
                .await
                .unwrap();

            let db = &fx.db;
            assert_eq!(
                db.as_ref().count_cap_grants_unkeyed().await.unwrap(),
                1,
                "{label}: must count as un-keyed"
            );
            if read_as_unkeyed {
                // Read on the slow path: fetched whatever secret is presented,
                // and so still authorising its own secret.
                for probe in [own, other] {
                    assert_eq!(
                        keyed(db, &author, 1, Some(&probe)).await.unwrap(),
                        vec![grant.entry.clone()],
                        "{label}: must be read like an un-keyed row"
                    );
                }
            } else {
                assert!(keyed(db, &author, 1, Some(&own)).await.unwrap().is_empty());
            }

            let report = db
                .backfill_cap_grant_lookup_keys(8, Duration::ZERO)
                .await
                .unwrap();
            assert_eq!(counts(&report), (0, 1, 0), "{label}: must be re-keyed");
            assert_eq!(
                stored(db, &grant.action).await.1,
                Some(current.clone()),
                "{label}"
            );
            assert_eq!(db.as_ref().count_cap_grants_unkeyed().await.unwrap(), 0);
            assert_eq!(
                keyed(db, &author, 1, Some(&own)).await.unwrap(),
                vec![grant.entry.clone()]
            );
            assert!(keyed(db, &author, 1, Some(&other))
                .await
                .unwrap()
                .is_empty());
        }
    }

    // -----------------------------------------------------------------------
    // Malformed widths
    // -----------------------------------------------------------------------

    /// A hash or key column that is not 36 bytes makes the backfill skip the
    /// row — no panic, no key derived over malformed bytes — and leaves it
    /// un-keyed and counted. `HoloHash::from_raw_36` only `debug_assert`s its
    /// length, so without the explicit check this test panics in a debug build.
    #[tokio::test]
    async fn backfill_skips_rows_with_malformed_hash_widths() {
        let mut fx = Fixture::new().await;
        let author = agent(1);
        let t = |n| CapAccess::Transferable { secret: secret(n) };
        let mut tx = fx.db.begin().await.unwrap();
        let healthy = fx.grant(&mut tx, &author, t(1), Keying::Legacy).await;
        let short_author = fx.grant(&mut tx, &author, t(2), Keying::Legacy).await;
        let short_entry_hash = fx.grant(&mut tx, &author, t(3), Keying::Legacy).await;
        let short_prev_hash = fx.grant(&mut tx, &author, t(4), Keying::Legacy).await;
        let template = fx.grant(&mut tx, &author, t(5), Keying::Legacy).await;
        tx.commit().await.unwrap();
        let pool = fx.db.pool();

        // A 35-byte author, with the private entry present under those same 35
        // bytes so that nothing but the width check stands in the way.
        let author_35 = vec![0x51u8; 35];
        sqlx::query("UPDATE Action SET author = ? WHERE hash = ?")
            .bind(&author_35)
            .bind(short_author.action.get_raw_36())
            .execute(pool)
            .await
            .unwrap();
        sqlx::query("UPDATE PrivateEntry SET author = ? WHERE hash = ?")
            .bind(&author_35)
            .bind(short_author.entry_hash.get_raw_36())
            .execute(pool)
            .await
            .unwrap();
        // A 35-byte entry hash, again with the private entry moved to match.
        let entry_35 = vec![0x52u8; 35];
        sqlx::query("UPDATE Action SET entry_hash = ? WHERE hash = ?")
            .bind(&entry_35)
            .bind(short_entry_hash.action.get_raw_36())
            .execute(pool)
            .await
            .unwrap();
        sqlx::query("UPDATE PrivateEntry SET hash = ? WHERE hash = ?")
            .bind(&entry_35)
            .bind(short_entry_hash.entry_hash.get_raw_36())
            .execute(pool)
            .await
            .unwrap();
        // A 35-byte prev_hash.
        sqlx::query("UPDATE Action SET prev_hash = ? WHERE hash = ?")
            .bind(vec![0x53u8; 35])
            .bind(short_prev_hash.action.get_raw_36())
            .execute(pool)
            .await
            .unwrap();
        // A 35-byte action hash: a copy of a healthy grant action under a short
        // primary key, with its own index row.
        let hash_35 = vec![0x54u8; 35];
        sqlx::query(
            "INSERT INTO Action (hash, author, seq, prev_hash, timestamp, action_type,
                                 action_data, signature, entry_hash, private_entry,
                                 record_validity)
             SELECT ?, author, seq + 1000000, prev_hash, timestamp, action_type,
                    action_data, signature, entry_hash, private_entry, record_validity
               FROM Action WHERE hash = ?",
        )
        .bind(&hash_35)
        .bind(template.action.get_raw_36())
        .execute(pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO CapGrant (action_hash, cap_access, tag) VALUES (?, 1, 'short')")
            .bind(&hash_35)
            .execute(pool)
            .await
            .unwrap();

        let report = fx
            .db
            .backfill_cap_grant_lookup_keys(2, Duration::ZERO)
            .await
            .unwrap();
        // 6 rows; the 35-byte author is not written to `elohim_author`.
        assert_eq!(counts(&report), (5, 2, 4));
        assert_eq!(fx.db.as_ref().count_cap_grants_unkeyed().await.unwrap(), 4);

        let by = Some(author.get_raw_36().to_vec());
        let key = |n| Some(cap_grant_secret_key(&author, &secret(n)).to_vec());
        assert_eq!(stored(&fx.db, &healthy.action).await, (by.clone(), key(1)));
        assert_eq!(stored(&fx.db, &template.action).await, (by.clone(), key(5)));
        assert_eq!(stored(&fx.db, &short_author.action).await, (None, None));
        assert_eq!(
            stored(&fx.db, &short_entry_hash.action).await,
            (by.clone(), None)
        );
        assert_eq!(
            stored(&fx.db, &short_prev_hash.action).await,
            (by.clone(), None)
        );
        let short_hash_row: (Option<Vec<u8>>, Option<Vec<u8>>) = sqlx::query_as(
            "SELECT elohim_author, elohim_secret_key FROM CapGrant WHERE action_hash = ?",
        )
        .bind(&hash_35)
        .fetch_one(pool)
        .await
        .unwrap();
        assert_eq!(short_hash_row, (by, None));
    }

    // -----------------------------------------------------------------------
    // Convergence under failure
    // -----------------------------------------------------------------------

    const FAST: CapGrantBackfillConfig = CapGrantBackfillConfig {
        start_delay: Duration::ZERO,
        batch: 4,
        pause: Duration::ZERO,
        min_backoff: Duration::from_millis(1),
        max_backoff: Duration::from_millis(8),
    };

    fn busy() -> sqlx::Error {
        sqlx::Error::Protocol("injected: database is locked".into())
    }

    /// What `converge_cap_grant_lookup_keys` reported, flattened for asserting.
    #[derive(Debug, Default)]
    struct Seen {
        /// `(consecutive_failures, retry_in, progressed)` of each failed pass.
        failures: Vec<(u32, Duration, bool)>,
        /// `(report, unkeyed)` of the converged pass, if one was reported.
        converged: Option<(CapGrantBackfillReport, Option<u64>)>,
    }

    impl Seen {
        fn record(&mut self, event: CapGrantBackfillEvent<'_>) {
            match event {
                CapGrantBackfillEvent::PassFailed {
                    consecutive_failures,
                    retry_in,
                    progress,
                    ..
                } => self.failures.push((
                    consecutive_failures,
                    retry_in,
                    progress.authors_filled + progress.secret_keys_filled > 0,
                )),
                CapGrantBackfillEvent::Converged { report, unkeyed } => {
                    self.converged = Some((report, unkeyed));
                }
            }
        }
    }

    /// FAULT INJECTION: every third backfill write fails as a busy database
    /// would. The store still ends fully keyed, and because every failed pass
    /// had made progress the failure streak never grows past one — a store too
    /// busy for a clean pass is not penalised with ever-longer waits.
    #[tokio::test]
    async fn backfill_converges_when_every_third_write_is_busy() {
        let fx = random_population(0x00B5_B5B5, 240, Some(Keying::Legacy)).await;
        let db = &fx.db;
        let (no_author, no_key) = unkeyed_counts(db).await;
        assert!(no_author > 240 && no_key > 100);
        let before = assert_matches_reference(db, false, "before").await;

        let mut writes = 0u32;
        let mut fault = move || {
            writes += 1;
            if writes.is_multiple_of(3) {
                Err(busy())
            } else {
                Ok(())
            }
        };
        let mut seen = Seen::default();
        let report = db
            .converge_cap_grant_lookup_keys_with(FAST, &mut |e| seen.record(e), &mut fault)
            .await;

        assert!(seen.failures.len() > 30, "faults were injected: {seen:?}");
        for (streak, retry_in, progressed) in &seen.failures {
            assert!(progressed, "two of every three writes land");
            assert_eq!(*streak, 1, "progress resets the failure streak");
            assert_eq!(*retry_in, FAST.min_backoff);
        }
        let (final_report, unkeyed) = seen.converged.expect("must report convergence");
        assert_eq!(final_report, report);
        assert_eq!(unkeyed, Some(0));
        assert_eq!(
            (
                report.authors_filled as i64,
                report.secret_keys_filled as i64
            ),
            (no_author, no_key)
        );
        assert_eq!(report.left_unkeyed, 0);
        assert_eq!(unkeyed_counts(db).await, (0, 0));
        assert_eq!(
            assert_matches_reference(db, true, "after faulty backfill").await,
            before
        );
    }

    /// With no retry budget, a backfill that fails many times in a row without
    /// making any progress is still not abandoned: the wait doubles to the cap
    /// and stays there, and the store is keyed as soon as writes get through.
    #[tokio::test]
    async fn backfill_outlasts_a_long_run_of_failures_without_progress() {
        let fx = random_population(0x0000_F00D, 60, Some(Keying::Legacy)).await;
        let db = &fx.db;

        let mut calls = 0u32;
        let mut fault = move || {
            calls += 1;
            if calls <= 12 {
                Err(busy())
            } else {
                Ok(())
            }
        };
        let mut seen = Seen::default();
        let report = db
            .converge_cap_grant_lookup_keys_with(FAST, &mut |e| seen.record(e), &mut fault)
            .await;

        let streaks: Vec<u32> = seen.failures.iter().map(|f| f.0).collect();
        assert_eq!(streaks, (1..=12).collect::<Vec<_>>());
        let waits: Vec<u128> = seen.failures.iter().map(|f| f.1.as_millis()).collect();
        assert_eq!(waits, [1, 2, 4, 8, 8, 8, 8, 8, 8, 8, 8, 8]);
        assert!(seen.failures.iter().all(|f| !f.2));
        assert!(seen.converged.is_some());
        assert!(report.secret_keys_filled > 20);
        assert_eq!(unkeyed_counts(db).await, (0, 0));
    }

    /// The pool closing mid-pass ends the backfill quietly: whatever error the
    /// interrupted write produced is not reported as a failure, and nothing is
    /// retried against a closed store.
    #[tokio::test]
    async fn backfill_stops_without_reporting_when_the_pool_closes() {
        let fx = random_population(0x0000_C105, 120, Some(Keying::Legacy)).await;
        let db = fx.db.clone();
        let pool = db.pool().clone();

        let mut calls = 0u32;
        let mut fault = move || {
            calls += 1;
            if calls == 5 {
                // `close` marks the pool closed as soon as it is called.
                drop(pool.close());
                Err(busy())
            } else {
                Ok(())
            }
        };
        let mut seen = Seen::default();
        let report = db
            .converge_cap_grant_lookup_keys_with(FAST, &mut |e| seen.record(e), &mut fault)
            .await;

        assert!(db.pool().is_closed());
        assert!(seen.failures.is_empty(), "a closed pool is not a failure");
        assert!(seen.converged.is_none(), "and it did not converge");
        assert_eq!(report.authors_filled, 16, "four clean author batches");
    }

    // -----------------------------------------------------------------------
    // Upgrade, roll back, upgrade again
    // -----------------------------------------------------------------------

    fn upgrade_fixture_id() -> Dht {
        Dht::new(Arc::new(DnaHash::from_raw_36(vec![7u8; 36])))
    }

    /// Open the database file the way the PARENT revision does: the recorded
    /// migrations and the parent's own post-migration indexes, and nothing of
    /// this change — no lookup columns, no lookup index.
    async fn open_as_parent(dir: &std::path::Path) -> DbWrite<Dht> {
        use crate::DatabaseIdentifier;
        let id = upgrade_fixture_id();
        let pool = crate::connect_database(&dir.join(id.database_id()), Default::default())
            .await
            .unwrap();
        crate::migrator_for(crate::kind::DbKind::Dht)
            .run(&pool)
            .await
            .unwrap();
        crate::dht::ensure_sync_indexes(&pool).await.unwrap();
        crate::dht::ensure_chain_read_indexes(&pool).await.unwrap();
        DbWrite::new(pool, id)
    }

    /// Open the database file the way THIS revision does.
    async fn open_as_new(dir: &std::path::Path) -> DbWrite<Dht> {
        crate::open_db(dir, upgrade_fixture_id(), Default::default())
            .await
            .unwrap()
    }

    /// The reference's answer for every author and class: what the parent
    /// revision authorises from.
    async fn reference_snapshot(db: &DbWrite<Dht>) -> Vec<Vec<Entry>> {
        let mut all = Vec::new();
        for who in AUTHORS {
            for class in [0_i64, 1, 2] {
                all.push(reference(db, &agent(who), class).await.unwrap());
            }
        }
        all
    }

    /// UPGRADE / DOWNGRADE on a real file.
    ///
    /// 1. The parent revision creates the database and writes grants.
    /// 2. This revision opens it (columns and index appear), and backfills only
    ///    part of it before stopping.
    /// 3. The parent revision opens it again — a rollback — and writes more
    ///    grants with its three-column insert, and revokes grants this revision
    ///    had already keyed.
    /// 4. This revision opens it again and finishes the backfill.
    ///
    /// At every step the keyed read reaches the decisions of the reference,
    /// and the reference's own answers are untouched by opening or backfilling.
    #[tokio::test]
    async fn upgrade_rollback_upgrade_keeps_every_decision() {
        let dir = tempfile::tempdir().unwrap();
        let dir = dir.path();

        // 1. Parent creates and writes.
        let db = open_as_parent(dir).await;
        assert_eq!(
            cap_grant_shape(&db).await.0.len(),
            3,
            "the parent's CapGrant has no lookup columns"
        );
        let mut fx = Fixture { db, next_id: 1 };
        let first = random_population_into(&mut fx, 0x0000_0A01, 200, Some(Keying::Legacy)).await;
        let written_by_parent = reference_snapshot(&fx.db).await;
        fx.db.pool().close().await;

        // 2. This revision opens, and backfills partially.
        fx.db = open_as_new(dir).await;
        assert_eq!(cap_grant_shape(&fx.db).await.0.len(), 5);
        assert_eq!(reference_snapshot(&fx.db).await, written_by_parent);
        let matched = assert_matches_reference(&fx.db, false, "first new open").await;
        assert!(matched > 40);
        while fx.db.backfill_cap_grant_authors_batch(50).await.unwrap() > 0 {}
        let batch = fx
            .db
            .backfill_cap_grant_secret_keys_batch(None, 60)
            .await
            .unwrap();
        assert_eq!(batch.keyed, 60);
        assert!(unkeyed_counts(&fx.db).await.1 > 20, "only partly keyed");
        assert_eq!(
            assert_matches_reference(&fx.db, false, "partly backfilled").await,
            matched
        );
        assert_eq!(reference_snapshot(&fx.db).await, written_by_parent);
        // Grants this revision has keyed and that are still live.
        let keyed_hashes: Vec<Vec<u8>> = sqlx::query_scalar(
            "SELECT action_hash FROM CapGrant WHERE elohim_secret_key IS NOT NULL",
        )
        .fetch_all(fx.db.pool())
        .await
        .unwrap();
        let keyed_grants: Vec<&(u8, Put)> = first
            .iter()
            .filter(|(_, put)| keyed_hashes.iter().any(|h| h == put.action.get_raw_36()))
            .collect();
        assert!(keyed_grants.len() >= 25, "{}", keyed_grants.len());
        fx.db.pool().close().await;

        // 3. Rollback: the parent opens the same file, writes three-column
        //    rows, and revokes grants that carry a key it knows nothing about.
        fx.db = open_as_parent(dir).await;
        assert_eq!(
            cap_grant_shape(&fx.db).await.0.len(),
            5,
            "the parent leaves the columns alone"
        );
        assert_eq!(reference_snapshot(&fx.db).await, written_by_parent);
        random_population_into(&mut fx, 0x0000_0A02, 120, Some(Keying::Legacy)).await;
        let mut tx = fx.db.begin().await.unwrap();
        for (who, put) in keyed_grants.iter().take(25) {
            fx.delete(&mut tx, &agent(*who), put).await;
        }
        tx.commit().await.unwrap();
        let after_rollback = reference_snapshot(&fx.db).await;
        assert_ne!(after_rollback, written_by_parent);
        fx.db.pool().close().await;

        // 4. This revision opens again: mixed keyed and un-keyed rows, and
        //    keyed rows that have since been revoked.
        fx.db = open_as_new(dir).await;
        assert_eq!(reference_snapshot(&fx.db).await, after_rollback);
        let matched = assert_matches_reference(&fx.db, false, "second new open").await;
        let mut seen = Seen::default();
        let report = fx
            .db
            .converge_cap_grant_lookup_keys(FAST, &mut |e| seen.record(e))
            .await;
        assert!(seen.failures.is_empty() && seen.converged.is_some());
        assert!(report.authors_filled >= 120 && report.secret_keys_filled > 60);
        assert_eq!(unkeyed_counts(&fx.db).await, (0, 0));
        assert_eq!(
            assert_matches_reference(&fx.db, true, "fully backfilled").await,
            matched
        );
        assert_eq!(reference_snapshot(&fx.db).await, after_rollback);
        fx.db.pool().close().await;
    }
}
