//! Free-standing operations against the `SliceHash` table.
//!
//! K2's gossip layer hashes contiguous arc slices and stores the resulting
//! hash per `(arc_start, arc_end, slice_index)`. Re-storing the same slice
//! replaces the prior hash (the table's PK has `ON CONFLICT REPLACE`).

use crate::models::dht::SliceHashIndexedRow;
use sqlx::{Executor, Sqlite};

/// Insert or replace the slice hash for `(arc_start, arc_end, slice_index)`,
/// skipping the write when the stored hash is already byte-identical.
pub(crate) async fn insert_slice_hash<'e, E>(
    executor: E,
    arc_start: u32,
    arc_end: u32,
    slice_index: u64,
    hash: &[u8],
) -> sqlx::Result<()>
where
    E: Executor<'e, Database = Sqlite>,
{
    // ELOHIM PATCH (ported from 0.6.3 da823fc6a): kitsune2's historical catch-up
    // re-stores byte-identical slice hashes every cycle. Skip the write when the
    // stored hash already matches; a real change still replaces (PK ON CONFLICT REPLACE).
    sqlx::query(
        "INSERT INTO SliceHash (arc_start, arc_end, slice_index, hash)
         SELECT ?1, ?2, ?3, ?4
         WHERE NOT EXISTS (
           SELECT 1 FROM SliceHash
           WHERE arc_start = ?1 AND arc_end = ?2 AND slice_index = ?3 AND hash = ?4
         )",
    )
    .bind(arc_start as i64)
    .bind(arc_end as i64)
    .bind(slice_index as i64)
    .bind(hash)
    .execute(executor)
    .await?;
    Ok(())
}

/// Number of stored slices for the arc, or 0 if none.
///
/// K2 assigns slice indices consecutively from 0, so the count is the
/// highest stored index + 1. This matches the kitsune2 reference op-store,
/// which returns `highest_stored_id + 1`. A plain `MAX(slice_index)` would
/// undercount by one and could not tell "no slices" apart from "one slice
/// at index 0", so read the nullable `MAX` and add one only when a row
/// exists.
pub(crate) async fn slice_hash_count<'e, E>(
    executor: E,
    arc_start: u32,
    arc_end: u32,
) -> sqlx::Result<u64>
where
    E: Executor<'e, Database = Sqlite>,
{
    let (max_index,): (Option<i64>,) = sqlx::query_as(
        "SELECT MAX(slice_index) FROM SliceHash
         WHERE arc_start = ? AND arc_end = ?",
    )
    .bind(arc_start as i64)
    .bind(arc_end as i64)
    .fetch_one(executor)
    .await?;
    Ok(max_index.map_or(0, |m| m.max(0) as u64 + 1))
}

/// Fetch a single stored slice hash, if any.
pub(crate) async fn get_slice_hash<'e, E>(
    executor: E,
    arc_start: u32,
    arc_end: u32,
    slice_index: u64,
) -> sqlx::Result<Option<Vec<u8>>>
where
    E: Executor<'e, Database = Sqlite>,
{
    let row: Option<(Vec<u8>,)> = sqlx::query_as(
        "SELECT hash FROM SliceHash
         WHERE arc_start = ? AND arc_end = ? AND slice_index = ?",
    )
    .bind(arc_start as i64)
    .bind(arc_end as i64)
    .bind(slice_index as i64)
    .fetch_optional(executor)
    .await?;
    Ok(row.map(|(h,)| h))
}

/// Fetch every `(slice_index, hash)` pair stored for the arc, in no
/// particular order. K2's callers don't rely on ordering here.
pub(crate) async fn get_slice_hashes<'e, E>(
    executor: E,
    arc_start: u32,
    arc_end: u32,
) -> sqlx::Result<Vec<SliceHashIndexedRow>>
where
    E: Executor<'e, Database = Sqlite>,
{
    sqlx::query_as::<_, SliceHashIndexedRow>(
        "SELECT slice_index, hash FROM SliceHash
         WHERE arc_start = ? AND arc_end = ?",
    )
    .bind(arc_start as i64)
    .bind(arc_end as i64)
    .fetch_all(executor)
    .await
}

#[cfg(test)]
mod tests {
    use crate::kind::Dht;
    use crate::test_open_db;
    use holo_hash::DnaHash;
    use std::sync::Arc;

    fn dht_id() -> Dht {
        Dht::new(Arc::new(DnaHash::from_raw_36(vec![0u8; 36])))
    }

    /// The change-check must be invisible to callers: a redundant re-store is a
    /// safe no-op, a real change still replaces, and neither path accumulates
    /// duplicate rows for the same `(arc_start, arc_end, slice_index)`.
    #[tokio::test]
    async fn slice_hash_change_check_updates_and_is_idempotent() {
        let db = test_open_db(dht_id()).await.unwrap();
        let (arc_start, arc_end, slice_index) = (0u32, 100u32, 7u64);
        let h1 = vec![1u8; 32];
        let h2 = vec![2u8; 32];

        // First store.
        db.insert_slice_hash(arc_start, arc_end, slice_index, &h1)
            .await
            .unwrap();
        assert_eq!(
            db.as_ref()
                .get_slice_hash(arc_start, arc_end, slice_index)
                .await
                .unwrap(),
            Some(h1.clone())
        );
        assert_eq!(
            db.as_ref()
                .get_slice_hashes(arc_start, arc_end)
                .await
                .unwrap()
                .len(),
            1
        );

        // Redundant re-store of the identical hash: no-op, still exactly one row.
        db.insert_slice_hash(arc_start, arc_end, slice_index, &h1)
            .await
            .unwrap();
        assert_eq!(
            db.as_ref()
                .get_slice_hash(arc_start, arc_end, slice_index)
                .await
                .unwrap(),
            Some(h1.clone()),
            "a redundant re-store must not alter the stored hash"
        );
        assert_eq!(
            db.as_ref()
                .get_slice_hashes(arc_start, arc_end)
                .await
                .unwrap()
                .len(),
            1,
            "a redundant re-store must not accumulate rows"
        );

        // A real change is never swallowed by the change-check.
        db.insert_slice_hash(arc_start, arc_end, slice_index, &h2)
            .await
            .unwrap();
        assert_eq!(
            db.as_ref()
                .get_slice_hash(arc_start, arc_end, slice_index)
                .await
                .unwrap(),
            Some(h2),
            "a changed hash must replace the stored one"
        );
        assert_eq!(
            db.as_ref()
                .get_slice_hashes(arc_start, arc_end)
                .await
                .unwrap()
                .len(),
            1,
            "a real change must replace, not duplicate"
        );
    }
}
