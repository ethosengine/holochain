//! `DbRead<Dht>` / `DbWrite<Dht>` API for the `CapGrant` table.

use super::super::inner::cap_grant;
use crate::handles::{DbRead, DbWrite};
use crate::kind::Dht;
use crate::models::dht::CapGrantRow;
use holo_hash::{ActionHash, AgentPubKey};
use holochain_integrity_types::capability::CapSecret;
use holochain_integrity_types::entry::Entry;

/// What a [`DbWrite::backfill_cap_grant_lookup_keys`] pass did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CapGrantBackfillReport {
    /// `CapGrant` rows whose `author` column was filled in.
    pub authors_filled: u64,
    /// Secret-bearing rows whose `secret_key` column was filled in.
    pub secret_keys_filled: u64,
    /// Secret-bearing rows examined and left without a `secret_key` because no
    /// key could be derived (missing or undecodable private entry, undecodable
    /// action). They stay on the read-every-un-keyed-row path, which is correct.
    pub left_unkeyed: u64,
}

/// One batch of the `secret_key` backfill.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct CapGrantKeyBatch {
    /// Rows examined.
    pub scanned: u64,
    /// Rows keyed.
    pub keyed: u64,
    /// Where the next batch starts; `None` when the scan reached the end.
    pub next_cursor: Option<Vec<u8>>,
}

impl DbWrite<Dht> {
    /// Insert the `CapGrant` index row for a grant action of `author`.
    ///
    /// `secret` is the grant's secret for a `Transferable` / `Assigned` grant
    /// and `None` for an `Unrestricted` one. The secret itself is not stored:
    /// the row carries [`cap_grant_secret_key`](crate::dht::cap_grant_secret_key).
    pub async fn insert_cap_grant(
        &self,
        action_hash: &ActionHash,
        author: &AgentPubKey,
        cap_access: i64,
        secret: Option<&CapSecret>,
        tag: Option<&str>,
    ) -> sqlx::Result<()> {
        cap_grant::insert_cap_grant(self.pool(), action_hash, author, cap_access, secret, tag).await
    }

    /// Fill `CapGrant.author` on up to `limit` rows that lack it; returns the
    /// number filled. One bounded statement.
    pub(crate) async fn backfill_cap_grant_authors_batch(&self, limit: u32) -> sqlx::Result<u64> {
        cap_grant::backfill_cap_grant_authors(self.pool(), limit).await
    }

    /// Key up to `limit` secret-bearing rows that have no `secret_key`, starting
    /// after `cursor`.
    ///
    /// The rows are read and their keys derived WITHOUT the write lock; only
    /// the `limit`-bounded run of single-row updates holds it.
    pub(crate) async fn backfill_cap_grant_secret_keys_batch(
        &self,
        cursor: Option<&[u8]>,
        limit: u32,
    ) -> sqlx::Result<CapGrantKeyBatch> {
        let rows = {
            let mut conn = self.as_ref().timed_conn().await?;
            cap_grant::get_cap_grants_missing_secret_key(&mut *conn, cursor, limit).await?
        };
        let scanned = rows.len() as u64;
        let next_cursor = rows.last().map(|row| row.action.hash.clone());
        let keys: Vec<_> = rows
            .into_iter()
            .filter_map(|row| {
                let action_hash = row.action.hash.clone();
                cap_grant::derive_cap_grant_secret_key(row).map(|key| (action_hash, key))
            })
            .collect();

        let mut keyed = 0;
        if !keys.is_empty() {
            let mut tx = self.begin().await?;
            for (action_hash, key) in &keys {
                keyed +=
                    cap_grant::set_cap_grant_secret_key(tx.conn_mut(), action_hash, key).await?;
            }
            tx.commit().await?;
        }
        Ok(CapGrantKeyBatch {
            scanned,
            keyed,
            next_cursor,
        })
    }

    /// Fill in the `CapGrant` lookup columns on rows that predate them.
    ///
    /// The authorisation read is correct whether or not this has run — a row
    /// with a NULL `author` or `secret_key` is still read, on the path every
    /// row took before the columns existed — so this only makes it cheaper, and
    /// may be interrupted at any point.
    ///
    /// - **Idempotent and resumable.** Finished rows are no longer selected, so
    ///   a later pass picks up whatever is left, including rows written by an
    ///   older binary after a rollback. A second pass over a finished store
    ///   only re-examines the rows that cannot be keyed.
    /// - **Bounded writes.** `author` is filled by one `UPDATE` per `batch`
    ///   rows; `secret_key` is derived outside the write lock and written
    ///   `batch` rows per transaction. `pause` is slept between batches so
    ///   other writers on the database get the lock.
    /// - **Fail-safe.** A row whose key cannot be derived with certainty is
    ///   skipped and stays NULL.
    ///
    /// Stops early, returning what it did, if the pool is closed.
    pub async fn backfill_cap_grant_lookup_keys(
        &self,
        batch: u32,
        pause: std::time::Duration,
    ) -> sqlx::Result<CapGrantBackfillReport> {
        let batch = batch.max(1);
        let mut report = CapGrantBackfillReport::default();

        while !self.pool().is_closed() {
            let filled = self.backfill_cap_grant_authors_batch(batch).await?;
            if filled == 0 {
                break;
            }
            report.authors_filled += filled;
            tokio::time::sleep(pause).await;
        }

        let mut cursor: Option<Vec<u8>> = None;
        while !self.pool().is_closed() {
            let step = self
                .backfill_cap_grant_secret_keys_batch(cursor.as_deref(), batch)
                .await?;
            report.secret_keys_filled += step.keyed;
            report.left_unkeyed += step.scanned - step.keyed;
            match step.next_cursor {
                Some(next) => cursor = Some(next),
                None => break,
            }
            tokio::time::sleep(pause).await;
        }
        Ok(report)
    }
}

impl DbRead<Dht> {
    pub async fn get_cap_grants_by_access(
        &self,
        author: AgentPubKey,
        cap_access: i64,
    ) -> sqlx::Result<Vec<CapGrantRow>> {
        let mut conn = self.timed_conn().await?;
        cap_grant::get_cap_grants_by_access(&mut *conn, author, cap_access).await
    }

    /// The author's live capability-grant entries of one access class, in
    /// source-chain (`Action.seq`) order.
    ///
    /// "Live" means: authored by `author`, of the given `cap_access` class, the
    /// grant entry is resolvable, and the author has neither updated nor
    /// deleted that entry.
    ///
    /// With `secret = Some(_)` the read is narrowed to the grants that can
    /// carry that secret — those keyed to it, plus any not yet keyed — and
    /// every one of them is returned. The narrowing is a filter only: the
    /// caller must still compare each returned grant's real secret
    /// (`CapGrant::is_valid` does). With `secret = None` every live grant of
    /// the class is returned.
    ///
    /// This is the authorisation read behind `DhtStoreRead::valid_cap_grants`
    /// in `holochain_state`; it costs one query, and on a store whose lookup
    /// columns are filled in that query reads only the matching grants —
    /// independent of how many grants the author, or any other agent sharing
    /// the database, has ever committed.
    pub async fn get_live_cap_grant_entries(
        &self,
        author: AgentPubKey,
        cap_access: i64,
        secret: Option<&CapSecret>,
    ) -> sqlx::Result<Vec<Entry>> {
        let mut conn = self.timed_conn().await?;
        cap_grant::get_live_cap_grant_entries(&mut *conn, author, cap_access, secret).await
    }

    pub async fn get_cap_grants_by_tag(
        &self,
        author: AgentPubKey,
        tag: &str,
    ) -> sqlx::Result<Vec<CapGrantRow>> {
        let mut conn = self.timed_conn().await?;
        cap_grant::get_cap_grants_by_tag(&mut *conn, author, tag).await
    }
}
