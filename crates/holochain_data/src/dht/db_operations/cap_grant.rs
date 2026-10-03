//! `DbRead<Dht>` / `DbWrite<Dht>` API for the `CapGrant` table.

use super::super::inner::cap_grant;
use crate::handles::{DbRead, DbWrite};
use crate::kind::Dht;
use crate::models::dht::CapGrantRow;
use holo_hash::{ActionHash, AgentPubKey};
use holochain_integrity_types::capability::CapSecret;
use holochain_integrity_types::entry::Entry;
use std::time::{Duration, Instant};

/// What the capability-grant lookup-key backfill did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CapGrantBackfillReport {
    /// `CapGrant` rows whose `elohim_author` column was filled in.
    pub authors_filled: u64,
    /// Secret-bearing rows whose `elohim_secret_key` column was filled in.
    pub secret_keys_filled: u64,
    /// Secret-bearing rows examined by the last pass and left without a key
    /// because none could be derived (missing or undecodable private entry,
    /// undecodable or malformed action). They stay on the
    /// read-every-un-keyed-row path: correct, slow, and — if the row is corrupt
    /// rather than merely missing its entry — still failing every
    /// secret-bearing authorisation of their author closed.
    pub left_unkeyed: u64,
    /// The longest any single backfill write took from asking for the write
    /// lock to releasing it. It bounds how long the backfill ever held the
    /// database's one writer (the time spent waiting for the lock is included,
    /// so the true hold is no longer than this).
    pub max_write_hold: Duration,
}

impl CapGrantBackfillReport {
    /// Fold the outcome of one more pass into a running total.
    fn absorb(&mut self, pass: &CapGrantBackfillReport) {
        self.authors_filled += pass.authors_filled;
        self.secret_keys_filled += pass.secret_keys_filled;
        // Not a sum: each pass re-examines the rows the previous one left.
        self.left_unkeyed = pass.left_unkeyed;
        self.max_write_hold = self.max_write_hold.max(pass.max_write_hold);
    }

    fn made_progress(&self) -> bool {
        self.authors_filled > 0 || self.secret_keys_filled > 0
    }
}

/// How [`DbWrite::converge_cap_grant_lookup_keys`] paces itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapGrantBackfillConfig {
    /// Waited once before the first pass. The backfill is never urgent, and a
    /// store that has just been opened is at its busiest (and, in a process
    /// that opens a store and exits at once, about to be torn down).
    pub start_delay: Duration,
    /// Rows per write. A batch is the longest the backfill holds the writer.
    pub batch: u32,
    /// Slept between batches, so queued writers get the lock.
    pub pause: Duration,
    /// Wait before retrying after the first failed pass of a streak.
    pub min_backoff: Duration,
    /// The wait doubles with each consecutive failure up to this cap.
    pub max_backoff: Duration,
}

/// Something [`DbWrite::converge_cap_grant_lookup_keys`] reports as it runs.
#[derive(Debug)]
pub enum CapGrantBackfillEvent<'a> {
    /// A pass failed and will be retried after `retry_in`.
    PassFailed {
        /// Why the pass stopped.
        error: &'a sqlx::Error,
        /// Failed passes since the last one that made progress, this included.
        consecutive_failures: u32,
        /// How long until the next pass.
        retry_in: Duration,
        /// What this pass filled in before it failed.
        progress: CapGrantBackfillReport,
        /// Secret-bearing rows still without a current key, if it could be
        /// counted.
        unkeyed: Option<u64>,
    },
    /// A pass ran to the end: every row that can be keyed is keyed.
    Converged {
        /// Everything filled in across all passes.
        report: CapGrantBackfillReport,
        /// Secret-bearing rows still without a current key — the rows no key
        /// could be derived for — if it could be counted.
        unkeyed: Option<u64>,
    },
}

/// One batch of the `elohim_secret_key` backfill.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct CapGrantKeyBatch {
    /// Rows examined.
    pub scanned: u64,
    /// Rows keyed.
    pub keyed: u64,
    /// Where the next batch starts; `None` when the scan reached the end.
    pub next_cursor: Option<Vec<u8>>,
    /// How long the batch's write transaction was open.
    pub write_hold: Duration,
}

/// Called before every backfill write; an `Err` is returned in place of the
/// write. Production passes [`no_fault`]; tests inject busy errors.
pub(crate) type BackfillFault<'a> = &'a mut (dyn FnMut() -> sqlx::Result<()> + Send);

pub(crate) fn no_fault() -> sqlx::Result<()> {
    Ok(())
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

    /// Fill `CapGrant.elohim_author` on up to `limit` rows that lack it;
    /// returns the number filled. One bounded statement.
    pub(crate) async fn backfill_cap_grant_authors_batch(&self, limit: u32) -> sqlx::Result<u64> {
        cap_grant::backfill_cap_grant_authors(self.pool(), limit).await
    }

    /// Key up to `limit` secret-bearing rows that have no key of the current
    /// derivation, starting after `cursor`.
    ///
    /// The rows are read and their keys derived WITHOUT the write lock; only
    /// the `limit`-bounded run of single-row updates holds it.
    #[cfg(test)]
    pub(crate) async fn backfill_cap_grant_secret_keys_batch(
        &self,
        cursor: Option<&[u8]>,
        limit: u32,
    ) -> sqlx::Result<CapGrantKeyBatch> {
        self.backfill_cap_grant_secret_keys_batch_with(cursor, limit, &mut no_fault)
            .await
    }

    async fn backfill_cap_grant_secret_keys_batch_with(
        &self,
        cursor: Option<&[u8]>,
        limit: u32,
        fault: BackfillFault<'_>,
    ) -> sqlx::Result<CapGrantKeyBatch> {
        let rows = {
            let mut conn = self.as_ref().timed_conn().await?;
            cap_grant::get_cap_grants_missing_secret_key(&mut *conn, cursor, limit).await?
        };
        let scanned = rows.len() as u64;
        // The largest hash read, whatever order the rows came back in.
        let next_cursor = rows.iter().map(|row| &row.action.hash).max().cloned();
        let keys: Vec<_> = rows
            .into_iter()
            .filter_map(|row| {
                let action_hash = row.action.hash.clone();
                cap_grant::derive_cap_grant_secret_key(row).map(|key| (action_hash, key))
            })
            .collect();

        let mut keyed = 0;
        let mut write_hold = Duration::ZERO;
        if !keys.is_empty() {
            fault()?;
            let started = Instant::now();
            let mut tx = self.begin().await?;
            for (action_hash, key) in &keys {
                keyed +=
                    cap_grant::set_cap_grant_secret_key(tx.conn_mut(), action_hash, key).await?;
            }
            tx.commit().await?;
            write_hold = started.elapsed();
        }
        Ok(CapGrantKeyBatch {
            scanned,
            keyed,
            next_cursor,
            write_hold,
        })
    }

    /// One pass of the backfill, recording into `report` as it goes so that
    /// what was done before a failure is not lost.
    async fn backfill_cap_grant_pass(
        &self,
        batch: u32,
        pause: Duration,
        report: &mut CapGrantBackfillReport,
        fault: BackfillFault<'_>,
    ) -> sqlx::Result<()> {
        let batch = batch.max(1);

        while !self.pool().is_closed() {
            fault()?;
            let started = Instant::now();
            let filled = self.backfill_cap_grant_authors_batch(batch).await?;
            report.max_write_hold = report.max_write_hold.max(started.elapsed());
            if filled == 0 {
                break;
            }
            report.authors_filled += filled;
            tokio::time::sleep(pause).await;
        }

        let mut cursor: Option<Vec<u8>> = None;
        while !self.pool().is_closed() {
            let step = self
                .backfill_cap_grant_secret_keys_batch_with(cursor.as_deref(), batch, &mut *fault)
                .await?;
            report.secret_keys_filled += step.keyed;
            report.left_unkeyed += step.scanned - step.keyed;
            report.max_write_hold = report.max_write_hold.max(step.write_hold);
            match step.next_cursor {
                Some(next) => cursor = Some(next),
                None => break,
            }
            tokio::time::sleep(pause).await;
        }
        Ok(())
    }

    /// Run one pass of the lookup-column backfill over rows that predate the
    /// columns, or whose key is of another derivation version.
    ///
    /// The authorisation read is correct whether or not this has run — a row
    /// with no `elohim_author` or no current `elohim_secret_key` is still read,
    /// on the path every row took before the columns existed — so this only
    /// makes it cheaper, and may be interrupted at any point.
    ///
    /// - **Idempotent and resumable.** Finished rows are no longer selected, so
    ///   a later pass picks up whatever is left, including rows written by an
    ///   older binary after a rollback. A second pass over a finished store
    ///   only re-examines the rows that cannot be keyed.
    /// - **Bounded writes.** `elohim_author` is filled by one `UPDATE` per
    ///   `batch` rows; `elohim_secret_key` is derived outside the write lock
    ///   and written `batch` rows per transaction. `pause` is slept between
    ///   batches so other writers on the database get the lock.
    /// - **Fail-safe.** A row whose key cannot be derived with certainty is
    ///   skipped and stays un-keyed.
    ///
    /// Stops early, returning what it did, if the pool is closed. An error
    /// loses nothing that was already written; use
    /// [`converge_cap_grant_lookup_keys`](Self::converge_cap_grant_lookup_keys)
    /// to keep going until the job is done.
    pub async fn backfill_cap_grant_lookup_keys(
        &self,
        batch: u32,
        pause: Duration,
    ) -> sqlx::Result<CapGrantBackfillReport> {
        let mut report = CapGrantBackfillReport::default();
        self.backfill_cap_grant_pass(batch, pause, &mut report, &mut no_fault)
            .await?;
        Ok(report)
    }

    /// Run the lookup-column backfill until it has converged or the pool is
    /// closed, whichever comes first.
    ///
    /// A pass that fails — typically a write that waited out the busy timeout
    /// behind other agents' writes on a busy store — is retried after a
    /// backoff that doubles from `min_backoff` to `max_backoff`. There is no
    /// retry budget: a store that is too busy for one uninterrupted pass still
    /// converges, because every pass keeps what it wrote and the streak of
    /// failures (and with it the backoff) is reset whenever a pass makes
    /// progress. A failure caused by the pool closing is not reported.
    ///
    /// The number of secret-bearing rows still without a current key is
    /// published as the `hc.db.cap_grant.unkeyed` gauge (labelled with the
    /// database's `kind` and `id`, one series per DNA) before the first pass
    /// and after every pass, so an incomplete backfill is a scrape rather than
    /// a log line. `on_event` receives each failure and the final outcome.
    ///
    /// Returns everything filled in. If the pool closed first, that is what
    /// had been filled in by then.
    pub async fn converge_cap_grant_lookup_keys(
        &self,
        config: CapGrantBackfillConfig,
        on_event: &mut (dyn FnMut(CapGrantBackfillEvent<'_>) + Send),
    ) -> CapGrantBackfillReport {
        self.converge_cap_grant_lookup_keys_with(config, on_event, &mut no_fault)
            .await
    }

    pub(crate) async fn converge_cap_grant_lookup_keys_with(
        &self,
        config: CapGrantBackfillConfig,
        on_event: &mut (dyn FnMut(CapGrantBackfillEvent<'_>) + Send),
        fault: BackfillFault<'_>,
    ) -> CapGrantBackfillReport {
        let gauge = crate::metrics::create_cap_grant_unkeyed_metric(self.identifier());
        let mut total = CapGrantBackfillReport::default();
        let mut consecutive_failures: u32 = 0;

        if !config.start_delay.is_zero() {
            tokio::select! {
                _ = tokio::time::sleep(config.start_delay) => {}
                _ = self.pool().close_event() => return total,
            }
        }

        if let Ok(unkeyed) = self.as_ref().count_cap_grants_unkeyed().await {
            gauge.record(unkeyed);
        }

        loop {
            if self.pool().is_closed() {
                return total;
            }
            let mut pass = CapGrantBackfillReport::default();
            let outcome = self
                .backfill_cap_grant_pass(config.batch, config.pause, &mut pass, &mut *fault)
                .await;
            total.absorb(&pass);

            // A pool closed mid-pass is the store going away, not a failure.
            if self.pool().is_closed() {
                return total;
            }
            let unkeyed = self.as_ref().count_cap_grants_unkeyed().await.ok();
            if let Some(unkeyed) = unkeyed {
                gauge.record(unkeyed);
            }

            let error = match outcome {
                Ok(()) => {
                    on_event(CapGrantBackfillEvent::Converged {
                        report: total,
                        unkeyed,
                    });
                    return total;
                }
                Err(error) => error,
            };

            if pass.made_progress() {
                consecutive_failures = 0;
            }
            consecutive_failures = consecutive_failures.saturating_add(1);
            let retry_in = backoff(config, consecutive_failures);
            on_event(CapGrantBackfillEvent::PassFailed {
                error: &error,
                consecutive_failures,
                retry_in,
                progress: pass,
                unkeyed,
            });

            tokio::select! {
                _ = tokio::time::sleep(retry_in) => {}
                _ = self.pool().close_event() => return total,
            }
        }
    }
}

/// `min_backoff` doubled once per consecutive failure after the first, capped
/// at `max_backoff`.
fn backoff(config: CapGrantBackfillConfig, consecutive_failures: u32) -> Duration {
    let doublings = consecutive_failures.saturating_sub(1).min(31);
    config
        .min_backoff
        .saturating_mul(1u32 << doublings)
        .min(config.max_backoff)
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

    /// Secret-bearing `CapGrant` rows that have no lookup key of the current
    /// derivation.
    ///
    /// Zero on a store the backfill has finished with, unless it holds rows no
    /// key could be derived for. Each such row is read by every secret-bearing
    /// authorisation of its author.
    pub async fn count_cap_grants_unkeyed(&self) -> sqlx::Result<u64> {
        let mut conn = self.timed_conn().await?;
        cap_grant::count_cap_grants_unkeyed(&mut *conn).await
    }

    /// The author's live capability-grant entries of one access class, in
    /// source-chain (`Action.seq`) order.
    ///
    /// "Live" means: authored by `author`, of the given `cap_access` class, the
    /// grant entry is resolvable, and the author has neither updated nor
    /// deleted that entry.
    ///
    /// With `secret = Some(_)` the read is narrowed to the grants that can
    /// carry that secret — those keyed to it, plus any not keyed by the current
    /// derivation — and every one of them is returned. The narrowing is a
    /// filter only: the caller must still compare each returned grant's real
    /// secret (`CapGrant::is_valid` does). With `secret = None` every live
    /// grant of the class is returned.
    ///
    /// This is the authorisation read behind `DhtStoreRead::valid_cap_grants`
    /// in `holochain_state`; it costs one query, and on a store whose lookup
    /// columns are filled in that query reads only the grants sharing the
    /// presented secret — independent of how many other grants the author, or
    /// any other agent sharing the database, has ever committed.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_from_the_floor_to_the_cap() {
        let config = CapGrantBackfillConfig {
            start_delay: Duration::ZERO,
            batch: 1,
            pause: Duration::ZERO,
            min_backoff: Duration::from_secs(5),
            max_backoff: Duration::from_secs(300),
        };
        let waits: Vec<u64> = [1, 2, 3, 4, 5, 6, 7, 8, 1_000, u32::MAX]
            .into_iter()
            .map(|n| backoff(config, n).as_secs())
            .collect();
        assert_eq!(waits, [5, 10, 20, 40, 80, 160, 300, 300, 300, 300]);
    }
}
