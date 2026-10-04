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
    /// The longest any batch waited for the database's write lock.
    pub max_lock_wait: Duration,
    /// The longest any batch HELD the write lock: from acquiring it to
    /// committing. This is the longest the backfill ever stood in the way of
    /// another writer.
    pub max_write_hold: Duration,
    /// How many times the backfill lengthened its pause because a batch had
    /// waited for, or held, the write lock for longer than
    /// [`CapGrantBackfillConfig::yield_above`].
    pub yields: u64,
}

impl CapGrantBackfillReport {
    /// Fold the outcome of one more pass into a running total.
    fn absorb(&mut self, pass: &CapGrantBackfillReport) {
        self.authors_filled += pass.authors_filled;
        self.secret_keys_filled += pass.secret_keys_filled;
        // Not a sum: each pass re-examines the rows the previous one left.
        self.left_unkeyed = pass.left_unkeyed;
        self.max_lock_wait = self.max_lock_wait.max(pass.max_lock_wait);
        self.max_write_hold = self.max_write_hold.max(pass.max_write_hold);
        self.yields += pass.yields;
    }

    fn made_progress(&self) -> bool {
        self.authors_filled > 0 || self.secret_keys_filled > 0
    }
}

/// How [`DbWrite::converge_cap_grant_lookup_keys`] paces itself.
///
/// The backfill is strictly background work. Rows it has not reached cost what
/// they cost before the lookup columns existed, so there is never a reason for
/// it to compete with anything: it writes little at a time and gets out of the
/// way as soon as it sees it is in the way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapGrantBackfillConfig {
    /// Waited once before the first pass.
    pub start_delay: Duration,
    /// Rows per write. Each batch is ONE statement, so this is what bounds how
    /// long the database's single writer is ever held.
    pub batch: u32,
    /// Slept between batches, with no connection held.
    pub pause: Duration,
    /// When a batch waited for the write lock, or held it, for longer than
    /// this, something else wants the database: the pause is doubled.
    pub yield_above: Duration,
    /// The pause doubles up to this, and falls back to `pause` as soon as a
    /// batch goes through without contention.
    pub max_pause: Duration,
    /// Wait before retrying after the first failed pass of a streak.
    pub min_backoff: Duration,
    /// The wait doubles with each consecutive failure up to this cap.
    pub max_backoff: Duration,
}

/// Something [`DbWrite::converge_cap_grant_lookup_keys`] reports as it runs.
#[derive(Debug)]
pub enum CapGrantBackfillEvent {
    /// The start delay is over and the first pass is about to begin.
    Started {
        /// Secret-bearing rows without a current key, if it could be counted.
        unkeyed: Option<u64>,
    },
    /// A batch waited for, or held, the write lock for longer than
    /// [`CapGrantBackfillConfig::yield_above`]; the pause was lengthened.
    Yielded {
        /// How long the batch waited for the write lock.
        lock_wait: Duration,
        /// How long the batch held the write lock.
        write_hold: Duration,
        /// The pause now in force.
        pause: Duration,
    },
    /// A pass failed and will be retried after `retry_in`.
    PassFailed {
        /// Why the pass stopped.
        error: String,
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

/// One batch of the backfill walk.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct CapGrantFillBatch {
    /// Rows whose author was filled in.
    pub authors: u64,
    /// Rows whose key was filled in.
    pub keyed: u64,
    /// Rows that needed a key and for which none could be derived.
    pub left_unkeyed: u64,
    /// Where the next batch starts; `None` when the walk reached the end.
    pub next_cursor: Option<Vec<u8>>,
    /// How long the batch waited for the write lock.
    pub lock_wait: Duration,
    /// How long the batch held the write lock.
    pub write_hold: Duration,
}

/// What reports events to the caller of the convergence driver.
pub(crate) type BackfillObserver<'a> = &'a mut (dyn FnMut(CapGrantBackfillEvent) + Send);

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

    /// One batch of the backfill walk: fill the author and the key on up to
    /// `limit` rows after `cursor` that lack either.
    #[cfg(test)]
    pub(crate) async fn backfill_cap_grant_batch(
        &self,
        cursor: Option<&[u8]>,
        limit: u32,
    ) -> sqlx::Result<CapGrantFillBatch> {
        self.backfill_cap_grant_batch_with(cursor.map(<[u8]>::to_vec), limit, &mut no_fault)
            .await
    }

    /// See [`backfill_cap_grant_batch`](Self::backfill_cap_grant_batch).
    ///
    /// The rows are read, and their keys derived, on a read connection that is
    /// returned to the pool before anything is written. The write is a single
    /// statement inside `BEGIN IMMEDIATE … COMMIT`, on a connection that is
    /// returned to the pool before this function returns: no connection, and
    /// no lock, outlives the batch.
    async fn backfill_cap_grant_batch_with(
        &self,
        cursor: Option<Vec<u8>>,
        limit: u32,
        fault: BackfillFault<'_>,
    ) -> sqlx::Result<CapGrantFillBatch> {
        let rows = {
            let mut conn = self.as_ref().timed_conn().await?;
            cap_grant::get_cap_grants_to_backfill(&mut *conn, cursor, limit).await?
        };
        // The largest hash read, whatever order the rows came back in.
        let next_cursor = rows.iter().map(|row| &row.live.action.hash).max().cloned();
        let fills: Vec<_> = rows
            .into_iter()
            .map(cap_grant::plan_cap_grant_fill)
            .collect();

        let mut batch = CapGrantFillBatch {
            authors: fills.iter().filter(|f| f.author.is_some()).count() as u64,
            keyed: fills.iter().filter(|f| f.secret_key.is_some()).count() as u64,
            left_unkeyed: fills
                .iter()
                .filter(|f| f.wanted_key && f.secret_key.is_none())
                .count() as u64,
            next_cursor,
            ..Default::default()
        };
        if batch.authors == 0 && batch.keyed == 0 {
            return Ok(batch);
        }

        fault()?;
        // `BEGIN IMMEDIATE` takes the write lock up front, so the wait for it
        // and the time it is held are measured apart. The transaction guard
        // rolls back if this future is dropped part-way.
        let asked = Instant::now();
        let mut tx = self.pool().begin_with("BEGIN IMMEDIATE").await?;
        let acquired = Instant::now();
        cap_grant::apply_cap_grant_fills(&mut tx, &fills).await?;
        tx.commit().await?;
        batch.lock_wait = acquired.duration_since(asked);
        batch.write_hold = acquired.elapsed();
        Ok(batch)
    }

    /// One pass of the backfill, recording into `report` as it goes so that
    /// what was done before a failure is not lost.
    async fn backfill_cap_grant_pass(
        &self,
        config: CapGrantBackfillConfig,
        report: &mut CapGrantBackfillReport,
        on_event: BackfillObserver<'_>,
        fault: BackfillFault<'_>,
    ) -> sqlx::Result<()> {
        let limit = config.batch.max(1);
        let mut pause = config.pause;
        let mut cursor: Option<Vec<u8>> = None;
        while !self.pool().is_closed() {
            let step = self
                .backfill_cap_grant_batch_with(cursor.clone(), limit, &mut *fault)
                .await?;
            report.authors_filled += step.authors;
            report.secret_keys_filled += step.keyed;
            report.left_unkeyed += step.left_unkeyed;
            report.max_lock_wait = report.max_lock_wait.max(step.lock_wait);
            report.max_write_hold = report.max_write_hold.max(step.write_hold);
            match step.next_cursor {
                Some(next) => cursor = Some(next),
                None => break,
            }

            // Yield. A batch that had to wait for the lock, or was slow to
            // write, means something else is using the database: back off, and
            // come back to the base pace only once a batch goes through clean.
            if step.lock_wait > config.yield_above || step.write_hold > config.yield_above {
                pause = pause
                    .max(config.yield_above)
                    .saturating_mul(2)
                    .min(config.max_pause.max(config.pause));
                report.yields += 1;
                on_event(CapGrantBackfillEvent::Yielded {
                    lock_wait: step.lock_wait,
                    write_hold: step.write_hold,
                    pause,
                });
            } else {
                pause = config.pause;
            }
            // Nothing is held here: the read connection and the write
            // transaction were both returned to the pool inside the batch.
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
    /// - **One walk.** The table is walked once per pass in primary-key order;
    ///   a batch fills the author and the key of its rows together and the
    ///   cursor never revisits a row, filled or unfillable.
    /// - **Bounded writes.** A batch is one statement over `batch` rows, taken
    ///   and released within the batch. `pause` is slept between batches with
    ///   nothing held.
    /// - **Fail-safe.** A row whose key cannot be derived with certainty is
    ///   skipped and stays un-keyed.
    ///
    /// Stops early, returning what it did, if the pool is closed. An error
    /// loses nothing that was already written; use
    /// [`converge_cap_grant_lookup_keys`](Self::converge_cap_grant_lookup_keys)
    /// to keep going until the job is done, and to yield under contention.
    pub async fn backfill_cap_grant_lookup_keys(
        &self,
        batch: u32,
        pause: Duration,
    ) -> sqlx::Result<CapGrantBackfillReport> {
        let config = CapGrantBackfillConfig {
            start_delay: Duration::ZERO,
            batch,
            pause,
            // No adaptive yielding: the caller chose the pace.
            yield_above: Duration::MAX,
            max_pause: pause,
            min_backoff: Duration::ZERO,
            max_backoff: Duration::ZERO,
        };
        let mut report = CapGrantBackfillReport::default();
        self.backfill_cap_grant_pass(config, &mut report, &mut |_| {}, &mut no_fault)
            .await?;
        Ok(report)
    }

    /// Run the lookup-column backfill until it has converged or the pool is
    /// closed, whichever comes first.
    ///
    /// **It yields.** Each batch is one small statement; between batches the
    /// task sleeps holding nothing. When a batch had to wait for the write
    /// lock, or held it, for longer than `yield_above`, the pause doubles (up
    /// to `max_pause`) and stays long until a batch goes through clean.
    ///
    /// **It does not give up.** A pass that fails — typically a write that
    /// waited out the busy timeout behind other agents' writes — is retried
    /// after a backoff that doubles from `min_backoff` to `max_backoff`. There
    /// is no retry budget: every pass keeps what it wrote and the streak of
    /// failures (and with it the backoff) is reset whenever a pass makes
    /// progress. A failure caused by the pool closing is not reported.
    ///
    /// **It is observable.** The number of secret-bearing rows still without a
    /// current key is published as the `hc.db.cap_grant.unkeyed` gauge
    /// (labelled with the database's `kind` and `id`, one series per DNA) when
    /// it starts and after every pass. `on_event` receives the start, each
    /// yield, each failure, and the final outcome.
    ///
    /// Returns everything filled in. If the pool closed first, that is what
    /// had been filled in by then.
    pub fn converge_cap_grant_lookup_keys<'a>(
        &'a self,
        config: CapGrantBackfillConfig,
        on_event: &'a mut (dyn FnMut(CapGrantBackfillEvent) + Send),
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = CapGrantBackfillReport> + Send + 'a>>
    {
        // Boxed with an explicit `Send` bound so that the bound is proved
        // here, over concrete lifetimes, and not re-derived by every caller
        // that spawns it.
        Box::pin(async move {
            let mut no_fault = no_fault;
            self.converge_cap_grant_lookup_keys_with(config, on_event, &mut no_fault)
                .await
        })
    }

    pub(crate) async fn converge_cap_grant_lookup_keys_with(
        &self,
        config: CapGrantBackfillConfig,
        on_event: BackfillObserver<'_>,
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

        let unkeyed = self.as_ref().count_cap_grants_unkeyed().await.ok();
        if let Some(unkeyed) = unkeyed {
            gauge.record(unkeyed);
        }
        on_event(CapGrantBackfillEvent::Started { unkeyed });

        loop {
            if self.pool().is_closed() {
                return total;
            }
            let mut pass = CapGrantBackfillReport::default();
            let outcome = self
                .backfill_cap_grant_pass(config, &mut pass, &mut *on_event, &mut *fault)
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
                error: error.to_string(),
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
            yield_above: Duration::MAX,
            max_pause: Duration::ZERO,
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
