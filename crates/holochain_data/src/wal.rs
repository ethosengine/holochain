//! ELOHIM PATCH (fleet CPU storm, H3): explicit WAL checkpoint cadence.
//!
//! Every database runs in WAL mode and relies on SQLite's automatic
//! checkpoint: a `PASSIVE` checkpoint attempted by whichever connection
//! commits past 1000 WAL pages. A passive checkpoint can only copy frames no
//! active reader still needs, and never shrinks the file. On a busy
//! conductor (many hosted agents, continuous overlapping reads) household
//! stores were measured with a WAL 1.1-4.3x the size of the main database,
//! pages reaching the main file only in the first ~90 s after boot, and
//! writers failing with `database is locked`.
//!
//! This module adds two bounded measures:
//!
//! - [`JOURNAL_SIZE_LIMIT_BYTES`] is applied to every connection, so once a
//!   checkpoint has fully backfilled the log the WAL file is cut back to that
//!   size when it is next reset, instead of staying at its high-water mark.
//! - [`DbWrite::wal_maintenance_pass`] runs a `PASSIVE` checkpoint and, only
//!   when the log is still large afterwards and little of it is left to copy,
//!   a `TRUNCATE` checkpoint whose wait for readers is capped at a short,
//!   explicit busy timeout. A `TRUNCATE` blocks new writers while it waits
//!   and while it copies, so both halves of the stall are bounded: the wait
//!   by [`WAL_TRUNCATE_MAX_WAIT`], the copy by [`WAL_TRUNCATE_MAX_COPY_FRAMES`].
//!   The caller runs it on a timer; it never waits unboundedly and it reports
//!   a pinned WAL (`busy`) instead of hiding it.

use crate::{DatabaseIdentifier, DbWrite, BUSY_TIMEOUT};
use std::time::Duration;

/// `PRAGMA journal_size_limit` applied to every connection: 64 MiB.
pub const JOURNAL_SIZE_LIMIT_BYTES: i64 = 64 * 1024 * 1024;

/// A WAL log of at least this many frames (about 64 MiB at the default 4 KiB
/// page size) after a passive checkpoint is truncated by
/// [`DbWrite::wal_maintenance_pass`].
pub const WAL_TRUNCATE_ABOVE_FRAMES: i64 = 16 * 1024;

/// How long a truncating checkpoint may wait for readers (and so hold off new
/// writers) before giving up.
pub const WAL_TRUNCATE_MAX_WAIT: Duration = Duration::from_millis(1000);

/// A truncating checkpoint also blocks new writers while it copies whatever
/// the passive checkpoint could not. It is only attempted when that remainder
/// is at most this many frames (about 16 MiB at 4 KiB pages), so the copy
/// half of the writer stall is bounded too; a larger remainder (a reader
/// pinning an old snapshot) is left to the next passive pass.
pub const WAL_TRUNCATE_MAX_COPY_FRAMES: i64 = 4 * 1024;

/// Which `PRAGMA wal_checkpoint` mode to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalCheckpointMode {
    /// Copy what no reader still needs; never waits, never blocks anyone.
    Passive,
    /// Copy everything, wait (bounded) for readers, then truncate the WAL
    /// file to zero bytes.
    Truncate,
}

impl WalCheckpointMode {
    fn sql(self) -> &'static str {
        match self {
            WalCheckpointMode::Passive => "PRAGMA wal_checkpoint(PASSIVE)",
            WalCheckpointMode::Truncate => "PRAGMA wal_checkpoint(TRUNCATE)",
        }
    }
}

/// The three values `PRAGMA wal_checkpoint` returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalCheckpointOutcome {
    /// The checkpoint could not complete: a reader or writer held it off.
    pub busy: bool,
    /// Frames in the WAL log (`-1` when the database is not in WAL mode).
    pub log_frames: i64,
    /// Frames of the log copied back into the database file.
    pub checkpointed_frames: i64,
}

impl WalCheckpointOutcome {
    /// Every frame in the log has been copied into the main database file.
    pub fn fully_backfilled(&self) -> bool {
        !self.busy && self.checkpointed_frames >= self.log_frames
    }
}

/// What one [`DbWrite::wal_maintenance_pass`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalMaintenanceOutcome {
    /// The passive checkpoint that always runs first.
    pub passive: WalCheckpointOutcome,
    /// The bounded truncating checkpoint, when the log was still at or above
    /// the threshold after the passive one.
    pub truncate: Option<WalCheckpointOutcome>,
}

impl<I: DatabaseIdentifier> DbWrite<I> {
    /// Run one `PRAGMA wal_checkpoint` in `mode`.
    ///
    /// A [`WalCheckpointMode::Truncate`] checkpoint waits for readers for at
    /// most `max_wait` (it sets that busy timeout on the one connection it
    /// uses and restores [`BUSY_TIMEOUT`] afterwards; a connection whose
    /// timeout cannot be restored is closed rather than returned to the pool).
    pub async fn wal_checkpoint(
        &self,
        mode: WalCheckpointMode,
        max_wait: Duration,
    ) -> sqlx::Result<WalCheckpointOutcome> {
        let mut conn = self.pool().acquire().await?;
        if mode == WalCheckpointMode::Passive {
            return run_checkpoint(&mut conn, mode).await;
        }
        set_busy_timeout(&mut conn, max_wait).await?;
        let outcome = run_checkpoint(&mut conn, mode).await;
        if set_busy_timeout(&mut conn, BUSY_TIMEOUT).await.is_err() {
            conn.close_on_drop();
        }
        outcome
    }

    /// One bounded WAL maintenance step: a passive checkpoint, then — only if
    /// the log still holds at least `truncate_above_frames` frames and at most
    /// [`WAL_TRUNCATE_MAX_COPY_FRAMES`] of them are left to copy — a
    /// truncating checkpoint that waits at most `truncate_max_wait`.
    pub async fn wal_maintenance_pass(
        &self,
        truncate_above_frames: i64,
        truncate_max_wait: Duration,
    ) -> sqlx::Result<WalMaintenanceOutcome> {
        let passive = self
            .wal_checkpoint(WalCheckpointMode::Passive, Duration::ZERO)
            .await?;
        let remainder = passive.log_frames - passive.checkpointed_frames;
        let truncate = if passive.log_frames >= truncate_above_frames
            && passive.log_frames > 0
            && remainder <= WAL_TRUNCATE_MAX_COPY_FRAMES
        {
            Some(
                self.wal_checkpoint(WalCheckpointMode::Truncate, truncate_max_wait)
                    .await?,
            )
        } else {
            None
        };
        Ok(WalMaintenanceOutcome { passive, truncate })
    }
}

async fn run_checkpoint(
    conn: &mut sqlx::SqliteConnection,
    mode: WalCheckpointMode,
) -> sqlx::Result<WalCheckpointOutcome> {
    let (busy, log_frames, checkpointed_frames): (i64, i64, i64) =
        sqlx::query_as(mode.sql()).fetch_one(&mut *conn).await?;
    Ok(WalCheckpointOutcome {
        busy: busy != 0,
        log_frames,
        checkpointed_frames,
    })
}

async fn set_busy_timeout(conn: &mut sqlx::SqliteConnection, wait: Duration) -> sqlx::Result<()> {
    let stmt = format!("PRAGMA busy_timeout = {}", wait.as_millis());
    sqlx::query(sqlx::AssertSqlSafe(stmt))
        .execute(&mut *conn)
        .await?;
    Ok(())
}
