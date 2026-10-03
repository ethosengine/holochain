//! # Publish Dht Op Workflow
//!
//! ## Open questions
//! - [x] Publish add and remove links on private entries, what are the constraints on when to publish
//!
//! For now, Publish links on private entries
// TODO: B-01827 Make story about: later consider adding a flag to make a link private and not publish it.
//       Even for those private links, we may need to publish them to the author of the private entry
//       (and we'd have to reference its action  which actually exists on the DHT to make that work,
//       rather than the entry which does not exist on the DHT).
//!
//!

use super::error::WorkflowResult;
use crate::core::queue_consumer::TriggerSender;
use crate::core::queue_consumer::WorkComplete;
use holo_hash::*;
use holochain_p2p::DynHolochainP2pDna;
use holochain_state::prelude::*;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tracing::*;

#[cfg(test)]
mod unit_tests;

/// Default redundancy factor for validation receipts
pub const DEFAULT_RECEIPT_BUNDLE_SIZE: u8 = 5;

/// When a cell's last full republish sweep ran, and how far up the chain it saw.
///
/// Every committing zome call triggers the publish workflow. Re-reading every
/// op the author has ever written on each of those runs costs the length of
/// the source chain, yet between sweeps only ops committed since the last
/// sweep can be due for a first publish: an op already published waits out
/// `min_publish_interval` before it is due again, and an op the sweep saw but
/// could not send waits for the next sweep. So a run reads the whole set only
/// when a sweep is due, and otherwise reads the never-published ops above the
/// chain head the last sweep saw.
///
/// One clock per cell, held in memory by the publish consumer. A new clock has
/// no sweep on record, so the first run after start-up is a sweep.
#[derive(Clone, Default)]
pub struct PublishSweepClock(Arc<std::sync::Mutex<Option<SweepMark>>>);

/// The last recorded sweep.
#[derive(Clone, Copy, Debug)]
struct SweepMark {
    /// When the sweep's selection ran.
    at: tokio::time::Instant,
    /// The chain head sequence read just before that selection.
    head_seq: u32,
}

impl PublishSweepClock {
    /// Which ops this run should read.
    fn scope(&self, min_publish_interval: Duration) -> PublishScope {
        let last = *self.0.lock().expect("publish sweep clock poisoned");
        match last {
            Some(mark) if mark.at.elapsed() < min_publish_interval => PublishScope::NewOnly {
                after_seq: mark.head_seq,
            },
            _ => PublishScope::Sweep,
        }
    }

    /// Record a sweep whose selection ran at `at` above nothing older than
    /// `head_seq`.
    fn mark_swept(&self, at: tokio::time::Instant, head_seq: u32) {
        *self.0.lock().expect("publish sweep clock poisoned") = Some(SweepMark { at, head_seq });
    }
}

/// Which ops a publish run reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PublishScope {
    /// Only never-published ops of actions after `after_seq`.
    NewOnly { after_seq: u32 },
    /// Every op still needing publish whose minimum interval has passed.
    Sweep,
}

/// Publish the agent's due ops, reading the whole set on every run.
///
/// Equivalent to [`publish_dht_ops_workflow_with_clock`] with a fresh clock, so
/// every call is a sweep.
#[cfg_attr(
    feature = "instrument",
    tracing::instrument(skip(dht_store, network, trigger_self, min_publish_interval))
)]
pub async fn publish_dht_ops_workflow(
    dht_store: DhtStore,
    network: DynHolochainP2pDna,
    trigger_self: TriggerSender,
    agent: AgentPubKey,
    min_publish_interval: Duration,
) -> WorkflowResult<WorkComplete> {
    publish_dht_ops_workflow_with_clock(
        dht_store,
        network,
        trigger_self,
        agent,
        min_publish_interval,
        &PublishSweepClock::default(),
    )
    .await
}

/// Publish the agent's due ops, sweeping the whole set at most once per
/// `min_publish_interval` and otherwise publishing only never-published ops.
///
/// A sweep is recorded, with the chain head read just before its selection,
/// unless the network reported that the space has not started; then the next
/// run sweeps again. An op that a recorded sweep failed to send waits for the
/// next sweep; a never-published op committed after the recorded head is
/// retried by every run until it is sent.
#[cfg_attr(
    feature = "instrument",
    tracing::instrument(skip(dht_store, network, trigger_self, min_publish_interval, clock))
)]
pub async fn publish_dht_ops_workflow_with_clock(
    dht_store: DhtStore,
    network: DynHolochainP2pDna,
    trigger_self: TriggerSender,
    agent: AgentPubKey,
    min_publish_interval: Duration,
    clock: &PublishSweepClock,
) -> WorkflowResult<WorkComplete> {
    let mut complete = WorkComplete::Complete;
    let scope = clock.scope(min_publish_interval);
    let selected_at = tokio::time::Instant::now();
    // The head is read before the selection, so an op committed while the
    // sweep runs lies above it and is read by the next new-only run.
    let sweep_head = match scope {
        PublishScope::Sweep => dht_store
            .as_read()
            .chain_head_for_author(&agent)
            .await?
            .map(|head| head.seq),
        PublishScope::NewOnly { .. } => None,
    };
    let to_publish =
        collect_ops_to_publish(&dht_store, agent.clone(), min_publish_interval, scope).await?;
    let to_publish_count: usize = to_publish.values().map(Vec::len).sum();

    if to_publish_count > 0 {
        info!(?agent, "publishing {to_publish_count} ops");
    }

    // Commit to the network
    let mut success = Vec::with_capacity(to_publish.len());
    for (basis, ops) in to_publish {
        let op_hash_list = ops.iter().map(|op| op.hash.clone()).collect();
        match network
            .publish(basis, agent.clone(), op_hash_list, None)
            .await
        {
            Err(e) => {
                // If we get a routing error it means the space hasn't started yet and we should try publishing again.
                if let holochain_p2p::HolochainP2pError::RoutingDnaError(_) = e {
                    // TODO if this doesn't change what is the loop terminate condition?
                    complete = WorkComplete::Incomplete(None);
                }
                warn!(failed_to_send_publish = ?e);
            }
            Ok(()) => {
                success.extend(ops);
            }
        }
    }

    if to_publish_count > 0 {
        info!(
            ?agent,
            "published {}/{} ops",
            success.len(),
            to_publish_count
        );
    }

    // Record the publish time for everything that was sent successfully, then
    // decide whether any ops may still need publishing in the future. Each op
    // carries its kind, so its publish time lands in the table that holds its
    // publish state; one unrecordable op does not void the others' records.
    if !success.is_empty() {
        dht_store
            .record_published_op_hashes(success, Timestamp::now())
            .await?;
    }
    if let Some(head_seq) = sweep_head {
        if matches!(complete, WorkComplete::Complete) {
            clock.mark_swept(selected_at, head_seq);
        }
    }

    let continue_publish = dht_store
        .as_read()
        .has_ops_still_needing_publish(&agent)
        .await?;

    // If we have more ops that could be published then continue looping.
    if continue_publish {
        trigger_self.resume_loop();
    } else {
        trigger_self.pause_loop();
    }

    debug!(?agent, "committed published ops");

    // --- END OF WORKFLOW, BEGIN FINISHER BOILERPLATE ---

    Ok(complete)
}

/// Collect the ops authored by `agent` that are ready to publish, grouped by
/// their DHT basis, from the DHT store. Each op keeps its [`PublishOpKind`] so
/// its publish time can be recorded in the right table once it is sent.
pub async fn publish_dht_ops_workflow_inner(
    dht_store: &DhtStore,
    agent: AgentPubKey,
    min_publish_interval: Duration,
) -> WorkflowResult<HashMap<OpBasis, Vec<PublishableOp>>> {
    collect_ops_to_publish(dht_store, agent, min_publish_interval, PublishScope::Sweep).await
}

async fn collect_ops_to_publish(
    dht_store: &DhtStore,
    agent: AgentPubKey,
    min_publish_interval: Duration,
    scope: PublishScope,
) -> WorkflowResult<HashMap<OpBasis, Vec<PublishableOp>>> {
    // Ops to publish by basis
    let mut to_publish = HashMap::new();

    let reader = dht_store.as_read();
    let ops = match scope {
        PublishScope::Sweep => {
            reader
                .get_ops_to_publish(&agent, min_publish_interval)
                .await?
        }
        PublishScope::NewOnly { after_seq } => {
            reader.get_new_ops_to_publish(&agent, after_seq).await?
        }
    };
    for (basis, op) in ops {
        // For every op publish a request
        // Collect and sort ops by basis
        to_publish.entry(basis).or_insert_with(Vec::new).push(op);
    }

    Ok(to_publish)
}
