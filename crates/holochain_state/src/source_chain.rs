use crate::chain_lock::ChainLock;
use crate::prelude::*;
use crate::scratch::ScratchError;
use crate::scratch::SyncScratchError;
use async_recursion::async_recursion;
pub use error::*;
// Authoring and op production build actions directly (via `build_action`
// and friends), stage them in the scratch, and turn them into ops via
// `produce_ops_from_record`.
use holo_hash::ActionHash;
use holo_hash::AgentPubKey;
use holo_hash::DnaHash;
use holo_hash::EntryHash;
use holo_hash::HasHash;
use holo_hash::HoloHashed;
use holochain_data::kind::Dht;
use holochain_data::{DbRead, DbWrite};
use holochain_keystore::{AgentPubKeyExt, MetaLairClient, SignedActionHashedExt};
use holochain_state_types::{SourceChainCursor, SourceChainDump};
use holochain_types::op::{
    produce_ops_from_record, ChainOp, DhtOp, DhtOpHashed, HashedChainOp, OpEntry,
};
use holochain_types::warrant::WarrantOp;
use holochain_zome_types::prelude::{
    build_action, from_countersigning_data, Action, ActionData, ActionHeader,
    AgentValidationPkgData, CreateData, DeleteData, DnaData, Record, RecordValidity, SignedAction,
    SignedActionHashed,
};
use kitsune2_api::DhtArc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;

mod error;

#[derive(Clone)]
pub struct SourceChain<Db = DbWrite<Dht>> {
    scratch: SyncScratch,
    pub(crate) dht_store: DhtStore<Db>,
    keystore: MetaLairClient,
    author: Arc<AgentPubKey>,
    cell_id: Arc<CellId>,
    head_info: Option<HeadInfo>,
    public_only: bool,
    zomes_initialized: Arc<AtomicBool>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeadInfo {
    pub action: ActionHash,
    pub seq: u32,
    pub timestamp: Timestamp,
}

impl HeadInfo {
    pub fn into_tuple(self) -> (ActionHash, u32, Timestamp) {
        (self.action, self.seq, self.timestamp)
    }
}

/// A source chain with read only access to the underlying database.
pub type SourceChainRead = SourceChain<DbRead<Dht>>;

// TODO: document that many functions here are only reading from the scratch,
//       not the entire source chain!
/// Writable functions for a source chain with write access.
impl SourceChain<DbWrite<Dht>> {
    #[cfg_attr(feature = "instrument", tracing::instrument(skip_all))]
    pub async fn unlock_chain(&self) -> SourceChainResult<()> {
        // The chain lock lives in the DhtStore.
        self.dht_store
            .release_chain_lock(self.author.as_ref())
            .await?;
        Ok(())
    }

    #[cfg_attr(feature = "instrument", tracing::instrument(skip_all))]
    pub async fn accept_countersigning_preflight_request(
        &self,
        preflight_request: PreflightRequest,
        agent_index: u8,
    ) -> SourceChainResult<CounterSigningAgentState> {
        let hashed_preflight_request =
            blake2b_256(&holochain_serialized_bytes::encode(&preflight_request)?);

        // This all needs to be ensured in a non-panicky way BEFORE calling into the source chain here.
        let author = self.author.clone();
        assert_eq!(
            *author,
            preflight_request.signing_agents[agent_index as usize].0
        );

        // Check for a chain lock.
        // Note that the lock may not be valid anymore, but we must respect it here anyway.
        // `get_chain_lock` returns any lock row, including an expired one, so an
        // expired lock still rejects acceptance.
        if self
            .dht_store
            .as_read()
            .get_chain_lock(author.as_ref().clone())
            .await?
            .is_some()
        {
            return Err(SourceChainError::ChainLocked);
        }

        let HeadInfo {
            action: persisted_head,
            seq: persisted_seq,
            ..
        } = self
            .dht_store
            .as_read()
            .chain_head_for_author(author.as_ref())
            .await?
            .ok_or(SourceChainError::ChainEmpty)?;
        let countersigning_agent_state =
            CounterSigningAgentState::new(agent_index, persisted_head, persisted_seq);

        // Take out the lock. We verified above that no lock exists, so this must
        // succeed; the bool guards against a concurrent writer slipping a lock in
        // between the check and here, in which case we reject as `ChainLocked`
        // rather than extending or stealing the lock. The head read above and
        // this lock acquisition are separate operations, not one transaction: a
        // concurrent flush can move the head in between, but a stale captured
        // head is rejected by the as-at check when the session commits, so the
        // session fails cleanly rather than forking the chain.
        let acquired = self
            .dht_store
            .acquire_chain_lock(
                author.as_ref(),
                &hashed_preflight_request,
                *preflight_request.session_times.end(),
                Timestamp::now(),
            )
            .await?;
        if !acquired {
            return Err(SourceChainError::ChainLocked);
        }

        Ok(countersigning_agent_state)
    }

    /// Hash, sign, and stage a fully-built [`Action`] (with its
    /// optional entry) at the end of the scratch.
    pub async fn put_with_action(
        &self,
        action: Action,
        maybe_entry: Option<Entry>,
        chain_top_ordering: ChainTopOrdering,
    ) -> SourceChainResult<ActionHash> {
        let entry_visibility = action.entry_visibility().copied();
        let action_hashed = HoloHashed::<Action>::from_content_sync(action);
        let hash = action_hashed.as_hash().clone();
        let signed_action = SignedActionHashed::sign(&self.keystore, action_hashed).await?;
        let record_entry =
            holochain_zome_types::prelude::RecordEntry::new(entry_visibility.as_ref(), maybe_entry);
        let record = Record::new(signed_action, record_entry);
        self.scratch
            .apply(|scratch| insert_record_scratch(scratch, record, chain_top_ordering))?;
        Ok(hash)
    }

    /// Put a new countersigning [`Action`] at the end of the source chain
    /// for `entry` (which must be an [`Entry::CounterSign`]).
    pub async fn put_countersigned(
        &self,
        entry: Entry,
        chain_top_ordering: ChainTopOrdering,
    ) -> SourceChainResult<ActionHash> {
        let entry_hash = EntryHash::with_data_sync(&entry);
        if let Entry::CounterSign(ref session_data, _) = entry {
            self.put_with_action(
                from_countersigning_data(entry_hash, session_data, (*self.author).clone())?,
                Some(entry),
                chain_top_ordering,
            )
            .await
        } else {
            // The caller MUST guard against this case.
            unreachable!("Put countersigned called with the wrong entry type");
        }
    }

    /// Put a new action at the end of the source chain, built from its
    /// per-variant [`ActionData`] payload.
    ///
    /// The header (author, sequence number, and previous action) is filled in
    /// from the current chain head.
    pub async fn put(
        &self,
        data: ActionData,
        maybe_entry: Option<Entry>,
        chain_top_ordering: ChainTopOrdering,
    ) -> SourceChainResult<ActionHash> {
        let HeadInfo {
            action: prev_action,
            seq: chain_head_seq,
            timestamp: chain_head_timestamp,
        } = self.chain_head_nonempty()?;
        let action_seq = chain_head_seq + 1;

        let header = ActionHeader {
            author: (*self.author).clone(),
            // If the current time is equal to the current chain head timestamp,
            // or even has drifted to be before it, just set the next timestamp
            // to be one unit ahead of the previous.
            //
            // TODO: put a limit on the size of the negative time interval
            //       we are willing to accept, beyond which we emit an error
            //       rather than bumping the timestamp
            timestamp: std::cmp::max(
                Timestamp::now(),
                (chain_head_timestamp + std::time::Duration::from_micros(1))?,
            ),
            action_seq,
            prev_action: Some(prev_action),
        };
        self.put_with_action(build_action(header, data), maybe_entry, chain_top_ordering)
            .await
    }

    /// Drain the scratch space and persist its contents to the databases.
    ///
    /// This drains all actions, entries, scheduled functions, and warrants from the scratch
    /// and writes them to the per-DNA DHT store. The flush proceeds as follows:
    ///
    /// 1. Validates countersigning invariants: a countersigning entry must be the only
    ///    action in the scratch, its chain lock must match and not be expired.
    /// 2. Performs an "as-at" consistency check against the current persisted chain head.
    ///    If the head has moved since this [`SourceChain`] was constructed, the behavior
    ///    depends on the [`ChainTopOrdering`]: under [`ChainTopOrdering::Strict`] the
    ///    flush fails with [`SourceChainError::HeadMoved`]; under
    ///    [`ChainTopOrdering::Relaxed`] the actions are rebased onto the new head and
    ///    the flush is retried recursively.
    /// 3. Inserts entries, actions, and ops into the DhtStore in a single
    ///    transaction. Ops belonging to a countersigning session are marked as withheld
    ///    from publishing.
    /// 4. Verifies warrant signatures and records valid warrants into the DhtStore.
    ///
    /// Returns an empty vec with zero warrants if the scratch is empty.
    ///
    /// # Errors
    ///
    /// - [`SourceChainError::HeadMoved`] if the chain head changed and ordering is strict.
    /// - [`SourceChainError::DirtyCounterSigningWrite`] if a countersigning entry is
    ///   flushed alongside other actions.
    /// - [`SourceChainError::ChainLocked`] if the chain is locked for a different session.
    /// - [`SourceChainError::LockExpired`] if the countersigning lock has expired.
    /// - [`SourceChainError::CountersigningWriteWithoutSession`] if a countersigning
    ///   entry is written without an active chain lock.
    #[async_recursion]
    #[cfg_attr(feature = "instrument", tracing::instrument(skip(self)))]
    // `storage_arcs` is only used in the recursive rebase call.
    #[allow(clippy::only_used_in_recursion)]
    pub async fn flush(
        &self,
        storage_arcs: Vec<DhtArc>,
    ) -> SourceChainResult<(Vec<SignedActionHashed>, u32)> {
        // Nothing to write
        if self.scratch.apply(|s| s.is_empty())? {
            return Ok((Vec::new(), 0));
        }

        let (scheduled_fns, actions, ops, entries, records, warrants) =
            self.scratch.apply_and_then(|scratch| {
                let records: Vec<Record> = scratch.records().collect();

                // The ops a freshly-authored batch of records produces.
                // `produce_ops_from_record` is infallible over a well-formed
                // record.
                let ops: Vec<HashedChainOp> =
                    records.iter().flat_map(produce_ops_from_record).collect();

                let actions = scratch.drain_actions().collect::<Vec<_>>();

                // Drain out any entries.
                let entries = scratch.drain_entries().collect::<Vec<_>>();
                let scheduled_fns = scratch.drain_scheduled_fns().collect::<Vec<_>>();
                let warrants = scratch.drain_warrants().collect::<Vec<_>>();
                SourceChainResult::Ok((scheduled_fns, actions, ops, entries, records, warrants))
            })?;

        let maybe_countersigned_entry = entries
            .iter()
            .map(|entry| entry.as_content())
            .find(|entry| matches!(entry, Entry::CounterSign(_, _)));

        if matches!(maybe_countersigned_entry, Some(Entry::CounterSign(_, _))) && actions.len() != 1
        {
            return Err(SourceChainError::DirtyCounterSigningWrite);
        }

        let lock_subject = chain_lock_subject_for_entry(maybe_countersigned_entry)?;

        // If the lock isn't empty this is a countersigning session.
        let is_countersigning_session = !lock_subject.is_empty();

        let author = self.author.clone();
        let persisted_head = self.head_info.as_ref().map(|h| h.action.clone());

        let now = Timestamp::now();

        // Acquire the per-author chain write permit on the DhtStore and
        // perform the source-chain write under it, gated by an as-at check
        // against the store head. The permit serializes flushes for this
        // (DNA, author) chain so a concurrent flush cannot also pass the
        // as-at and fork the chain.
        //
        // The permit is acquired and released *inside* this async block so it
        // is not held when the relaxed-ordering rebase below recurses into
        // `flush` (which re-acquires it).
        let chain_flush_result: SourceChainResult<Vec<SignedActionHashed>> = async {
            let _chain_write_permit = self
                .dht_store
                .acquire_chain_write_permit(author.as_ref())
                .await;

            // If there are records to write, then we need to respect the chain
            // lock. Reading it here opens a tiny TOCTOU window (the lock is
            // mutated by the countersigning workflow, not by flush, so the
            // chain permit does not stabilise it), but this is a coarse
            // countersigning-session guard and the window is acceptable.
            if !records.is_empty() {
                let chain_lock = self
                    .dht_store
                    .as_read()
                    .get_chain_lock(author.as_ref().clone())
                    .await?;
                match chain_lock {
                    Some(chain_lock) => {
                        // If the chain is locked, the lock must be for this entry.
                        if chain_lock.subject() != lock_subject {
                            return Err(SourceChainError::ChainLocked);
                        }
                        // If the lock is expired then we can't write this countersigning session.
                        else if chain_lock.is_expired_at(now) {
                            return Err(SourceChainError::LockExpired);
                        }

                        // Otherwise, the lock matches this entry and has not expired. We can proceed!
                    }
                    None => {
                        // If this is a countersigning entry but there is no chain lock then maybe
                        // the session expired before the entry could be written or maybe the app
                        // has just made a mistake. Either way, it's not valid to write this entry!
                        if is_countersigning_session {
                            return Err(SourceChainError::CountersigningWriteWithoutSession);
                        }
                    }
                }
            }

            // As-at check against the STORE head, under the permit, before the
            // write. Only meaningful when there are actions that move the head.
            // The permit guarantees no concurrent flush commits between this
            // read and the write below, and no other code path writes this
            // author's chain head, so reading on a pool connection (rather than
            // inside `tx`) is safe.
            if !actions.is_empty() {
                let head_info = self
                    .dht_store
                    .as_read()
                    .chain_head_for_author(author.as_ref())
                    .await?;
                let latest_head = head_info.as_ref().map(|h| h.action.clone());

                if persisted_head != latest_head {
                    return Err(SourceChainError::HeadMoved(
                        Box::new(actions),
                        Box::new(entries),
                        persisted_head,
                        head_info,
                    ));
                }
            }

            // The authoritative source-chain write: entries, actions, ops and
            // scheduled fns into the DhtStore, in one transaction.
            let mut tx = self
                .dht_store
                .db()
                .begin()
                .await
                .map_err(SourceChainError::other)?;

            // Collect the set of entry hashes whose authoring action declares
            // them as private. Entries whose hash matches one of these go to
            // `PrivateEntry`; every other entry — including any whose hash is
            // not referenced by an in-batch action — goes to the public `Entry`
            // table.
            let private_entry_hashes = actions
                .iter()
                .filter_map(|sah| {
                    let action = sah.action();
                    let visibility = action.entry_visibility()?;
                    if *visibility == EntryVisibility::Private {
                        action.entry_hash().cloned()
                    } else {
                        None
                    }
                })
                .collect::<std::collections::HashSet<_>>();

            for entry_hashed in &entries {
                let entry_hash = entry_hashed.as_hash();
                let entry = entry_hashed.as_content();
                if private_entry_hashes.contains(entry_hash) {
                    tx.insert_private_entry(entry_hash, author.as_ref(), entry)
                        .await
                        .map_err(SourceChainError::other)?;
                } else {
                    tx.insert_entry(entry_hash, entry)
                        .await
                        .map_err(SourceChainError::other)?;
                }
            }

            // Track which action hashes were successfully inserted into the
            // store. Ops whose action insert failed must also be skipped to
            // avoid FK violations on ChainOp.action_hash.
            let mut inserted_action_hashes = std::collections::HashSet::<ActionHash>::new();

            for sah in &actions {
                tx.insert_action(sah, Some(RecordValidity::Accepted))
                    .await
                    .map_err(SourceChainError::other)?;

                // Record that this action hash is present in the store.
                inserted_action_hashes.insert(sah.as_hash().clone());

                crate::dht_store::action_indexes::insert_action_indexes(
                    &mut tx,
                    sah.as_hash(),
                    &sah.hashed.content.data,
                )
                .await
                .map_err(SourceChainError::other)?;

                // For Create/Update of a CapGrant entry type, insert a CapGrant index row.
                if let Some((cap_access, tag)) = cap_grant_index_params(sah, &entries) {
                    tx.insert_cap_grant(sah.as_hash(), cap_access, tag.as_deref())
                        .await
                        .map_err(SourceChainError::other)?;
                }
            }

            for op in &ops {
                // Skip ops whose action hash was not recorded as successfully inserted.
                if !inserted_action_hashes.contains(op.action_hash()) {
                    continue;
                }
                let storage_center_loc = op.storage_center_loc;
                let timestamp = op.action.action().timestamp();

                let serialized_size = encoded_chain_op_size(op, &entries);
                tx.insert_chain_op(holochain_data::dht::InsertChainOp {
                    op_hash: &op.op_hash,
                    action_hash: op.action_hash(),
                    op_type: i64::from(op.op_type),
                    basis_hash: &op.basis_hash,
                    storage_center_loc,
                    validation_status: RecordValidity::Accepted,
                    locally_validated: true,
                    require_receipt: false,
                    when_received: timestamp,
                    when_integrated: timestamp,
                    serialized_size,
                })
                .await
                .map_err(SourceChainError::other)?;

                // Always insert a ChainOpPublish row for self-authored ops so the
                // publish workflow can track them without a separate lookup.
                // Countersigning ops are withheld from publishing until the
                // session succeeds.
                let withhold = if is_countersigning_session {
                    Some(true)
                } else {
                    None
                };
                tx.insert_chain_op_publish(&op.op_hash, None, None, withhold)
                    .await
                    .map_err(SourceChainError::other)?;
            }

            // Scheduled functions flushed from the scratch are always written
            // with `maybe_schedule = None`.
            // None => start=now, end=Timestamp::max(), ephemeral=true.
            for scheduled_fn in &scheduled_fns {
                let maybe_schedule_blob =
                    serialize_maybe_schedule_none().map_err(SourceChainError::other)?;
                let _ = tx
                    .upsert_scheduled_function(holochain_data::dht::InsertScheduledFunction {
                        author: author.as_ref(),
                        zome_name: scheduled_fn.zome_name().0.as_ref(),
                        scheduled_fn: scheduled_fn.fn_name().0.as_ref(),
                        maybe_schedule: &maybe_schedule_blob,
                        start_at: now,
                        end_at: Timestamp::max(),
                        ephemeral: true,
                    })
                    .await
                    .map_err(SourceChainError::other)?;
            }

            tx.commit().await.map_err(SourceChainError::other)?;

            SourceChainResult::Ok(actions)
        }
        .await;

        match chain_flush_result {
            Err(SourceChainError::HeadMoved(actions, entries, old_head, Some(new_head_info))) => {
                let is_relaxed =
                    self.scratch
                        .apply_and_then::<bool, SyncScratchError, _>(|scratch| {
                            Ok(scratch.chain_top_ordering() == ChainTopOrdering::Relaxed)
                        })?;
                if is_relaxed {
                    let keystore = self.keystore.clone();
                    // A child chain is needed with a new as-at that matches
                    // the rebase.
                    let child_chain = Self::new(
                        self.dht_store.clone(),
                        keystore.clone(),
                        (*self.author).clone(),
                    )
                    .await?;
                    let rebased_actions =
                        rebase_actions_on(&keystore, *actions, new_head_info).await?;
                    child_chain.scratch.apply(move |scratch| {
                        for action in rebased_actions {
                            scratch.add_action(action, ChainTopOrdering::Relaxed);
                        }
                        for entry in *entries {
                            scratch.add_entry(entry, ChainTopOrdering::Relaxed);
                        }
                    })?;
                    child_chain.flush(storage_arcs).await
                } else {
                    Err(SourceChainError::HeadMoved(
                        actions,
                        entries,
                        old_head,
                        Some(new_head_info),
                    ))
                }
            }
            Ok(actions) => {
                // Verify warrant signatures, then record the valid ones into the
                // DhtStore so `ops_pending_sys_validation` picks them up via
                // `LimboWarrant`.
                let mut warrant_ops = Vec::new();
                for warrant in warrants {
                    match warrant
                        .author
                        .verify_signature(warrant.signature(), warrant.data())
                        .await
                    {
                        Ok(true) => warrant_ops.push(DhtOpHashed::from_content_sync(
                            DhtOp::WarrantOp(Box::new(WarrantOp::from(warrant))),
                        )),
                        Ok(false) => {
                            tracing::info!(
                                "Invalid signature of a warrant in the scratch space. Skipping warrant"
                            );
                            continue;
                        }
                        Err(err) => {
                            tracing::warn!(?err, "Could not verify warrant signature before recording from scratch space into the DhtStore. Skipping warrant");
                            continue;
                        }
                    }
                }

                let total_warrants = warrant_ops.len() as u32;
                // Record valid warrants into the DhtStore so
                // `ops_pending_sys_validation` picks them up via `LimboWarrant`.
                if !warrant_ops.is_empty() {
                    // Warrants do not require validation receipts, set all to false.
                    let warrant_ops_with_validation_receipt_required_flag =
                        warrant_ops.into_iter().map(|op| (op, false)).collect();
                    self.dht_store
                        .record_incoming_ops(warrant_ops_with_validation_receipt_required_flag)
                        .await
                        .map_err(SourceChainError::other)?;
                }

                SourceChainResult::Ok((actions, total_warrants))
            }
            Err(e) => Err(e),
        }
    }

    /// Checks if the current [`AgentPubKey`] of the source chain is valid and returns its [`Create`](ActionData::Create) action.
    ///
    /// Valid means that there's no [`Update`](ActionData::Update) or [`Delete`](ActionData::Delete) action for the key on the chain.
    /// Returns the create action if it is valid, and an [`SourceChainError::InvalidAgentKey`] otherwise.
    ///
    /// Returns the `Action` from [`DhtStore::valid_create_agent_key_action`],
    /// which is the source of truth.
    pub async fn valid_create_agent_key_action(
        &self,
    ) -> SourceChainResult<holochain_zome_types::prelude::Action> {
        let agent_key = self.agent_pubkey().clone();
        self.dht_store
            .as_read()
            .valid_create_agent_key_action(&agent_key)
            .await?
            .ok_or_else(|| {
                SourceChainError::InvalidAgentKey(agent_key, self.cell_id().as_ref().clone())
            })
    }

    /// Deletes the current [`AgentPubKey`] of the source chain if it is valid and returns a [`SourceChainError::InvalidAgentKey`]
    /// otherwise.
    ///
    /// The agent key is valid if there are no [`Update`](ActionData::Update) or [`Delete`](ActionData::Delete) actions for that key on the chain.
    pub async fn delete_valid_agent_pub_key(&self) -> SourceChainResult<()> {
        let valid_create_agent_key_action = self.valid_create_agent_key_action().await?;

        self.put(
            ActionData::Delete(DeleteData {
                deletes_address: valid_create_agent_key_action.to_hash(),
                deletes_entry_address: self.agent_pubkey().clone().into(),
            }),
            None,
            ChainTopOrdering::Strict,
        )
        .await?;

        Ok(())
    }
}

impl SourceChain<DbWrite<Dht>> {
    pub async fn new(
        dht_store: DhtStore,
        keystore: MetaLairClient,
        author: AgentPubKey,
    ) -> SourceChainResult<Self> {
        let scratch = Scratch::new().into_sync();
        let author = Arc::new(author);
        let cell_id = Arc::new(CellId::new(
            dht_store.dna_hash().clone(),
            author.as_ref().clone(),
        ));
        let head_info = Some(
            dht_store
                .as_read()
                .chain_head_for_author(author.as_ref())
                .await?
                .ok_or(SourceChainError::ChainEmpty)?,
        );
        Ok(Self {
            scratch,
            dht_store,
            keystore,
            author,
            cell_id,
            head_info,
            public_only: false,
            zomes_initialized: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Create a source chain with a blank chain head.
    /// You probably don't want this.
    /// This type is only useful for when a source chain
    /// really needs to be constructed before genesis runs.
    pub async fn raw_empty(
        dht_store: DhtStore,
        keystore: MetaLairClient,
        author: AgentPubKey,
    ) -> SourceChainResult<Self> {
        let scratch = Scratch::new().into_sync();
        let author = Arc::new(author);
        let cell_id = Arc::new(CellId::new(
            dht_store.dna_hash().clone(),
            author.as_ref().clone(),
        ));
        let head_info = dht_store
            .as_read()
            .chain_head_for_author(author.as_ref())
            .await?;
        Ok(Self {
            scratch,
            dht_store,
            keystore,
            author,
            cell_id,
            head_info,
            public_only: false,
            zomes_initialized: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Downgrade this writable source chain to a read-only source chain.
    pub fn as_read(&self) -> SourceChainRead {
        SourceChain {
            scratch: self.scratch.clone(),
            dht_store: self.dht_store.as_read(),
            keystore: self.keystore.clone(),
            author: self.author.clone(),
            cell_id: self.cell_id.clone(),
            head_info: self.head_info.clone(),
            public_only: self.public_only,
            zomes_initialized: self.zomes_initialized.clone(),
        }
    }
}

impl<Db> SourceChain<Db>
where
    Db: AsRef<DbRead<Dht>>,
{
    pub fn public_only(&mut self) {
        self.public_only = true;
    }

    pub fn keystore(&self) -> &MetaLairClient {
        &self.keystore
    }

    /// Take a snapshot of the scratch space that will
    /// not remain in sync with future updates.
    pub fn snapshot(&self) -> SourceChainResult<Scratch> {
        Ok(self.scratch.apply(|scratch| scratch.clone())?)
    }

    pub fn scratch(&self) -> SyncScratch {
        self.scratch.clone()
    }

    pub fn agent_pubkey(&self) -> &AgentPubKey {
        self.author.as_ref()
    }

    pub fn to_agent_pubkey(&self) -> Arc<AgentPubKey> {
        self.author.clone()
    }

    pub fn cell_id(&self) -> Arc<CellId> {
        self.cell_id.clone()
    }

    /// This has to clone all the data because we can't return
    /// references to constructed data.
    // TODO: Maybe we should store data as records in the scratch?
    // TODO: document that this is only the records in the SCRATCH, not the
    //       entire source chain!
    pub fn scratch_records(&self) -> SourceChainResult<Vec<Record>> {
        Ok(self.scratch.apply(|scratch| scratch.records().collect())?)
    }

    pub async fn zomes_initialized(&self) -> SourceChainResult<bool> {
        if self.zomes_initialized.load(Ordering::Relaxed) {
            return Ok(true);
        }
        let query_filter = ChainQueryFilter {
            action_type: Some(vec![ActionType::InitZomesComplete]),
            ..QueryFilter::default()
        };
        let init_zomes_complete_actions = self.query(query_filter).await?;
        if init_zomes_complete_actions.len() > 1 {
            tracing::warn!("Multiple InitZomesComplete actions are present");
        }
        let zomes_initialized = !init_zomes_complete_actions.is_empty();
        self.set_zomes_initialized(zomes_initialized);
        Ok(zomes_initialized)
    }

    pub fn set_zomes_initialized(&self, value: bool) {
        self.zomes_initialized.store(value, Ordering::Relaxed);
    }

    /// Accessor for the chain head that will be used at flush time to check
    /// the "as at" for ordering integrity etc.
    pub fn persisted_head_info(&self) -> Option<HeadInfo> {
        self.head_info.clone()
    }

    pub fn chain_head(&self) -> SourceChainResult<Option<HeadInfo>> {
        // Check scratch for newer head.
        Ok(self
            .scratch
            .apply(|scratch| scratch.chain_head().or_else(|| self.persisted_head_info()))?)
    }

    pub fn chain_head_nonempty(&self) -> SourceChainResult<HeadInfo> {
        // Check scratch for newer head.
        self.chain_head()?.ok_or(SourceChainError::ChainEmpty)
    }

    #[cfg(feature = "test_utils")]
    pub fn len(&self) -> SourceChainResult<u32> {
        Ok(self.scratch.apply(|scratch| {
            let scratch_max = scratch.chain_head().map(|h| h.seq);
            let persisted_max = self.head_info.as_ref().map(|h| h.seq);
            match (scratch_max, persisted_max) {
                (None, None) => 0,
                (Some(s), None) => s + 1,
                (None, Some(s)) => s + 1,
                (Some(a), Some(b)) => a.max(b) + 1,
            }
        })?)
    }

    #[cfg(feature = "test_utils")]
    pub fn is_empty(&self) -> SourceChainResult<bool> {
        Ok(self.len()? == 0)
    }

    pub async fn valid_cap_grant(
        &self,
        check_function: GrantedFunction,
        check_agent: AgentPubKey,
        check_secret: Option<CapSecret>,
    ) -> SourceChainResult<Option<CapGrant>> {
        let author_grant = CapGrant::from(self.agent_pubkey().clone());
        if author_grant.is_valid(&check_function, &check_agent, check_secret.as_ref()) {
            // caller is source chain author
            return Ok(Some(author_grant));
        }

        // Remote caller. The candidate grants are read from the DhtStore, which
        // applies the access-type pre-filter and "not updated/deleted"
        // exclusion; the exact secret/assignee/function match remains the
        // authority of `CapGrant::is_valid` below.
        let cap_grants = self
            .dht_store
            .as_read()
            .valid_cap_grants(self.agent_pubkey(), check_secret.as_ref())
            .await?;
        // Loop over all found cap grants and check if one of them is valid for
        // assignee and function.
        for cap_grant in cap_grants {
            if cap_grant.is_valid(&check_function, &check_agent, check_secret.as_ref()) {
                return Ok(Some(cap_grant));
            }
        }
        Ok(None)
    }

    /// Query Actions in the source chain.
    ///
    /// This returns a Vec rather than an iterator because it is intended to be
    /// used by the `query` host function, which crosses the wasm boundary.
    ///
    /// Returns [`holochain_zome_types::prelude::Record`]s, matching
    /// [`DhtStore::source_chain_records`] filtered by `query`, with the scratch
    /// overlaid afterwards.
    ///
    /// Cost is bounded by the filter, not by the chain: a sequence range (and,
    /// alongside it or unbounded, the action-type and entry-hash filters) is
    /// applied in the SQL that reads the committed chain, and entries are
    /// loaded only for the records that survive the full filter.
    /// [`ChainQueryFilter::filter_actions`] is still the final authority over
    /// which records come back and in what order; see
    /// `committed_chain_prefilter` for why pushing the per-row predicates
    /// down cannot change that answer.
    pub async fn query(
        &self,
        query: QueryFilter,
    ) -> SourceChainResult<Vec<holochain_zome_types::prelude::Record>> {
        let public_only = self.public_only;
        let store = self.dht_store.as_read();

        // 1. The committed actions — headers only — narrowed in SQL.
        let entry_hashes = prefilter_entry_hashes(&query);
        let mut committed = store
            .source_chain_actions(
                self.author.as_ref(),
                committed_chain_prefilter(&query, entry_hashes.as_deref()),
            )
            .await?;

        // The store returns committed actions in ascending sequence order.
        // `order_descending` applies to the committed records only (the scratch
        // is always appended in ascending order below), so reverse the
        // committed actions for a descending query.
        if query.order_descending {
            committed.reverse();
        }

        // 2. The scratch, exactly as before: every uncommitted action, with its
        // in-memory entry when entries are requested.
        let scratch_records = self.scratch.apply(|scratch| {
            let mut scratch_records: Vec<_> = scratch
                .actions()
                .filter_map(|sah| {
                    let entry = match sah.action().entry_hash() {
                        Some(eh) if query.include_entries => scratch.get_entry(eh).ok()?,
                        _ => None,
                    };
                    let record_entry = RecordEntry::new(sah.action().entry_visibility(), entry);
                    Some(Record::new(sah.clone(), record_entry))
                })
                .collect();
            scratch_records.sort_unstable_by_key(|e| e.action().action_seq());
            scratch_records
        })?;

        // 3. The authoritative filter, over committed actions and scratch
        // records together (a hash-bounded range walks `prev_action` across
        // both).
        let candidates: Vec<QueryCandidate> = committed
            .into_iter()
            .map(QueryCandidate::Committed)
            .chain(scratch_records.into_iter().map(QueryCandidate::Scratch))
            .collect();
        let survivors = query.filter_actions(candidates);

        // 4. Entries for the surviving committed actions only, then the
        // records in the filter's order.
        let mut committed_survivors = Vec::new();
        let slots: Vec<Option<Record>> = survivors
            .into_iter()
            .map(|candidate| match candidate {
                QueryCandidate::Committed(sah) => {
                    committed_survivors.push(sah);
                    None
                }
                QueryCandidate::Scratch(record) => Some(record),
            })
            .collect();
        let committed_len = committed_survivors.len();
        let committed_records = store
            .source_chain_records_for_actions(
                self.author.as_ref(),
                committed_survivors,
                query.include_entries,
                public_only,
            )
            .await?;
        debug_assert_eq!(committed_records.len(), committed_len);
        let mut committed_records = committed_records.into_iter();

        Ok(slots
            .into_iter()
            .filter_map(|slot| slot.or_else(|| committed_records.next()))
            .collect())
    }

    /// The pre-pushdown implementation of [`query`](Self::query), kept
    /// verbatim as a test oracle: read the whole committed chain with entries,
    /// overlay the scratch, filter in Rust. Differential tests assert the two
    /// agree for every filter shape; nothing outside `cfg(test)` may call it.
    #[cfg(test)]
    pub(crate) async fn query_reference(
        &self,
        query: QueryFilter,
    ) -> SourceChainResult<Vec<holochain_zome_types::prelude::Record>> {
        let public_only = self.public_only;
        let mut records = self
            .dht_store
            .as_read()
            .source_chain_records(self.author.as_ref(), query.include_entries, public_only)
            .await?;
        if query.order_descending {
            records.reverse();
        }
        self.scratch.apply(|scratch| {
            let mut scratch_records: Vec<_> = scratch
                .actions()
                .filter_map(|sah| {
                    let entry = match sah.action().entry_hash() {
                        Some(eh) if query.include_entries => scratch.get_entry(eh).ok()?,
                        _ => None,
                    };
                    let record_entry = RecordEntry::new(sah.action().entry_visibility(), entry);
                    Some(Record::new(sah.clone(), record_entry))
                })
                .collect();
            scratch_records.sort_unstable_by_key(|e| e.action().action_seq());
            records.extend(scratch_records);
        })?;
        Ok(query.filter_records(records))
    }

    pub async fn get_chain_lock(&self) -> SourceChainResult<Option<ChainLock>> {
        // The chain lock lives in the DhtStore.
        Ok(self
            .dht_store
            .as_read()
            .get_chain_lock(self.author.as_ref().clone())
            .await?)
    }

    /// If there is a countersigning session get the
    /// CreateEntry op to send to the entry authorities.
    pub fn countersigning_op(&self) -> SourceChainResult<Option<ChainOp>> {
        let r = self.scratch.apply(|scratch| {
            scratch
                .entries()
                .find(|e| matches!(**e.1, Entry::CounterSign(_, _)))
                .and_then(|(entry_hash, entry)| {
                    scratch
                        .actions()
                        .find(|shh| {
                            shh.action()
                                .entry_hash()
                                .map(|eh| eh == entry_hash)
                                .unwrap_or(false)
                        })
                        .map(|shh| {
                            let signed_action =
                                SignedAction::new(shh.action().clone(), shh.signature().clone());
                            ChainOp::CreateEntry(signed_action, OpEntry::Present((**entry).clone()))
                        })
                })
        })?;
        Ok(r)
    }

    pub async fn dump(&self) -> SourceChainResult<SourceChainDump> {
        dump_state(&self.dht_store.as_read(), (*self.author).clone()).await
    }
}

/// A record candidate for [`SourceChain::query`]: a committed action whose
/// entry has not been read yet, or a scratch record (entry already in memory).
#[derive(Clone)]
enum QueryCandidate {
    Committed(SignedActionHashed),
    Scratch(Record),
}

impl holochain_zome_types::prelude::ActionSequenceAndHash for QueryCandidate {
    fn action_seq(&self) -> u32 {
        holochain_zome_types::prelude::ActionHashedContainer::action(self).action_seq()
    }

    fn address(&self) -> &ActionHash {
        holochain_zome_types::prelude::ActionHashedContainer::action_hash(self)
    }
}

impl holochain_zome_types::prelude::ActionHashedContainer for QueryCandidate {
    fn action(&self) -> &Action {
        match self {
            Self::Committed(sah) => sah.action(),
            Self::Scratch(record) => record.action(),
        }
    }

    fn action_hash(&self) -> &ActionHash {
        match self {
            Self::Committed(sah) => sah.as_hash(),
            Self::Scratch(record) => record.action_address(),
        }
    }
}

/// The entry hashes of `query` as a pre-filter slice, when there are few
/// enough to bind (above the cap the store would ignore them anyway, so they
/// are not even collected).
fn prefilter_entry_hashes(query: &QueryFilter) -> Option<Vec<EntryHash>> {
    query
        .entry_hashes
        .as_ref()
        .filter(|hashes| hashes.len() <= holochain_data::dht::MAX_PREFILTER_ENTRY_HASHES)
        .map(|hashes| hashes.iter().cloned().collect())
}

/// The SQL pre-filter for the committed half of [`SourceChain::query`].
///
/// Why this cannot change the result: under an `Unbounded` or
/// `ActionSeqRange` range, [`ChainQueryFilter::filter_actions`] is a
/// conjunction of independent per-record predicates — `seq` in range,
/// `action_type` in the list, `entry_hash` in the set — that keeps the
/// survivors in their input order. Removing, in SQL, only records one of those
/// predicates rejects therefore leaves the survivors and their order
/// unchanged; the Rust filter runs afterwards regardless. `entry_type` has no
/// column and stays Rust-side. When it is present without an explicit action
/// filter, only Create/Update can match (`Action::entry_type` returns None for
/// every other variant), so those action types are a safe SQL pre-filter.
///
/// A hash-bounded range (`ActionHashRange`, `ActionHashTerminated`) is a walk
/// along `prev_action` that happens BEFORE the per-record predicates; removing
/// any record (even one the predicates would reject) could cut the walk short.
/// Those ranges read the whole committed chain's actions, as before — but
/// still load entries only for the records that survive.
fn committed_chain_prefilter<'a>(
    query: &'a QueryFilter,
    entry_hashes: Option<&'a [EntryHash]>,
) -> holochain_data::dht::AuthorChainPrefilter<'a> {
    let seq_range = match &query.sequence_range {
        ChainQueryFilterRange::Unbounded => None,
        ChainQueryFilterRange::ActionSeqRange(start, end) => Some((*start, *end)),
        ChainQueryFilterRange::ActionHashRange(..)
        | ChainQueryFilterRange::ActionHashTerminated(..) => {
            return holochain_data::dht::AuthorChainPrefilter::default();
        }
    };
    holochain_data::dht::AuthorChainPrefilter {
        seq_range,
        action_types: query.action_type.as_deref().or_else(|| {
            query
                .entry_type
                .as_ref()
                .map(|_| &[ActionType::Create, ActionType::Update][..])
        }),
        entry_hashes,
    }
}

pub fn chain_lock_subject_for_entry(entry: Option<&Entry>) -> SourceChainResult<Vec<u8>> {
    Ok(match entry {
        // TODO document that this implies preflight requests must be unique. I.e. if you want to countersign the
        //      same thing with multiple groups, then you need to use different session times.
        Some(Entry::CounterSign(session_data, _)) => holo_hash::encode::blake2b_256(
            &holochain_serialized_bytes::encode(session_data.preflight_request())?,
        ),
        _ => Vec::with_capacity(0),
    })
}

/// Rebase a batch of actions onto a new chain head, re-signing each one.
async fn rebase_actions_on(
    keystore: &MetaLairClient,
    mut actions: Vec<SignedActionHashed>,
    mut head: HeadInfo,
) -> Result<Vec<SignedActionHashed>, ScratchError> {
    actions.sort_by_key(|shh| shh.action().action_seq());
    for shh in actions.iter_mut() {
        let mut action = shh.action().clone();
        holochain_zome_types::action::ActionExt::rebase_on(
            &mut action,
            head.action.clone(),
            head.seq,
            head.timestamp,
        )?;
        head.seq = action.action_seq();
        head.timestamp = action.timestamp();
        let hh = HoloHashed::<Action>::from_content_sync(action);
        head.action = hh.as_hash().clone();
        let new_shh = SignedActionHashed::sign(keystore, hh).await?;
        *shh = new_shh;
    }
    Ok(actions)
}

#[cfg_attr(feature = "instrument", tracing::instrument(skip_all))]
pub async fn genesis(
    dht_store: DhtStore,
    keystore: MetaLairClient,
    dna_hash: DnaHash,
    agent_pubkey: AgentPubKey,
    membrane_proof: Option<MembraneProof>,
) -> SourceChainResult<()> {
    // The genesis DNA action, uniquely, has no `prev_action`.
    let dna_header = ActionHeader {
        author: agent_pubkey.clone(),
        timestamp: Timestamp::now(),
        action_seq: 0,
        prev_action: None,
    };
    let dna_action = build_action(dna_header, ActionData::Dna(DnaData { dna_hash }));
    let dna_action_hashed = HoloHashed::<Action>::from_content_sync(dna_action);
    let dna_action = SignedActionHashed::sign(&keystore, dna_action_hashed).await?;
    let dna_action_address = dna_action.as_hash().clone();
    let dna_ops = produce_ops_from_record(&Record::new(dna_action.clone(), RecordEntry::NA));

    // create the agent validation entry and add it directly to the store
    let agent_validation_header = ActionHeader {
        author: agent_pubkey.clone(),
        timestamp: Timestamp::now(),
        action_seq: 1,
        prev_action: Some(dna_action_address),
    };
    let agent_validation_action = build_action(
        agent_validation_header,
        ActionData::AgentValidationPkg(AgentValidationPkgData { membrane_proof }),
    );
    let agent_validation_action_hashed =
        HoloHashed::<Action>::from_content_sync(agent_validation_action);
    let agent_validation_action =
        SignedActionHashed::sign(&keystore, agent_validation_action_hashed).await?;
    let avh_addr = agent_validation_action.as_hash().clone();
    let avh_ops = produce_ops_from_record(&Record::new(
        agent_validation_action.clone(),
        RecordEntry::NA,
    ));

    // create a agent chain record and add it directly to the store
    let agent_header = ActionHeader {
        author: agent_pubkey.clone(),
        timestamp: Timestamp::now(),
        action_seq: 2,
        prev_action: Some(avh_addr),
    };
    let agent_action = build_action(
        agent_header,
        ActionData::Create(CreateData {
            entry_type: EntryType::AgentPubKey,
            entry_hash: agent_pubkey.clone().into(),
        }),
    );
    let agent_action_hashed = HoloHashed::<Action>::from_content_sync(agent_action);
    let agent_action = SignedActionHashed::sign(&keystore, agent_action_hashed).await?;
    let agent_entry = Some(Entry::Agent(agent_pubkey.clone()));
    let agent_ops = produce_ops_from_record(&Record::new(
        agent_action.clone(),
        RecordEntry::new(
            agent_action.action().entry_visibility(),
            agent_entry.clone(),
        ),
    ));

    // The ops for all three genesis records, with hashes and basis already
    // computed by `produce_ops_from_record`.
    let ops_with_hashes_for_new_db: Vec<HashedChainOp> = dna_ops
        .into_iter()
        .chain(avh_ops)
        .chain(agent_ops)
        .collect();

    // Clone the actions and agent entry for the DhtStore write block below.
    let dna_action_for_new_db = dna_action.clone();
    let agent_validation_action_for_new_db = agent_validation_action.clone();
    let agent_action_for_new_db = agent_action.clone();
    // `agent_entry` is `Option<Entry>`; clone it for the DhtStore write block.
    let agent_entry_for_new_db = agent_entry.clone();
    // Entry hash for the agent entry (AgentPubKey → EntryHash via Into).
    let agent_entry_hash: EntryHash = agent_pubkey.into();

    // Write the genesis actions, entries and ops to the DhtStore.
    {
        let mut tx = dht_store
            .db()
            .begin()
            .await
            .map_err(SourceChainError::other)?;

        // Insert the public agent entry (Entry::Agent is always public).
        if let Some(entry) = &agent_entry_for_new_db {
            tx.insert_entry(&agent_entry_hash, entry)
                .await
                .map_err(SourceChainError::other)?;
        }

        // Insert all three genesis actions.
        let genesis_actions: &[&SignedActionHashed] = &[
            &dna_action_for_new_db,
            &agent_validation_action_for_new_db,
            &agent_action_for_new_db,
        ];
        for sah in genesis_actions {
            tx.insert_action(sah, Some(RecordValidity::Accepted))
                .await
                .map_err(SourceChainError::other)?;
        }

        // Insert chain ops for all three genesis actions.
        let genesis_entries_slice: Vec<EntryHashed> = agent_entry_for_new_db
            .as_ref()
            .map(|e| {
                vec![EntryHashed::with_pre_hashed(
                    e.clone(),
                    agent_entry_hash.clone(),
                )]
            })
            .unwrap_or_default();
        for op in &ops_with_hashes_for_new_db {
            let storage_center_loc = op.storage_center_loc;
            let timestamp = op.action.action().timestamp();

            let serialized_size = encoded_chain_op_size(op, &genesis_entries_slice);
            tx.insert_chain_op(holochain_data::dht::InsertChainOp {
                op_hash: &op.op_hash,
                action_hash: op.action_hash(),
                op_type: i64::from(op.op_type),
                basis_hash: &op.basis_hash,
                storage_center_loc,
                validation_status: RecordValidity::Accepted,
                locally_validated: true,
                require_receipt: false,
                when_received: timestamp,
                when_integrated: timestamp,
                serialized_size,
            })
            .await
            .map_err(SourceChainError::other)?;

            tx.insert_chain_op_publish(&op.op_hash, None, None, None)
                .await
                .map_err(SourceChainError::other)?;
        }

        tx.commit().await.map_err(SourceChainError::other)?;
    }

    Ok(())
}

pub type CurrentCountersigningSessionOpt = Option<(Record, EntryHash, CounterSigningSessionData)>;

/// Dump the entire source chain from the DhtStore.
///
/// Private entries are included — the query looks in both the public `Entry`
/// table and the author's `PrivateEntry` table — so the dump faithfully
/// reflects the author's own chain. `published_ops_count` is the number of
/// integrated ops that have been published at least once.
///
/// This is the production path backing the admin `DumpState` and `DumpFullState`
/// APIs.
#[cfg_attr(feature = "instrument", tracing::instrument(skip_all))]
pub async fn dump_state(
    dht_store: &DhtStoreRead,
    author: AgentPubKey,
) -> Result<SourceChainDump, SourceChainError> {
    dump_state_paginated(dht_store, author, None, None).await
}

/// Dump one exclusive page of an author's source chain.
///
/// # Errors
///
/// Returns an error for invalid pagination arguments or a failed state query.
#[cfg_attr(feature = "instrument", tracing::instrument(skip_all))]
pub async fn dump_state_paginated(
    dht_store: &DhtStoreRead,
    author: AgentPubKey,
    cursor: Option<&SourceChainCursor>,
    limit: Option<u32>,
) -> Result<SourceChainDump, SourceChainError> {
    dht_store
        .dump_source_chain_paginated(&author, cursor, limit)
        .await
        .map_err(SourceChainError::other)
}

// ---------------------------------------------------------------------------
// Private helpers for the new-DB writes in `flush` and `genesis`
// ---------------------------------------------------------------------------

/// Return the `(cap_access_i64, Option<tag>)` parameters needed for
/// `TxWrite::insert_cap_grant`, if the given action creates/updates a
/// `CapGrant` entry. Returns `None` for all other action types.
///
/// The entry content is needed to extract the tag; entries are looked up by
/// the entry hash carried by the action.
fn cap_grant_index_params(
    shh: &SignedActionHashed,
    entries: &[EntryHashed],
) -> Option<(i64, Option<String>)> {
    let (entry_type, entry_hash) = match &shh.action().data {
        ActionData::Create(d) => (&d.entry_type, &d.entry_hash),
        ActionData::Update(d) => (&d.entry_type, &d.entry_hash),
        _ => return None,
    };

    if !matches!(entry_type, EntryType::CapGrant) {
        return None;
    }

    // Find the matching entry in the scratch batch.
    let entry = entries
        .iter()
        .find(|e| e.as_hash() == entry_hash)?
        .as_content();

    let cap_grant = match entry {
        Entry::CapGrant(g) => g,
        _ => return None,
    };

    let cap_access_i64 = match &cap_grant.access {
        CapAccess::Unrestricted => 0_i64,
        CapAccess::Transferable { .. } => 1_i64,
        CapAccess::Assigned { .. } => 2_i64,
    };
    // Deliberate empty→NULL normalisation: the schema stores an absent tag as
    // NULL rather than an empty string.
    let tag = if cap_grant.tag.is_empty() {
        None
    } else {
        Some(cap_grant.tag.clone())
    };

    Some((cap_access_i64, tag))
}

/// Serialize `None` as an `Option<Schedule>` blob.
///
/// `None` is serialized via
/// `holochain_serialized_bytes::encode(&None::<Schedule>)`.
fn serialize_maybe_schedule_none(
) -> Result<Vec<u8>, holochain_serialized_bytes::SerializedBytesError> {
    holochain_serialized_bytes::encode(&None::<holochain_zome_types::schedule::Schedule>)
}

/// Encode the wire-form `DhtOp` for a [`HashedChainOp`] and return its
/// serialized length in bytes. The action is already carried on `op`; the
/// entry (if any) is looked up by `Action::entry_hash` in `entries`. Always
/// succeeds: `op`'s `op_type` was derived from its own action by
/// `produce_ops_from_record`, so the two always agree.
pub(crate) fn encoded_chain_op_size(op: &HashedChainOp, entries: &[EntryHashed]) -> u32 {
    let action = op.action.action();
    let maybe_entry: Option<Entry> = action
        .entry_hash()
        .and_then(|eh| entries.iter().find(|e| e.as_hash() == eh))
        .map(|e| e.as_content().clone());
    let signed_action = SignedAction::new(action.clone(), op.action.signature().clone());
    let op_entry = |entry: Option<Entry>| match entry {
        Some(entry) => OpEntry::Present(entry),
        // No privacy signal is available here (only whether the entry was
        // found in `entries`); `ActionOnly` is the conservative choice — see
        // `chain_op_from_joined_row`'s NotStored/NA → ActionOnly mapping.
        None => OpEntry::ActionOnly,
    };

    let chain_op = ChainOp::from_type(op.op_type, signed_action, op_entry(maybe_entry));
    holochain_serialized_bytes::encode(&DhtOp::ChainOp(Box::new(chain_op)))
        .map(|b| b.len() as u32)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source_chain::SourceChainResult;
    use ::fixt::fixt;
    use ::fixt::prelude::*;
    use holo_hash::fixt::DnaHashFixturator;
    use holo_hash::fixt::{ActionHashFixturator, AgentPubKeyFixturator, EntryHashFixturator};
    use holochain_keystore::test_keystore;
    use holochain_zome_types::prelude::{CloseChainData, Entry, InitZomesCompleteData, UpdateData};
    use matches::assert_matches;
    use std::collections::{BTreeSet, HashSet};

    #[tokio::test(flavor = "multi_thread")]
    async fn test_relaxed_ordering() -> SourceChainResult<()> {
        let TestCase {
            chain: chain_1,
            agent_key: alice,
            dht_store,
            keystore,
            ..
        } = TestCase::new().await;

        let chain_2 = SourceChain::new(dht_store.clone(), keystore.clone(), alice.clone()).await?;
        let chain_3 = SourceChain::new(dht_store.clone(), keystore.clone(), alice.clone()).await?;

        let close_chain = ActionData::CloseChain(CloseChainData { new_target: None });
        chain_1
            .put(close_chain.clone(), None, ChainTopOrdering::Strict)
            .await?;
        chain_2
            .put(close_chain.clone(), None, ChainTopOrdering::Strict)
            .await?;
        chain_3
            .put(close_chain, None, ChainTopOrdering::Relaxed)
            .await?;

        let storage_arcs = vec![DhtArc::Empty];
        chain_1.flush(storage_arcs.clone()).await?;
        // Read the chain head from the DhtStore.
        let seq = dht_store
            .as_read()
            .chain_head_for_author(&alice)
            .await?
            .expect("chain head present after flush")
            .seq;
        assert_eq!(seq, 3);

        assert!(matches!(
            chain_2.flush(storage_arcs.clone()).await,
            Err(SourceChainError::HeadMoved(_, _, _, _))
        ));
        // Read the chain head from the DhtStore.
        let seq = dht_store
            .as_read()
            .chain_head_for_author(&alice)
            .await?
            .expect("chain head present after flush")
            .seq;
        assert_eq!(seq, 3);

        chain_3.flush(storage_arcs).await?;
        // Read the chain head from the DhtStore.
        let seq = dht_store
            .as_read()
            .chain_head_for_author(&alice)
            .await?
            .expect("chain head present after flush")
            .seq;
        assert_eq!(seq, 4);

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_relaxed_ordering_with_entry() -> SourceChainResult<()> {
        let TestCase {
            chain: chain_1,
            agent_key: alice,
            dht_store,
            keystore,
            ..
        } = TestCase::new().await;

        let chain_2 = SourceChain::new(dht_store.clone(), keystore.clone(), alice.clone()).await?;
        let chain_3 = SourceChain::new(dht_store.clone(), keystore.clone(), alice.clone()).await?;

        let entry_1 = Entry::App(fixt!(AppEntryBytes));
        let eh1 = EntryHash::with_data_sync(&entry_1);
        let create = ActionData::Create(CreateData {
            entry_type: EntryType::App(fixt!(AppEntryDef)),
            entry_hash: eh1.clone(),
        });
        let h1 = chain_1
            .put(create, Some(entry_1.clone()), ChainTopOrdering::Strict)
            .await
            .unwrap();

        let entry_err = Entry::App(fixt!(AppEntryBytes));
        let entry_hash_err = EntryHash::with_data_sync(&entry_err);
        let create = ActionData::Create(CreateData {
            entry_type: EntryType::App(fixt!(AppEntryDef)),
            entry_hash: entry_hash_err.clone(),
        });
        chain_2
            .put(create, Some(entry_err.clone()), ChainTopOrdering::Strict)
            .await
            .unwrap();

        let entry_2 = Entry::App(fixt!(AppEntryBytes));
        let eh2 = EntryHash::with_data_sync(&entry_2);
        let create = ActionData::Create(CreateData {
            entry_type: EntryType::App(AppEntryDef::new(
                EntryDefIndex(0),
                0.into(),
                EntryVisibility::Private,
            )),
            entry_hash: eh2.clone(),
        });
        let old_h2 = chain_3
            .put(create, Some(entry_2.clone()), ChainTopOrdering::Relaxed)
            .await
            .unwrap();

        let storage_arcs = vec![DhtArc::Empty];
        chain_1.flush(storage_arcs.clone()).await?;
        // Read the chain head from the DhtStore.
        let seq = dht_store
            .as_read()
            .chain_head_for_author(&alice)
            .await?
            .expect("chain head present after flush")
            .seq;
        assert_eq!(seq, 3);

        assert!(matches!(
            chain_2.flush(storage_arcs.clone()).await,
            Err(SourceChainError::HeadMoved(_, _, _, _))
        ));

        chain_3.flush(storage_arcs).await?;
        // Read the chain head from the DhtStore.
        let head = dht_store
            .as_read()
            .chain_head_for_author(&alice)
            .await?
            .expect("chain head present after flush");

        // not equal since action hash change due to rebasing
        assert_ne!(head.action, old_h2);
        assert_eq!(head.seq, 4);

        // The full records are read from the DhtStore. h1 is public; h2 (the
        // head) is a private entry, so the author key is passed so the store
        // attaches the author's `PrivateEntry`.
        let h1_record_entry_fetched = dht_store
            .as_read()
            .retrieve_record(&h1, Some(&alice))
            .await?
            .expect("h1 record present in store")
            .into_inner()
            .1;
        let h2_record_entry_fetched = dht_store
            .as_read()
            .retrieve_record(&head.action, Some(&alice))
            .await?
            .expect("h2 record present in store")
            .into_inner()
            .1;
        assert_eq!(RecordEntry::Present(entry_1), h1_record_entry_fetched);
        assert_eq!(RecordEntry::Present(entry_2), h2_record_entry_fetched);

        Ok(())
    }

    // The genesis agent-key `Create` is read back from the DhtStore as the
    // valid agent-key action.
    #[tokio::test(flavor = "multi_thread")]
    async fn valid_create_agent_key_action_reads_from_store() {
        let TestCase {
            chain, agent_key, ..
        } = TestCase::new().await;

        let action = chain.valid_create_agent_key_action().await.unwrap();

        // The returned action is the agent-key `Create`: an `AgentPubKey`-typed
        // `Create` whose entry hash is the agent key.
        assert_matches!(action.data, ActionData::Create(_));
        assert_eq!(action.entry_type(), Some(&EntryType::AgentPubKey));
        let agent_key_entry_hash: EntryHash = agent_key.into();
        assert_eq!(action.entry_hash(), Some(&agent_key_entry_hash));
    }

    // Test that a valid agent pub key can be deleted and that repeated deletes fail.
    #[tokio::test(flavor = "multi_thread")]
    async fn delete_valid_agent_pub_key() {
        let TestCase { chain, .. } = TestCase::new().await;

        let result = chain.delete_valid_agent_pub_key().await;
        assert!(result.is_ok());
        chain.flush(vec![DhtArc::Empty]).await.unwrap();

        // Valid agent pub key has been deleted. Repeating the operation should fail now as no valid
        // pub key can be found.
        let result = chain.delete_valid_agent_pub_key().await.unwrap_err();
        assert_matches!(result, SourceChainError::InvalidAgentKey(invalid_key, cell_id) if invalid_key == *chain.author && cell_id == *chain.cell_id());
    }

    // An `Update` targeting the agent-key entry invalidates the key, just like
    // a `Delete` does, so `valid_create_agent_key_action` returns
    // `InvalidAgentKey`.
    #[tokio::test(flavor = "multi_thread")]
    async fn updated_agent_key_is_invalid() {
        let TestCase {
            chain, agent_key, ..
        } = TestCase::new().await;

        // Valid before any modification.
        let create = chain.valid_create_agent_key_action().await.unwrap();
        let agent_key_entry_hash: EntryHash = agent_key.clone().into();

        // Author an `Update` whose original entry is the agent-key entry. This
        // populates the `UpdatedRecord` index (keyed on `original_entry_hash`)
        // for the agent key.
        let action_data = ActionData::Update(UpdateData {
            entry_type: EntryType::AgentPubKey,
            entry_hash: agent_key_entry_hash.clone(),
            original_action_address: create.to_hash(),
            original_entry_address: agent_key_entry_hash,
        });
        chain
            .put(
                action_data,
                Some(Entry::Agent(agent_key.clone())),
                ChainTopOrdering::default(),
            )
            .await
            .unwrap();
        chain.flush(vec![DhtArc::Empty]).await.unwrap();

        let result = chain.valid_create_agent_key_action().await.unwrap_err();
        assert_matches!(
            result,
            SourceChainError::InvalidAgentKey(invalid_key, _) if invalid_key == agent_key
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_get_cap_grant() -> SourceChainResult<()> {
        let TestCase {
            chain,
            agent_key: alice,
            dht_store,
            keystore,
            ..
        } = TestCase::new().await;

        let secret = Some(CapSecretFixturator::new(Unpredictable).next().unwrap());
        // create transferable cap grant
        #[allow(clippy::unnecessary_literal_unwrap)] // must be this type
        let secret_access = CapAccess::from(secret.unwrap());

        // @todo curry
        let _curry = CurryPayloadsFixturator::new(Empty).next().unwrap();
        let function: GrantedFunction = ("foo".into(), "bar".into());
        let mut fns = HashSet::new();
        fns.insert(function.clone());
        let functions = GrantedFunctions::Listed(fns);
        let grant = ZomeCallCapGrant::new("tag".into(), secret_access.clone(), functions.clone());

        let bob = keystore.new_sign_keypair_random().await.unwrap();
        let carol = keystore.new_sign_keypair_random().await.unwrap();

        // alice as chain author always has a valid cap grant; provided secrets
        // are ignored
        assert_eq!(
            chain
                .valid_cap_grant(function.clone(), alice.clone(), secret)
                .await?,
            Some(CapGrant::ChainAuthor(alice.clone())),
        );

        // bob should not get a cap grant as the secret hasn't been committed yet
        assert_eq!(
            chain
                .valid_cap_grant(function.clone(), bob.clone(), secret)
                .await?,
            None
        );

        let storage_arcs = vec![DhtArc::Empty];

        // write cap grant to alice's source chain
        let (original_action_address, original_entry_address) = {
            let (entry, entry_hash) =
                EntryHashed::from_content_sync(Entry::CapGrant(grant.clone())).into_inner();
            let action_data = ActionData::Create(CreateData {
                entry_type: EntryType::CapGrant,
                entry_hash: entry_hash.clone(),
            });
            let action = chain
                .put(action_data, Some(entry), ChainTopOrdering::default())
                .await?;

            chain.flush(storage_arcs.clone()).await.unwrap();
            (action, entry_hash)
        };

        // alice should find her own authorship with higher priority than the
        // committed grant even if she passes in the secret
        assert_eq!(
            chain
                .valid_cap_grant(function.clone(), alice.clone(), secret)
                .await?,
            Some(CapGrant::ChainAuthor(alice.clone())),
        );

        // bob and carol (and everyone else) should be authorized with transferable cap grant
        // when passing in the secret
        assert_eq!(
            chain
                .valid_cap_grant(function.clone(), bob.clone(), secret)
                .await?,
            Some(grant.clone().into())
        );
        assert_eq!(
            chain
                .valid_cap_grant(function.clone(), carol.clone(), secret)
                .await?,
            Some(grant.clone().into())
        );
        // bob should not be authorized for other zomes/functions than the ones granted
        assert_eq!(
            chain
                .valid_cap_grant(("boo".into(), "far".into()), bob.clone(), secret)
                .await?,
            None
        );

        // convert transferable cap grant to assigned with bob as assignee
        let mut assignees = BTreeSet::new();
        assignees.insert(bob.clone());
        let updated_secret = Some(CapSecretFixturator::new(Unpredictable).next().unwrap());
        #[allow(clippy::unnecessary_literal_unwrap)] // must be this type
        let updated_access = CapAccess::from((updated_secret.unwrap(), assignees));
        let updated_grant = ZomeCallCapGrant::new("tag".into(), updated_access.clone(), functions);

        // commit grant update to alice's source chain
        let (updated_action_hash, updated_entry_hash) = {
            let chain =
                SourceChain::new(dht_store.clone(), keystore.clone(), alice.clone()).await?;
            let (entry, entry_hash) =
                EntryHashed::from_content_sync(Entry::CapGrant(updated_grant.clone())).into_inner();
            let action_data = ActionData::Update(UpdateData {
                entry_type: EntryType::CapGrant,
                entry_hash: entry_hash.clone(),
                original_action_address,
                original_entry_address,
            });
            let action = chain
                .put(action_data, Some(entry), ChainTopOrdering::default())
                .await?;
            chain.flush(storage_arcs.clone()).await.unwrap();

            (action, entry_hash)
        };

        // alice as chain owner should be unaffected by updates
        // chain author grant should always be returned
        assert_eq!(
            chain
                .valid_cap_grant(function.clone(), alice.clone(), secret)
                .await?,
            Some(CapGrant::ChainAuthor(alice.clone())),
        );
        assert_eq!(
            chain
                .valid_cap_grant(function.clone(), alice.clone(), updated_secret)
                .await?,
            Some(CapGrant::ChainAuthor(alice.clone())),
        );

        // bob must not get a valid cap grant with the initial cap secret,
        // as it is invalidated by the cap grant update
        assert_eq!(
            chain
                .valid_cap_grant(function.clone(), bob.clone(), secret)
                .await?,
            None
        );
        // when bob provides the updated secret, validation should succeed,
        // bob being an assignee
        assert_eq!(
            chain
                .valid_cap_grant(function.clone(), bob.clone(), updated_secret)
                .await?,
            Some(updated_grant.clone().into())
        );

        // carol must not get a valid cap grant with either the original secret (because it was replaced)
        // or the updated secret (because she is not an assignee)
        assert_eq!(
            chain
                .valid_cap_grant(function.clone(), carol.clone(), secret)
                .await?,
            None
        );
        assert_eq!(
            chain
                .valid_cap_grant(function.clone(), carol.clone(), updated_secret)
                .await?,
            None
        );

        // Two source chains of the same DNA on the same conductor share DB tables.
        // That could lead to cap grants looked up by their secret alone being
        // returned for any agent on the conductor,in this case for alice trying
        // to access carol's chain
        {
            let extra_dht_store = crate::test_utils::test_dht_store(fake_dna_hash(1)).await;
            genesis(
                extra_dht_store.clone(),
                keystore.clone(),
                fake_dna_hash(1),
                carol.clone(),
                None,
            )
            .await
            .unwrap();
            let carol_chain = SourceChain::new(extra_dht_store, keystore.clone(), carol.clone())
                .await
                .unwrap();
            let maybe_cap_grant = carol_chain
                .valid_cap_grant(("".into(), "".into()), alice.clone(), secret)
                .await
                .unwrap();
            assert_eq!(maybe_cap_grant, None);
        }

        // delete updated cap grant
        {
            let chain =
                SourceChain::new(dht_store.clone(), keystore.clone(), alice.clone()).await?;
            let action_data = ActionData::Delete(DeleteData {
                deletes_address: updated_action_hash,
                deletes_entry_address: updated_entry_hash,
            });
            chain
                .put(action_data, None, ChainTopOrdering::default())
                .await?;
            chain.flush(storage_arcs.clone()).await.unwrap();
        }

        // alice should get her author cap grant as always, independent of
        // any provided secret
        assert_eq!(
            chain
                .valid_cap_grant(function.clone(), alice.clone(), secret)
                .await?,
            Some(CapGrant::ChainAuthor(alice.clone())),
        );
        assert_eq!(
            chain
                .valid_cap_grant(function.clone(), alice.clone(), updated_secret)
                .await?,
            Some(CapGrant::ChainAuthor(alice.clone())),
        );

        // bob should not get a cap grant for any secret anymore
        assert_eq!(
            chain
                .valid_cap_grant(function.clone(), bob.clone(), secret)
                .await?,
            None
        );
        assert_eq!(
            chain
                .valid_cap_grant(function.clone(), bob.clone(), updated_secret)
                .await?,
            None
        );

        // create an unrestricted cap grant in alice's chain
        let unrestricted_grant = ZomeCallCapGrant::new(
            "unrestricted".into(),
            CapAccess::Unrestricted,
            GrantedFunctions::All,
        );
        let (original_action_address, original_entry_address) = {
            let chain =
                SourceChain::new(dht_store.clone(), keystore.clone(), alice.clone()).await?;
            let (entry, entry_hash) =
                EntryHashed::from_content_sync(Entry::CapGrant(unrestricted_grant.clone()))
                    .into_inner();
            let action_data = ActionData::Create(CreateData {
                entry_type: EntryType::CapGrant,
                entry_hash: entry_hash.clone(),
            });
            let action = chain
                .put(action_data, Some(entry), ChainTopOrdering::default())
                .await?;
            chain.flush(storage_arcs.clone()).await.unwrap();
            (action, entry_hash)
        };

        // bob should get a cap grant for any zome and function
        let granted_function: GrantedFunction = ("zome".into(), "fn".into());
        assert_eq!(
            chain
                .valid_cap_grant(granted_function.clone(), bob.clone(), None)
                .await?,
            Some(unrestricted_grant.clone().into())
        );
        // carol should get a cap grant now too
        assert_eq!(
            chain
                .valid_cap_grant(granted_function.clone(), carol.clone(), None)
                .await?,
            Some(unrestricted_grant.clone().into())
        );
        // but not for bob's chain
        //
        // Two source chains of the same DNA on the same conductor share DB tables.
        // That could lead to cap grants looked up by being unrestricted alone
        // being returned for any agent on the conductor.
        // In this case carol should not get an unrestricted cap grant for
        // bob's chain.
        {
            {
                let extra_dht_store = crate::test_utils::test_dht_store(fake_dna_hash(1)).await;
                genesis(
                    extra_dht_store.clone(),
                    keystore.clone(),
                    fake_dna_hash(1),
                    bob.clone(),
                    None,
                )
                .await
                .unwrap();
                let bob_chain = SourceChain::new(extra_dht_store, keystore.clone(), bob.clone())
                    .await
                    .unwrap();
                let maybe_cap_grant = bob_chain
                    .valid_cap_grant(("".into(), "".into()), carol.clone(), None)
                    .await
                    .unwrap();
                assert_eq!(maybe_cap_grant, None);
            }
        }

        // delete unrestricted cap grant
        {
            let chain =
                SourceChain::new(dht_store.clone(), keystore.clone(), alice.clone()).await?;
            let action_data = ActionData::Delete(DeleteData {
                deletes_address: original_action_address,
                deletes_entry_address: original_entry_address,
            });
            chain
                .put(action_data, None, ChainTopOrdering::default())
                .await?;
            chain.flush(storage_arcs.clone()).await.unwrap();
        }

        // bob must not get unrestricted cap grant any longer
        assert_eq!(
            chain
                .valid_cap_grant(granted_function.clone(), bob.clone(), None)
                .await?,
            None
        );

        // Create two unrestricted cap grants in alice's chain to make sure
        // that all of them are considered when checking grant validity
        // instead of only the first cap grant found.

        // first unrestricted cap grant with irrelevant zome and fn
        let some_zome_name: ZomeName = "some_zome".into();
        let some_fn_name: FunctionName = "some_fn".into();
        let mut granted_fns = HashSet::new();
        granted_fns.insert((some_zome_name.clone(), some_fn_name.clone()));
        let first_unrestricted_grant = ZomeCallCapGrant::new(
            "unrestricted_1".into(),
            CapAccess::Unrestricted,
            GrantedFunctions::Listed(granted_fns),
        );

        // second unrestricted cap grant with the actually granted zome and fn
        let granted_zome_name: ZomeName = "granted_zome".into();
        let granted_fn_name: FunctionName = "granted_fn".into();
        let mut granted_fns = HashSet::new();
        granted_fns.insert((granted_zome_name.clone(), granted_fn_name.clone()));
        let second_unrestricted_grant = ZomeCallCapGrant::new(
            "unrestricted_2".into(),
            CapAccess::Unrestricted,
            GrantedFunctions::Listed(granted_fns),
        );

        {
            let chain =
                SourceChain::new(dht_store.clone(), keystore.clone(), alice.clone()).await?;

            // commit first grant to alice's chain
            let (entry, entry_hash) =
                EntryHashed::from_content_sync(Entry::CapGrant(first_unrestricted_grant.clone()))
                    .into_inner();
            let action_data = ActionData::Create(CreateData {
                entry_type: EntryType::CapGrant,
                entry_hash: entry_hash.clone(),
            });
            let _ = chain
                .put(action_data, Some(entry), ChainTopOrdering::default())
                .await?;

            // commit second grant to alice's chain
            let (entry, entry_hash) =
                EntryHashed::from_content_sync(Entry::CapGrant(second_unrestricted_grant.clone()))
                    .into_inner();
            let action_data = ActionData::Create(CreateData {
                entry_type: EntryType::CapGrant,
                entry_hash: entry_hash.clone(),
            });
            let _ = chain
                .put(action_data, Some(entry), ChainTopOrdering::default())
                .await?;

            chain.flush(storage_arcs).await.unwrap();
        }

        let actual_cap_grant = chain
            .valid_cap_grant((granted_zome_name, granted_fn_name), bob, None)
            .await
            .unwrap();
        assert_eq!(actual_cap_grant, Some(second_unrestricted_grant.into()));

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn source_chain_buffer_iter_back() -> SourceChainResult<()> {
        holochain_trace::test_run();
        let keystore = test_keystore();
        let dna_hash = fixt!(DnaHash);
        let dht_store = crate::test_utils::test_dht_store(dna_hash.clone()).await;

        let author = Arc::new(keystore.new_sign_keypair_random().await.unwrap());

        genesis(
            dht_store.clone(),
            keystore.clone(),
            dna_hash,
            (*author).clone(),
            None,
        )
        .await
        .unwrap();

        let source_chain = SourceChain::new(dht_store.clone(), keystore.clone(), (*author).clone())
            .await
            .unwrap();
        let entry = Entry::App(fixt!(AppEntryBytes));
        let create = ActionData::Create(CreateData {
            entry_type: EntryType::App(fixt!(AppEntryDef)),
            entry_hash: EntryHash::with_data_sync(&entry),
        });
        let h1 = source_chain
            .put(create, Some(entry), ChainTopOrdering::default())
            .await
            .unwrap();
        let entry = Entry::App(fixt!(AppEntryBytes));
        let create = ActionData::Create(CreateData {
            entry_type: EntryType::App(fixt!(AppEntryDef)),
            entry_hash: EntryHash::with_data_sync(&entry),
        });
        let h2 = source_chain
            .put(create, Some(entry), ChainTopOrdering::default())
            .await
            .unwrap();
        source_chain.flush(vec![DhtArc::Empty]).await.unwrap();

        // The head and full records are read from the DhtStore.
        let head = dht_store
            .as_read()
            .chain_head_for_author(author.as_ref())
            .await?
            .expect("chain head present after flush");
        assert_eq!(head.action, h2);

        let h1_record_fetched = dht_store
            .as_read()
            .retrieve_record(&h1, Some(author.as_ref()))
            .await?
            .expect("h1 record present in store");
        let h2_record_fetched = dht_store
            .as_read()
            .retrieve_record(&h2, Some(author.as_ref()))
            .await?
            .expect("h2 record present in store");
        assert_eq!(h1, *h1_record_fetched.action_address());
        assert_eq!(h2, *h2_record_fetched.action_address());

        // check that you can iterate on the chain
        let source_chain = SourceChain::new(dht_store.clone(), keystore.clone(), (*author).clone())
            .await
            .unwrap();
        let res = source_chain.query(QueryFilter::new()).await.unwrap();
        assert_eq!(res.len(), 5);
        assert_eq!(*res[3].action_address(), h1);
        assert_eq!(*res[4].action_address(), h2);

        Ok(())
    }

    /// After `genesis`, the store reports the author has done genesis, the
    /// chain head is the seq-2 AgentId `Create`, and the head record is
    /// retrievable from the store.
    #[tokio::test(flavor = "multi_thread")]
    async fn genesis_writes_to_merged_store() -> SourceChainResult<()> {
        holochain_trace::test_run();
        let keystore = test_keystore();
        let dna_hash = fixt!(DnaHash);
        let dht_store = crate::test_utils::test_dht_store(dna_hash.clone()).await;
        let author = keystore.new_sign_keypair_random().await.unwrap();

        genesis(
            dht_store.clone(),
            keystore.clone(),
            dna_hash,
            author.clone(),
            None,
        )
        .await
        .unwrap();

        let store = dht_store.as_read();

        // `has_genesis` requires all three genesis actions to be present.
        assert!(store.has_genesis(&author).await?);

        // The chain head is the seq-2 AgentId `Create`.
        let head = store
            .chain_head_for_author(&author)
            .await?
            .expect("chain head present after genesis");
        assert_eq!(head.seq, 2);

        let head_record = store
            .retrieve_record(&head.action, Some(&author))
            .await?
            .expect("head record present in store");
        assert_eq!(head_record.action().action_seq(), 2);
        assert!(matches!(head_record.action().data, ActionData::Create(_)));

        Ok(())
    }

    /// The publish selector admits only ops that are `locally_validated = 1`
    /// with a `ChainOpPublish` row (the FK-787 livelock cure). That must never
    /// delay an author's OWN fresh ops: the flush writes the `ChainOp` row with
    /// `locally_validated = 1` and its `ChainOpPublish` row in the same
    /// transaction, so a just-committed op is selectable on the very next
    /// publish loop, with no local-validation round-trip in between.
    #[tokio::test(flavor = "multi_thread")]
    async fn freshly_authored_ops_are_publishable_immediately() -> SourceChainResult<()> {
        let TestCase {
            chain,
            agent_key,
            dht_store,
            ..
        } = TestCase::new().await;

        let before: HashSet<DhtOpHash> = dht_store
            .as_read()
            .get_ops_to_publish(&agent_key, std::time::Duration::ZERO)
            .await?
            .into_iter()
            .map(|(_, op)| op.hash)
            .collect();
        let needing_before = dht_store
            .as_read()
            .num_still_needing_publish(&agent_key)
            .await?;

        let entry = Entry::App(fixt!(AppEntryBytes));
        let entry_hash = EntryHash::with_data_sync(&entry);
        let create = ActionData::Create(CreateData {
            entry_type: EntryType::App(AppEntryDef::new(
                0.into(),
                0.into(),
                EntryVisibility::Public,
            )),
            entry_hash,
        });
        chain
            .put(create, Some(entry), ChainTopOrdering::default())
            .await?;
        chain.flush(vec![DhtArc::Empty]).await?;

        let after = dht_store
            .as_read()
            .get_ops_to_publish(&agent_key, std::time::Duration::ZERO)
            .await?;
        let fresh: Vec<_> = after
            .iter()
            .filter(|(_, op)| !before.contains(&op.hash))
            .collect();
        // A public Create yields StoreRecord, StoreEntry and RegisterAgentActivity.
        assert_eq!(
            fresh.len(),
            3,
            "every op of the freshly authored public Create must be selected at once"
        );
        assert!(fresh
            .iter()
            .all(|(_, op)| op.kind == crate::dht_store::PublishOpKind::ChainOp));
        assert_eq!(
            dht_store
                .as_read()
                .num_still_needing_publish(&agent_key)
                .await?,
            needing_before + 3,
            "the fresh ops keep the publish loop alive until their receipts complete"
        );
        Ok(())
    }

    /// Verify that `DhtStore::dump_source_chain` returns records in seq order,
    /// resolves private-entry records' entry data from `PrivateEntry`, and
    /// reports the correct published-op count.
    #[tokio::test(flavor = "multi_thread")]
    async fn dump_state_from_store() -> SourceChainResult<()> {
        let TestCase {
            chain,
            agent_key,
            dht_store,
            keystore,
        } = TestCase::new().await;

        // Add a private-entry action (seq 3) on top of the genesis 3-action chain.
        let private_entry = Entry::App(fixt!(AppEntryBytes));
        let private_entry_hash = EntryHash::with_data_sync(&private_entry);
        let create = ActionData::Create(CreateData {
            entry_type: EntryType::App(AppEntryDef::new(
                0.into(),
                0.into(),
                EntryVisibility::Private,
            )),
            entry_hash: private_entry_hash.clone(),
        });
        chain
            .put(
                create,
                Some(private_entry.clone()),
                ChainTopOrdering::default(),
            )
            .await?;
        chain.flush(vec![DhtArc::Empty]).await?;

        let dump = dht_store.as_read().dump_source_chain(&agent_key).await?;

        // Four records: Dna(0), AgentValidationPkg(1), Create/AgentId(2), Create/Private(3).
        assert_eq!(
            dump.records.len(),
            4,
            "expected 4 records after genesis + 1"
        );

        // Verify seq order.
        for (i, rec) in dump.records.iter().enumerate() {
            assert_eq!(rec.action.action_seq(), i as u32, "record {i} out of order");
        }

        // The private-entry record (seq 3) must expose its entry.
        let private_rec = &dump.records[3];
        assert_eq!(
            private_rec.entry.as_ref(),
            Some(&private_entry),
            "private-entry record must include the entry"
        );

        // No publishing has occurred — published_ops_count must be 0.
        assert_eq!(
            dump.published_ops_count, 0,
            "no ops have been published yet"
        );

        let published_op = dht_store
            .as_read()
            .ops_to_publish_for_wire(&agent_key)
            .await?
            .into_iter()
            .next()
            .expect("at least one authored op");
        dht_store
            .record_published_op_hashes(
                vec![crate::dht_store::PublishableOp {
                    hash: DhtOpHash::from_raw_36(published_op.op_hash),
                    kind: crate::dht_store::PublishOpKind::ChainOp,
                }],
                Timestamp::now(),
            )
            .await?;

        let first_page = dht_store
            .as_read()
            .dump_source_chain_paginated(&agent_key, None, Some(2))
            .await?;
        assert_eq!(first_page.records.len(), 2);
        assert_eq!(first_page.records, dump.records[..2]);
        assert_eq!(first_page.published_ops_count, 1);

        let sequence_page = dht_store
            .as_read()
            .dump_source_chain_paginated(
                &agent_key,
                Some(&SourceChainCursor::Sequence(1)),
                Some(10),
            )
            .await?;
        let hash_page = dht_store
            .as_read()
            .dump_source_chain_paginated(
                &agent_key,
                Some(&SourceChainCursor::ActionHash(
                    dump.records[1].action_address.clone(),
                )),
                Some(10),
            )
            .await?;
        assert_eq!(sequence_page, hash_page);
        assert_eq!(sequence_page.records, dump.records[2..]);
        assert_eq!(sequence_page.published_ops_count, 1);

        let empty_page = dht_store
            .as_read()
            .dump_source_chain_paginated(&agent_key, Some(&SourceChainCursor::Sequence(3)), Some(5))
            .await?;
        assert!(empty_page.records.is_empty());
        assert_eq!(empty_page.published_ops_count, 1);

        assert!(dht_store
            .as_read()
            .dump_source_chain_paginated(&agent_key, None, Some(0))
            .await
            .is_err());
        assert!(dht_store
            .as_read()
            .dump_source_chain_paginated(
                &agent_key,
                Some(&SourceChainCursor::ActionHash(ActionHash::from_raw_36(
                    vec![42; 36],
                ))),
                Some(1),
            )
            .await
            .is_err());

        let mut rejected_action = dump.records[3].action.clone();
        rejected_action.header.action_seq = 99;
        rejected_action.header.prev_action = Some(dump.records[3].action_address.clone());
        rejected_action.header.timestamp = Timestamp::now();
        let rejected_action_hash = ActionHash::with_data_sync(&rejected_action);
        let rejected_op =
            DhtOpHashed::from_content_sync(DhtOp::ChainOp(Box::new(ChainOp::AgentActivity(
                SignedAction::new(rejected_action, Signature::from([42; 64])),
            ))));
        dht_store
            .record_incoming_ops(vec![(rejected_op, false)])
            .await?;
        assert!(dht_store
            .as_read()
            .dump_source_chain_paginated(
                &agent_key,
                Some(&SourceChainCursor::ActionHash(rejected_action_hash)),
                Some(1),
            )
            .await
            .is_err());

        let other_agent = keystore.new_sign_keypair_random().await.unwrap();
        genesis(
            dht_store.clone(),
            keystore,
            chain.cell_id().dna_hash().clone(),
            other_agent.clone(),
            None,
        )
        .await?;
        let other_dump = dht_store.as_read().dump_source_chain(&other_agent).await?;
        assert!(dht_store
            .as_read()
            .dump_source_chain_paginated(
                &agent_key,
                Some(&SourceChainCursor::ActionHash(
                    other_dump.records[0].action_address.clone(),
                )),
                Some(1),
            )
            .await
            .is_err());

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn source_chain_buffer_dump_entries_json() -> SourceChainResult<()> {
        let TestCase {
            chain: _,
            agent_key,
            dht_store,
            ..
        } = TestCase::new().await;

        let json = dump_state(&dht_store.as_read(), agent_key.clone()).await?;
        let json = serde_json::to_string_pretty(&json)?;
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["records"][0]["action"]["data"]["type"], "Dna");
        assert_eq!(parsed["records"][0]["entry"], serde_json::Value::Null);

        assert_eq!(parsed["records"][2]["action"]["data"]["type"], "Create");
        assert_eq!(
            parsed["records"][2]["action"]["data"]["entry_type"],
            "AgentPubKey"
        );
        assert_eq!(parsed["records"][2]["entry"]["entry_type"], "Agent");
        assert_ne!(
            parsed["records"][2]["entry"]["entry"],
            serde_json::Value::Null
        );

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn source_chain_query() {
        let TestCase {
            chain,
            agent_key: alice,
            keystore,
            ..
        } = TestCase::new().await;

        let app_entry_type = EntryType::App(AppEntryDef {
            zome_index: 0.into(),
            entry_index: 0.into(),
            visibility: EntryVisibility::Public,
        });

        let chain_top = chain.chain_head_nonempty().unwrap();

        // Add an app entry to the chain
        let create_action = {
            let entry = Entry::App(fixt!(AppEntryBytes));
            let entry_hashed = EntryHashed::from_content_sync(entry);

            let action = Action {
                header: ActionHeader {
                    author: alice.clone(),
                    timestamp: Timestamp::now(),
                    action_seq: chain_top.seq + 1,
                    prev_action: Some(chain_top.action.as_hash().clone()),
                },
                data: ActionData::Create(CreateData {
                    entry_type: app_entry_type.clone(),
                    entry_hash: entry_hashed.hash.clone(),
                }),
            };
            let sig = alice.sign(&keystore, &action).await.unwrap();
            let signed_action = SignedActionHashed::with_presigned(
                HoloHashed::from_content_sync(action.clone()),
                sig,
            );

            chain
                .scratch()
                .apply(move |scratch| {
                    scratch.add_action(signed_action, ChainTopOrdering::Strict);
                    scratch.add_entry(entry_hashed, ChainTopOrdering::Strict);
                })
                .unwrap();
            chain.flush(vec![DhtArc::Empty]).await.unwrap();

            action
        };

        // Add an app entry to the scratch space
        {
            let chain_top = chain.chain_head_nonempty().unwrap();

            let entry = Entry::App(fixt!(AppEntryBytes));
            let entry_hashed = EntryHashed::from_content_sync(entry);

            let action = Action {
                header: ActionHeader {
                    author: alice.clone(),
                    timestamp: Timestamp::now(),
                    action_seq: chain_top.seq + 2,
                    prev_action: Some(create_action.to_hash()),
                },
                data: ActionData::Update(UpdateData {
                    original_action_address: create_action.to_hash(),
                    original_entry_address: create_action.entry_hash().unwrap().clone(),
                    entry_type: app_entry_type.clone(),
                    entry_hash: entry_hashed.hash.clone(),
                }),
            };
            let sig = alice.sign(&keystore, &action).await.unwrap();
            let signed_action =
                SignedActionHashed::with_presigned(HoloHashed::from_content_sync(action), sig);

            chain
                .scratch()
                .apply(move |scratch| {
                    scratch.add_action(signed_action, ChainTopOrdering::Strict);
                    scratch.add_entry(entry_hashed, ChainTopOrdering::Strict);
                })
                .unwrap();
        }

        let records = chain.query(ChainQueryFilter::default()).await.unwrap();

        // All the range queries which should return a full set of records
        let full_ranges = [
            ChainQueryFilterRange::Unbounded,
            ChainQueryFilterRange::ActionSeqRange(0, 4),
            ChainQueryFilterRange::ActionHashRange(
                records[0].action_address().clone(),
                records[4].action_address().clone(),
            ),
            ChainQueryFilterRange::ActionHashTerminated(records[4].action_address().clone(), 4),
        ];

        // A variety of combinations of query parameters
        let cases = [
            ((None, None, vec![], false), 5),
            ((None, None, vec![], true), 5),
            ((Some(vec![ActionType::Dna]), None, vec![], false), 1),
            ((None, Some(vec![EntryType::AgentPubKey]), vec![], false), 1),
            ((None, Some(vec![EntryType::AgentPubKey]), vec![], true), 1),
            ((Some(vec![ActionType::Create]), None, vec![], false), 2),
            ((Some(vec![ActionType::Create]), None, vec![], true), 2),
            (
                (
                    Some(vec![ActionType::Create]),
                    Some(vec![EntryType::AgentPubKey]),
                    vec![],
                    false,
                ),
                1,
            ),
            (
                (
                    Some(vec![ActionType::Create]),
                    Some(vec![EntryType::AgentPubKey]),
                    vec![records[2].action().entry_hash().unwrap().clone()],
                    true,
                ),
                1,
            ),
            (
                (
                    Some(vec![ActionType::Create, ActionType::Dna]),
                    None,
                    vec![],
                    true,
                ),
                3,
            ),
            (
                (
                    None,
                    Some(vec![EntryType::AgentPubKey, app_entry_type]),
                    vec![],
                    true,
                ),
                3,
            ),
        ];

        // Test all permutations of cases defined with all full range queries,
        // and both boolean values of `include_entries`.
        for ((action_type, entry_type, entry_hashes, include_entries), num_expected) in cases {
            let entry_hashes = if entry_hashes.is_empty() {
                None
            } else {
                Some(entry_hashes.into_iter().collect())
            };
            for sequence_range in full_ranges.clone() {
                let query = ChainQueryFilter {
                    sequence_range: sequence_range.clone(),
                    action_type: action_type.clone(),
                    entry_type: entry_type.clone(),
                    entry_hashes: entry_hashes.clone(),
                    include_entries,
                    order_descending: false,
                };

                let queried = chain.query(query.clone()).await.unwrap();
                let actual = queried.len();
                assert!(queried.iter().all(|e| e.action().author() == &alice));
                assert_eq!(
                    num_expected, actual,
                    "Expected {num_expected} items but got {actual} with filter {query:?}"
                );
            }
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn source_chain_query_private_entry_redacted_under_public_only() {
        let TestCase {
            mut chain,
            agent_key: alice,
            keystore,
            ..
        } = TestCase::new().await;

        let private_entry_type = EntryType::App(AppEntryDef {
            zome_index: 0.into(),
            entry_index: 0.into(),
            visibility: EntryVisibility::Private,
        });
        let public_entry_type = EntryType::App(AppEntryDef {
            zome_index: 0.into(),
            entry_index: 1.into(),
            visibility: EntryVisibility::Public,
        });

        // Commit a Create with a PRIVATE entry to the DhtStore via flush.
        let chain_top = chain.chain_head_nonempty().unwrap();
        let private_entry_hashed = EntryHashed::from_content_sync(Entry::App(fixt!(AppEntryBytes)));
        let private_create_action = Action {
            header: ActionHeader {
                author: alice.clone(),
                timestamp: Timestamp::now(),
                action_seq: chain_top.seq + 1,
                prev_action: Some(chain_top.action.as_hash().clone()),
            },
            data: ActionData::Create(CreateData {
                entry_type: private_entry_type.clone(),
                entry_hash: private_entry_hashed.hash.clone(),
            }),
        };
        let sig = alice.sign(&keystore, &private_create_action).await.unwrap();
        let private_sah = SignedActionHashed::with_presigned(
            HoloHashed::from_content_sync(private_create_action),
            sig,
        );
        let private_action_hash = private_sah.as_hash().clone();
        chain
            .scratch()
            .apply({
                let private_sah = private_sah.clone();
                move |scratch| {
                    scratch.add_action(private_sah, ChainTopOrdering::Strict);
                    scratch.add_entry(private_entry_hashed, ChainTopOrdering::Strict);
                }
            })
            .unwrap();
        chain.flush(vec![DhtArc::Empty]).await.unwrap();

        // Add an uncommitted public Create to the scratch.
        let chain_top = chain.chain_head_nonempty().unwrap();
        let public_entry_hashed = EntryHashed::from_content_sync(Entry::App(fixt!(AppEntryBytes)));
        let public_create_action = Action {
            header: ActionHeader {
                author: alice.clone(),
                timestamp: Timestamp::now(),
                action_seq: chain_top.seq + 1,
                prev_action: Some(chain_top.action.as_hash().clone()),
            },
            data: ActionData::Create(CreateData {
                entry_type: public_entry_type.clone(),
                entry_hash: public_entry_hashed.hash.clone(),
            }),
        };
        let sig = alice.sign(&keystore, &public_create_action).await.unwrap();
        let public_sah = SignedActionHashed::with_presigned(
            HoloHashed::from_content_sync(public_create_action),
            sig,
        );
        let scratch_action_hash = public_sah.as_hash().clone();
        chain
            .scratch()
            .apply({
                let public_sah = public_sah.clone();
                move |scratch| {
                    scratch.add_action(public_sah, ChainTopOrdering::Strict);
                    scratch.add_entry(public_entry_hashed, ChainTopOrdering::Strict);
                }
            })
            .unwrap();

        // With full visibility, the committed private entry is present and the
        // uncommitted scratch record is visible.
        let q = ChainQueryFilter::default().include_entries(true);
        let records = chain.query(q.clone()).await.unwrap();
        let committed_private = records
            .iter()
            .find(|r| r.action_address() == &private_action_hash)
            .expect("committed private record present");
        assert!(
            matches!(committed_private.entry(), RecordEntry::Present(_)),
            "private entry should be present without public_only"
        );
        assert!(
            records
                .iter()
                .any(|r| r.action_address() == &scratch_action_hash),
            "uncommitted scratch record should be visible"
        );

        // With public_only set, the committed private entry is redacted (the
        // action remains) but the scratch record — this agent's own data — still
        // carries its entry.
        chain.public_only();
        let records = chain.query(q).await.unwrap();
        let committed_private = records
            .iter()
            .find(|r| r.action_address() == &private_action_hash)
            .expect("committed private action still present under public_only");
        assert!(
            matches!(committed_private.entry(), RecordEntry::Hidden),
            "private entry should be redacted (Hidden) under public_only, got {:?}",
            committed_private.entry()
        );
        let scratch_record = records
            .iter()
            .find(|r| r.action_address() == &scratch_action_hash)
            .expect("scratch record still visible under public_only");
        assert!(
            matches!(scratch_record.entry(), RecordEntry::Present(_)),
            "scratch entry (own data) should remain present under public_only"
        );
    }

    /// `query` pushes the sequence range, action types and entry hashes into
    /// SQL and loads entries only for survivors; the result must equal the
    /// whole-chain-then-Rust-filter oracle for EVERY filter shape — every
    /// range variant (including hash ranges that start in the committed chain
    /// and end in the scratch, empty and inverted ranges), every per-record
    /// predicate alone and combined, both orders, with and without entries,
    /// with and without `public_only`.
    #[tokio::test(flavor = "multi_thread")]
    async fn source_chain_query_pushdown_matches_whole_chain_filter() {
        let TestCase {
            chain,
            agent_key: alice,
            dht_store,
            keystore,
        } = TestCase::new().await;
        drop(chain);

        let public_type = EntryType::App(AppEntryDef {
            zome_index: 0.into(),
            entry_index: 0.into(),
            visibility: EntryVisibility::Public,
        });
        let private_type = EntryType::App(AppEntryDef {
            zome_index: 0.into(),
            entry_index: 1.into(),
            visibility: EntryVisibility::Private,
        });
        let app_entry = |i: u32| {
            Entry::App(AppEntryBytes(SerializedBytes::from(
                holochain_serialized_bytes::UnsafeBytes::from(
                    holochain_serialized_bytes::encode(&(i, "pushdown")).unwrap(),
                ),
            )))
        };
        let create = |entry_type: EntryType, entry: &Entry| {
            ActionData::Create(CreateData {
                entry_type,
                entry_hash: EntryHash::with_data_sync(entry),
            })
        };

        // Committed: public creates, private creates, entry-less actions and
        // an update, interleaved.
        let committed = fresh_chain(&dht_store, &keystore, &alice).await.unwrap();
        let mut first_public: Option<(ActionHash, EntryHash)> = None;
        for i in 0..12u32 {
            let (data, entry) = match i % 4 {
                0 | 3 => {
                    let e = app_entry(i);
                    (create(public_type.clone(), &e), Some(e))
                }
                1 => {
                    let e = app_entry(i);
                    (create(private_type.clone(), &e), Some(e))
                }
                _ => match &first_public {
                    Some((action, entry_hash)) if i == 6 => {
                        let e = app_entry(i);
                        (
                            ActionData::Update(UpdateData {
                                original_action_address: action.clone(),
                                original_entry_address: entry_hash.clone(),
                                entry_type: public_type.clone(),
                                entry_hash: EntryHash::with_data_sync(&e),
                            }),
                            Some(e),
                        )
                    }
                    _ => (
                        ActionData::InitZomesComplete(InitZomesCompleteData {}),
                        None,
                    ),
                },
            };
            let entry_hash = data.entry_hash().cloned();
            let hash = committed
                .put(data, entry, ChainTopOrdering::default())
                .await
                .unwrap();
            if first_public.is_none() {
                first_public = entry_hash.map(|eh| (hash, eh));
            }
        }
        // A real private capability entry exercises attachment/redaction, and
        // an entry-less link makes explicit CreateLink filters non-vacuous.
        let cap_entry = Entry::CapGrant(ZomeCallCapGrant::new(
            "query-prefilter".into(),
            CapAccess::Unrestricted,
            GrantedFunctions::All,
        ));
        committed
            .put(
                create(EntryType::CapGrant, &cap_entry),
                Some(cap_entry),
                ChainTopOrdering::default(),
            )
            .await
            .unwrap();
        committed
            .put(
                ActionData::CreateLink(CreateLinkData {
                    base_address: EntryHash::from_raw_36(vec![1; 36]).into(),
                    target_address: EntryHash::from_raw_36(vec![2; 36]).into(),
                    zome_index: 0.into(),
                    link_type: 0.into(),
                    tag: LinkTag::new(vec![]),
                }),
                None,
                ChainTopOrdering::default(),
            )
            .await
            .unwrap();
        committed.flush(vec![DhtArc::Empty]).await.unwrap();

        // Scratch: two uncommitted actions on top of the committed head.
        let mut chain = fresh_chain(&dht_store, &keystore, &alice).await.unwrap();
        let scratch_entry = app_entry(100);
        chain
            .put(
                create(public_type.clone(), &scratch_entry),
                Some(scratch_entry.clone()),
                ChainTopOrdering::default(),
            )
            .await
            .unwrap();
        chain
            .put(
                ActionData::InitZomesComplete(InitZomesCompleteData {}),
                None,
                ChainTopOrdering::default(),
            )
            .await
            .unwrap();

        let all = chain
            .query_reference(ChainQueryFilter::default())
            .await
            .unwrap();
        // 3 genesis + 14 committed + 2 scratch.
        assert_eq!(all.len(), 19);
        let hash_at = |seq: usize| all[seq].action_address().clone();
        let head = all.len() as u32 - 1;
        let committed_entry_hash = all[4].action().entry_hash().unwrap().clone();
        let scratch_entry_hash = EntryHash::with_data_sync(&scratch_entry);

        let ranges = [
            ChainQueryFilterRange::Unbounded,
            ChainQueryFilterRange::ActionSeqRange(0, u32::MAX),
            ChainQueryFilterRange::ActionSeqRange(4, 9),
            ChainQueryFilterRange::ActionSeqRange(7, 7),
            ChainQueryFilterRange::ActionSeqRange(9, 4),
            ChainQueryFilterRange::ActionSeqRange(head - 3, head + 5),
            ChainQueryFilterRange::ActionHashRange(hash_at(2), hash_at(9)),
            ChainQueryFilterRange::ActionHashRange(hash_at(10), hash_at(head as usize)),
            // `start` after `end`: the walk never meets it and runs to genesis.
            ChainQueryFilterRange::ActionHashRange(hash_at(12), hash_at(5)),
            ChainQueryFilterRange::ActionHashTerminated(hash_at(8), 3),
            ChainQueryFilterRange::ActionHashTerminated(hash_at(head as usize), 4),
            ChainQueryFilterRange::ActionHashTerminated(ActionHash::from_raw_36(vec![7; 36]), 2),
        ];
        let action_types = [
            None,
            Some(vec![ActionType::Create]),
            Some(vec![ActionType::Create, ActionType::Update]),
            Some(vec![ActionType::CreateLink]),
            Some(vec![ActionType::InitZomesComplete, ActionType::Dna]),
            Some(vec![]),
        ];
        let entry_types = [
            None,
            Some(vec![EntryType::AgentPubKey]),
            Some(vec![EntryType::CapGrant]),
            Some(vec![]),
            Some(vec![public_type.clone(), private_type.clone()]),
        ];
        let entry_hash_sets = [
            None,
            Some(
                [committed_entry_hash, scratch_entry_hash]
                    .into_iter()
                    .collect::<HashSet<_>>(),
            ),
        ];

        let mut compared = 0usize;
        let mut nonempty = 0usize;
        for public_only in [false, true] {
            if public_only {
                chain.public_only();
            }
            for sequence_range in &ranges {
                for action_type in &action_types {
                    for entry_type in &entry_types {
                        for entry_hashes in &entry_hash_sets {
                            for include_entries in [false, true] {
                                for order_descending in [false, true] {
                                    let query = ChainQueryFilter {
                                        sequence_range: sequence_range.clone(),
                                        entry_type: entry_type.clone(),
                                        entry_hashes: entry_hashes.clone(),
                                        action_type: action_type.clone(),
                                        include_entries,
                                        order_descending,
                                    };
                                    let got = chain.query(query.clone()).await.unwrap();
                                    let expected =
                                        chain.query_reference(query.clone()).await.unwrap();
                                    assert_eq!(
                                        got, expected,
                                        "public_only={public_only} {query:?}"
                                    );
                                    compared += 1;
                                    nonempty += usize::from(!got.is_empty());
                                }
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(compared, 2 * 12 * 6 * 5 * 2 * 2 * 2);
        // Guard against a vacuous pass where every shape returned nothing.
        assert!(
            nonempty > compared / 10,
            "{nonempty} of {compared} non-empty"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn source_chain_query_ordering() {
        let TestCase { chain, .. } = TestCase::new().await;

        let asc = chain.query(ChainQueryFilter::default()).await.unwrap();
        let desc = chain
            .query(ChainQueryFilter::default().descending())
            .await
            .unwrap();

        assert_eq!(asc.len(), 3);
        assert_ne!(asc, desc);

        let mut desc_sorted = desc;
        desc_sorted.sort_by_key(|r| r.action().action_seq());
        assert_eq!(asc, desc_sorted);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn init_zomes_complete() {
        let TestCase { chain, .. } = TestCase::new().await;

        // zomes initialized should be false after genesis
        let zomes_initialized = chain.zomes_initialized().await.unwrap();
        assert!(!zomes_initialized);

        // insert init marker into source chain
        let result = chain
            .put(
                ActionData::InitZomesComplete(InitZomesCompleteData {}),
                None,
                ChainTopOrdering::Strict,
            )
            .await;
        assert!(result.is_ok());

        chain.flush(vec![DhtArc::Empty]).await.unwrap();

        // zomes initialized should be true after init zomes has run
        let zomes_initialized = chain.zomes_initialized().await.unwrap();
        assert!(zomes_initialized);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn flush_writes_warrants_to_dht_store() {
        let TestCase {
            chain,
            agent_key,
            dht_store,
            keystore,
            ..
        } = TestCase::new().await;
        let warrantee = fixt!(AgentPubKey);

        // The warrant is authored by `agent_key` (the warrant issuer). Read it
        // back via the DhtStore (limbo + integrated).
        let actual_warrants = dht_store
            .as_read()
            .warrants_by_author(agent_key.clone())
            .await
            .unwrap();
        assert_eq!(actual_warrants.len(), 0);

        // Create a warrant
        let signed_warrant = create_signed_warrant(&agent_key, &warrantee, &keystore).await;
        // Add warrant to scratch
        chain
            .scratch
            .apply(|scratch| {
                scratch.add_warrant(signed_warrant.clone());
            })
            .unwrap();

        // Flush should write warrants to the DHT store
        let (actions, warrant_count) = chain.flush(vec![]).await.unwrap();
        assert!(actions.is_empty());
        assert_eq!(warrant_count, 1);

        // Check the DHT store
        let actual_warrants = dht_store
            .as_read()
            .warrants_by_author(agent_key.clone())
            .await
            .unwrap();
        assert_eq!(actual_warrants, vec![WarrantOp::from(signed_warrant)]);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn duplicate_warrants_are_not_inserted_during_flush() {
        holochain_trace::test_run();
        let TestCase {
            chain,
            agent_key,
            dht_store,
            keystore,
            ..
        } = TestCase::new().await;
        let warrantee = fixt!(AgentPubKey);

        // Create a warrant
        let signed_warrant = create_signed_warrant(&agent_key, &warrantee, &keystore).await;
        // Add warrant to scratch
        chain
            .scratch
            .apply(|scratch| {
                scratch.add_warrant(signed_warrant.clone());
            })
            .unwrap();

        // Flush should write warrant to the DHT store
        let (actions, warrant_count) = chain.flush(vec![]).await.unwrap();
        assert!(actions.is_empty());
        assert_eq!(warrant_count, 1);

        // Check the DHT store
        let actual_warrants = dht_store
            .as_read()
            .warrants_by_author(agent_key.clone())
            .await
            .unwrap();
        assert_eq!(
            actual_warrants,
            vec![WarrantOp::from(signed_warrant.clone())]
        );

        // Add same warrant to scratch again
        chain
            .scratch
            .apply(|scratch| {
                scratch.add_warrant(signed_warrant.clone());
            })
            .unwrap();

        // Flush should not write duplicate warrant to the DHT store
        let (actions, warrant_count) = chain.flush(vec![]).await.unwrap();
        assert!(actions.is_empty());
        assert_eq!(warrant_count, 1); // rejected inserts are not reported by the insertion method, so this will indicate 1

        // Check the DHT store again
        let actual_warrants = dht_store
            .as_read()
            .warrants_by_author(agent_key.clone())
            .await
            .unwrap();
        assert_eq!(actual_warrants, vec![WarrantOp::from(signed_warrant)]);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn counterfeit_warrants_are_not_inserted_during_flush() {
        let TestCase {
            chain,
            agent_key,
            dht_store,
            ..
        } = TestCase::new().await;
        let warrantee = fixt!(AgentPubKey);

        // Create a counterfeit warrant
        let warrant = Warrant::new(
            WarrantProof::ChainIntegrity(ChainIntegrityWarrant::InvalidChainOp {
                action_author: warrantee.clone(),
                action: (fixt!(ActionHash), fixt!(Signature)),
                chain_op_type: ChainOpType::AgentActivity,
                reason: "invalid chain op".into(),
            }),
            agent_key.clone(),
            Timestamp::now(),
            warrantee.clone(),
        );
        let signed_warrant = SignedWarrant::new(warrant, fixt!(Signature));
        // Add warrant to scratch
        chain
            .scratch
            .apply(|scratch| {
                scratch.add_warrant(signed_warrant.clone());
            })
            .unwrap();

        // Flush should not write warrant to DHT database
        let (actions, warrant_count) = chain.flush(vec![]).await.unwrap();
        assert!(actions.is_empty());
        assert_eq!(warrant_count, 0);

        // Check the DHT store — the counterfeit warrant must not be present.
        let actual_warrants = dht_store
            .as_read()
            .warrants_by_author(agent_key.clone())
            .await
            .unwrap();
        assert!(actual_warrants.is_empty());
    }

    /// Flush of a countersigning op writes `withhold_publish = 1` to `ChainOpPublish`
    /// in the new DHT schema.
    #[tokio::test(flavor = "multi_thread")]
    async fn flush_countersigning_op_sets_withhold_publish() {
        use holochain_zome_types::prelude::{
            CounterSigningAgentState, CounterSigningSessionData, CounterSigningSessionTimes,
            PreflightRequest,
        };
        use std::time::Duration;

        let TestCase {
            chain,
            agent_key: alice,
            dht_store,
            keystore,
            ..
        } = TestCase::new().await;

        // Second signing agent — exists only as a key; no local chain needed.
        let bob = keystore.new_sign_keypair_random().await.unwrap();

        // Build a preflight request for alice (index 0) and bob (index 1).
        let app_entry_hash = fixt!(EntryHash);
        let app_entry_type = EntryType::App(AppEntryDef::new(
            EntryDefIndex(0),
            0.into(),
            EntryVisibility::Public,
        ));
        let start = Timestamp::now();
        let end = (start + Duration::from_secs(60)).unwrap();
        let session_times = CounterSigningSessionTimes::try_new(start, end).unwrap();
        let preflight_request = PreflightRequest::try_new(
            app_entry_hash,
            vec![(alice.clone(), vec![]), (bob.clone(), vec![])],
            vec![],
            0,
            false,
            session_times,
            ActionBase::Create(CreateBase::new(app_entry_type.clone())),
            PreflightBytes(vec![]),
        )
        .unwrap();

        // Alice accepts — this locks her chain and returns her agent state.
        let alice_agent_state = chain
            .accept_countersigning_preflight_request(preflight_request.clone(), 0)
            .await
            .unwrap();

        // Build a fake Bob agent state (index 1). The test only cares that
        // the flush path sets `withhold_publish`; full signature verification
        // is not exercised here.
        let bob_agent_state = CounterSigningAgentState::new(1, fixt!(ActionHash), 2);

        let session_data = CounterSigningSessionData::try_new(
            preflight_request,
            vec![
                (alice_agent_state, fixt!(Signature)),
                (bob_agent_state, fixt!(Signature)),
            ],
            vec![],
        )
        .unwrap();

        let entry = Entry::CounterSign(Box::new(session_data), fixt!(AppEntryBytes));
        chain
            .put_countersigned(entry, ChainTopOrdering::Strict)
            .await
            .unwrap();

        chain.flush(vec![DhtArc::Empty]).await.unwrap();

        // Assert that at least one ChainOpPublish row carries withhold_publish = 1.
        let withheld_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM ChainOpPublish WHERE withhold_publish = 1")
                .fetch_one(dht_store.db().pool())
                .await
                .unwrap();
        assert!(
            withheld_count > 0,
            "expected at least one ChainOpPublish row with withhold_publish=1 \
             after countersigning flush, got 0"
        );
    }

    /// `SourceChain::new` reads the chain head from the DHT store. After genesis
    /// plus one flush, a second `SourceChain::new` for the same author observes
    /// the flushed head as its persisted head.
    #[tokio::test(flavor = "multi_thread")]
    async fn chain_head_read_from_store() -> SourceChainResult<()> {
        let TestCase {
            chain,
            agent_key: alice,
            dht_store,
            keystore,
            ..
        } = TestCase::new().await;

        // Author one action and flush it so the DHT store has a head beyond genesis.
        let storage_arcs = vec![DhtArc::Empty];
        chain
            .put(
                ActionData::CloseChain(CloseChainData { new_target: None }),
                None,
                ChainTopOrdering::Strict,
            )
            .await?;
        let (flushed_actions, _) = chain.flush(storage_arcs).await?;
        let expected_head = flushed_actions
            .last()
            .expect("flush must return at least one action")
            .as_hash()
            .clone();

        let chain2 = SourceChain::new(dht_store.clone(), keystore, alice).await?;

        assert_eq!(
            chain2.persisted_head_info().map(|h| h.action),
            Some(expected_head),
        );

        Ok(())
    }

    /// The flush as-at check reads the store head. Two source chains for the
    /// same author share the store; once one flushes, the other's stale
    /// `persisted_head` must be detected as `HeadMoved`, and a normal flush's
    /// action must be visible via the store.
    #[tokio::test(flavor = "multi_thread")]
    async fn flush_as_at_detects_head_moved_against_store() -> SourceChainResult<()> {
        let TestCase {
            chain: chain_1,
            agent_key: alice,
            dht_store,
            keystore,
            ..
        } = TestCase::new().await;

        // A second chain reading the same store head; it goes stale once
        // chain_1 flushes.
        let chain_2 = SourceChain::new(dht_store.clone(), keystore.clone(), alice.clone()).await?;

        let close_chain = ActionData::CloseChain(CloseChainData { new_target: None });
        chain_1
            .put(close_chain.clone(), None, ChainTopOrdering::Strict)
            .await?;
        chain_2
            .put(close_chain, None, ChainTopOrdering::Strict)
            .await?;

        // chain_1 flushes: its action becomes the store head and is visible via
        // the store.
        let (flushed, _) = chain_1.flush(vec![DhtArc::Empty]).await?;
        let flushed_head = flushed
            .last()
            .expect("flush returns at least one action")
            .as_hash()
            .clone();
        let store_head = dht_store
            .as_read()
            .chain_head_for_author(&alice)
            .await?
            .expect("store head present after flush");
        assert_eq!(store_head.action, flushed_head);

        // chain_2's persisted_head is stale; a strict flush must detect the
        // moved store head and fail with HeadMoved.
        assert_matches!(
            chain_2.flush(vec![DhtArc::Empty]).await,
            Err(SourceChainError::HeadMoved(_, _, _, _))
        );

        Ok(())
    }

    /// Concurrent strict flushes from the same chain head must not fork the
    /// chain. Two `SourceChain` handles for the same `(DNA, author)` observe the
    /// same store head, each stage one strict action, then flush in true
    /// parallel. The per-`(DNA, author)` chain write permit acquired in `flush`,
    /// combined with the as-at check against the store head, serializes the two
    /// flushes: exactly one commits and the other gets `HeadMoved`. The store
    /// head must advance by exactly one — never forking into two actions at the
    /// same sequence. Both flushing both successfully would be the fork bug the
    /// permit prevents, in which case this test fails.
    #[tokio::test(flavor = "multi_thread")]
    async fn concurrent_strict_flushes_do_not_fork_chain() -> SourceChainResult<()> {
        let TestCase {
            chain: _chain,
            agent_key: alice,
            dht_store,
            keystore,
            ..
        } = TestCase::new().await;

        // The head sequence both chains start contending from (the genesis head).
        let pre_seq = dht_store
            .as_read()
            .chain_head_for_author(&alice)
            .await?
            .expect("genesis chain head present")
            .seq;

        // Two fresh chains for the same author, both observing the same head.
        let chain_a = SourceChain::new(dht_store.clone(), keystore.clone(), alice.clone()).await?;
        let chain_b = SourceChain::new(dht_store.clone(), keystore.clone(), alice.clone()).await?;

        // Each stages one strict action from the same head; the flush loser gets
        // a clean `HeadMoved` (strict ordering means no relaxed rebase/retry).
        let close_chain = ActionData::CloseChain(CloseChainData { new_target: None });
        chain_a
            .put(close_chain.clone(), None, ChainTopOrdering::Strict)
            .await?;
        chain_b
            .put(close_chain, None, ChainTopOrdering::Strict)
            .await?;

        // Flush both in true parallel on the multi-threaded runtime via spawned
        // tasks. `SourceChain` is `Clone` + `Send` + `'static`, so each owned
        // handle moves into its own task.
        let arcs_a = vec![DhtArc::Empty];
        let arcs_b = arcs_a.clone();
        let task_a = tokio::spawn(async move { chain_a.flush(arcs_a).await });
        let task_b = tokio::spawn(async move { chain_b.flush(arcs_b).await });
        let (res_a, res_b) = tokio::join!(task_a, task_b);
        let res_a = res_a.expect("flush task a did not panic");
        let res_b = res_b.expect("flush task b did not panic");

        // Exactly one flush committed (`Ok`) and exactly one was rejected with
        // `HeadMoved`. Don't assume which won the race.
        let oks = [&res_a, &res_b].iter().filter(|r| r.is_ok()).count();
        assert_eq!(
            oks, 1,
            "exactly one flush must commit; a={res_a:?}, b={res_b:?}"
        );
        let loser = if res_a.is_err() { &res_a } else { &res_b };
        assert_matches!(loser, Err(SourceChainError::HeadMoved(_, _, _, _)));

        // No fork: the store head advanced by exactly one.
        let new_seq = dht_store
            .as_read()
            .chain_head_for_author(&alice)
            .await?
            .expect("chain head present after flush")
            .seq;
        assert_eq!(
            new_seq,
            pre_seq + 1,
            "store head must advance by exactly one, not fork"
        );

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Capability-grant lookup at scale.
    //
    // `DhtStoreRead::valid_cap_grants` was rewritten from a load-every-grant
    // scan (three queries per grant plus a chunked batch read) into one query
    // per access class. These tests pin that the rewrite is decision-preserving:
    // the differential tests compare it against `valid_cap_grants_reference`
    // — the verbatim old implementation, kept under `cfg(test)` as an oracle —
    // over a randomised population, and the targeted tests pin each individual
    // rule (secret, delete, update, assignee, unrestricted, function scope,
    // author isolation, first-match order) with hundreds of decoy grants
    // present so a regression that reintroduces "return the first grant found"
    // cannot pass.
    // -----------------------------------------------------------------------

    /// Deterministic, dependency-free PRNG. A differential failure must be
    /// reproducible from the seed printed in the assertion message.
    struct Lcg(u64);

    impl Lcg {
        fn new(seed: u64) -> Self {
            Self(seed)
        }

        fn next_u64(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            self.0 >> 11
        }

        fn below(&mut self, n: u64) -> u64 {
            self.next_u64() % n
        }
    }

    /// A distinct `CapSecret` per seed — injective, because the seed's own
    /// bytes lead the secret.
    fn secret_from(seed: u64) -> CapSecret {
        use holochain_zome_types::prelude::CAP_SECRET_BYTES;
        let mut bytes = [0u8; CAP_SECRET_BYTES];
        bytes[..8].copy_from_slice(&seed.to_le_bytes());
        for (i, b) in bytes.iter_mut().enumerate().skip(8) {
            *b = (i as u8).wrapping_mul(31).wrapping_add(seed as u8);
        }
        CapSecret::try_from(bytes.as_slice()).unwrap()
    }

    fn listed(fns: &[(&str, &str)]) -> GrantedFunctions {
        GrantedFunctions::Listed(
            fns.iter()
                .map(|(z, f)| ((*z).into(), (*f).into()))
                .collect::<HashSet<GrantedFunction>>(),
        )
    }

    /// A `SourceChain` reflecting the CURRENT persisted head.
    ///
    /// `SourceChain` snapshots the chain head when it is constructed, so a
    /// handle that has already been flushed cannot author again — the next
    /// flush fails with `HeadMoved`. Every batch that follows a flush therefore
    /// needs a fresh handle (the pre-existing `test_get_cap_grant` does the
    /// same thing inline).
    async fn fresh_chain(
        dht_store: &DhtStore,
        keystore: &MetaLairClient,
        author: &AgentPubKey,
    ) -> SourceChainResult<SourceChain> {
        SourceChain::new(dht_store.clone(), keystore.clone(), author.clone()).await
    }

    /// Commit a `Create` of a cap grant to `chain`'s scratch (no flush).
    async fn put_cap_grant(
        chain: &SourceChain,
        grant: &ZomeCallCapGrant,
    ) -> SourceChainResult<(ActionHash, EntryHash)> {
        let (entry, entry_hash) =
            EntryHashed::from_content_sync(Entry::CapGrant(grant.clone())).into_inner();
        let action = chain
            .put(
                ActionData::Create(CreateData {
                    entry_type: EntryType::CapGrant,
                    entry_hash: entry_hash.clone(),
                }),
                Some(entry),
                ChainTopOrdering::default(),
            )
            .await?;
        Ok((action, entry_hash))
    }

    /// Commit an `Update` replacing `(original_action, original_entry)` with
    /// `grant`.
    async fn update_cap_grant(
        chain: &SourceChain,
        original_action: ActionHash,
        original_entry: EntryHash,
        grant: &ZomeCallCapGrant,
    ) -> SourceChainResult<(ActionHash, EntryHash)> {
        let (entry, entry_hash) =
            EntryHashed::from_content_sync(Entry::CapGrant(grant.clone())).into_inner();
        let action = chain
            .put(
                ActionData::Update(UpdateData {
                    entry_type: EntryType::CapGrant,
                    entry_hash: entry_hash.clone(),
                    original_action_address: original_action,
                    original_entry_address: original_entry,
                }),
                Some(entry),
                ChainTopOrdering::default(),
            )
            .await?;
        Ok((action, entry_hash))
    }

    /// Commit a `Delete` of `(action, entry)`.
    async fn delete_cap_grant(
        chain: &SourceChain,
        action: ActionHash,
        entry: EntryHash,
    ) -> SourceChainResult<()> {
        chain
            .put(
                ActionData::Delete(DeleteData {
                    deletes_address: action,
                    deletes_entry_address: entry,
                }),
                None,
                ChainTopOrdering::default(),
            )
            .await?;
        Ok(())
    }

    /// The decision `SourceChain::valid_cap_grant` would reach if it were still
    /// driven by the pre-optimisation store read. Mirrors
    /// `SourceChain::valid_cap_grant` exactly — author fast path, then
    /// first-match over the candidate vector — but sources its candidates from
    /// `valid_cap_grants_reference`.
    async fn oracle_decision(
        dht_store: &DhtStore,
        author: &AgentPubKey,
        function: &GrantedFunction,
        agent: &AgentPubKey,
        secret: Option<CapSecret>,
    ) -> SourceChainResult<Option<CapGrant>> {
        let author_grant = CapGrant::from(author.clone());
        if author_grant.is_valid(function, agent, secret.as_ref()) {
            return Ok(Some(author_grant));
        }
        Ok(dht_store
            .as_read()
            .valid_cap_grants_reference(author, secret.as_ref())
            .await?
            .into_iter()
            .find(|g| g.is_valid(function, agent, secret.as_ref())))
    }

    /// What a seeded population looks like to the probes.
    struct Population {
        /// `(secret, function, one assignee that should work)` for grants that
        /// must still authorise after all updates/deletes are applied.
        live_transferable: Vec<(CapSecret, GrantedFunction)>,
        live_assigned: Vec<(CapSecret, GrantedFunction, AgentPubKey)>,
        /// Secrets that must NOT authorise: deleted, or superseded by an update.
        dead_secrets: Vec<(CapSecret, GrantedFunction)>,
        /// Secrets introduced by updates, which must authorise.
        updated_secrets: Vec<(CapSecret, GrantedFunction)>,
        /// Functions of `Unrestricted` grants that must authorise ANY agent
        /// with NO secret. This is the highest-blast-radius class, so the
        /// population deliberately updates and deletes some of them: those are
        /// the only inputs that exercise the two `NOT IN` anti-joins on the
        /// `check_secret == None` path.
        live_unrestricted: Vec<GrantedFunction>,
        /// Functions of `Unrestricted` grants that were deleted or superseded
        /// and must NOT authorise.
        dead_unrestricted: Vec<GrantedFunction>,
    }

    /// Seed `count` grants across all three access classes, then update a
    /// slice of them and delete another slice. Flushes twice: once for the
    /// creates (so updates/deletes can reference committed actions) and once
    /// for the modifications.
    async fn seed_population(
        dht_store: &DhtStore,
        keystore: &MetaLairClient,
        author: &AgentPubKey,
        seed: u64,
        count: u64,
    ) -> SourceChainResult<Population> {
        let mut rng = Lcg::new(seed);
        let storage_arcs = vec![DhtArc::Empty];
        let chain = &fresh_chain(dht_store, keystore, author).await?;

        // A small pool of third-party agents to draw assignees from.
        let mut agents = Vec::new();
        for _ in 0..4 {
            agents.push(keystore.new_sign_keypair_random().await.unwrap());
        }

        let functions = [
            ("zome_a", "fn_one"),
            ("zome_a", "fn_two"),
            ("zome_b", "fn_one"),
            ("zome_c", "fn_three"),
        ];

        #[allow(clippy::type_complexity)]
        let mut created: Vec<(
            ActionHash,
            EntryHash,
            CapSecret,
            GrantedFunction,
            (String, String),
            u64,
        )> = Vec::new();
        let mut pop = Population {
            live_transferable: Vec::new(),
            live_assigned: Vec::new(),
            dead_secrets: Vec::new(),
            updated_secrets: Vec::new(),
            live_unrestricted: Vec::new(),
            dead_unrestricted: Vec::new(),
        };

        for i in 0..count {
            let secret = secret_from(seed.wrapping_mul(1_000_003).wrapping_add(i));
            let class = rng.below(3);
            // Unrestricted grants are parked on a zome the secret-bearing
            // probes never name, and each gets its OWN function name, so an
            // absolute "must be denied" assertion can never be satisfied by a
            // different decoy, and each unrestricted grant can be probed
            // individually through the no-secret path.
            let (zome, func) = if class == 0 {
                ("zome_unrestricted".to_string(), format!("u_{i}"))
            } else {
                let (z, f) = functions[rng.below(functions.len() as u64) as usize];
                (z.to_string(), f.to_string())
            };
            let function: GrantedFunction = (zome.as_str().into(), func.as_str().into());
            let access = match class {
                0 => CapAccess::Unrestricted,
                1 => CapAccess::Transferable { secret },
                _ => {
                    let mut assignees = BTreeSet::new();
                    assignees.insert(agents[rng.below(agents.len() as u64) as usize].clone());
                    CapAccess::Assigned { secret, assignees }
                }
            };
            let grant = ZomeCallCapGrant::new(
                format!("tag-{i}"),
                access.clone(),
                listed(&[(zome.as_str(), func.as_str())]),
            );
            let (action, entry) = put_cap_grant(chain, &grant).await?;
            created.push((action, entry, secret, function.clone(), (zome, func), class));

            match &access {
                CapAccess::Transferable { .. } => {
                    pop.live_transferable.push((secret, function));
                }
                CapAccess::Assigned { assignees, .. } => {
                    pop.live_assigned.push((
                        secret,
                        function,
                        assignees.iter().next().unwrap().clone(),
                    ));
                }
                CapAccess::Unrestricted => {
                    pop.live_unrestricted.push(function);
                }
            }
        }
        chain.flush(storage_arcs.clone()).await.unwrap();

        // A flushed `SourceChain` cannot author again — take a fresh handle for
        // the modification pass.
        let chain = &fresh_chain(dht_store, keystore, author).await?;

        // Update every 7th grant; delete every 11th. Unrestricted grants are
        // INCLUDED: they are the only inputs that drive the two `NOT IN`
        // anti-joins on the `check_secret == None` path, which is the path that
        // authorises any agent with no secret at all. An unrestricted grant is
        // updated to another unrestricted grant (on a fresh function name) so
        // the access class — and therefore the code path — is preserved.
        for (idx, (action, entry, secret, function, (zome, func), class)) in
            created.iter().enumerate()
        {
            if idx % 7 == 0 {
                if *class == 0 {
                    let new_func = format!("{func}_updated");
                    let updated = ZomeCallCapGrant::new(
                        format!("tag-updated-{idx}"),
                        CapAccess::Unrestricted,
                        listed(&[(zome.as_str(), new_func.as_str())]),
                    );
                    update_cap_grant(chain, action.clone(), entry.clone(), &updated).await?;
                    pop.dead_unrestricted.push(function.clone());
                    pop.live_unrestricted
                        .push((zome.as_str().into(), new_func.as_str().into()));
                    pop.live_unrestricted.retain(|f| f != function);
                } else {
                    let new_secret =
                        secret_from(seed.wrapping_mul(7_700_007).wrapping_add(idx as u64));
                    let updated = ZomeCallCapGrant::new(
                        format!("tag-updated-{idx}"),
                        CapAccess::Transferable { secret: new_secret },
                        listed(&[(zome.as_str(), func.as_str())]),
                    );
                    update_cap_grant(chain, action.clone(), entry.clone(), &updated).await?;
                    pop.dead_secrets.push((*secret, function.clone()));
                    pop.updated_secrets.push((new_secret, function.clone()));
                    pop.live_transferable.retain(|(s, _)| s != secret);
                    pop.live_assigned.retain(|(s, _, _)| s != secret);
                }
            } else if idx % 11 == 0 {
                delete_cap_grant(chain, action.clone(), entry.clone()).await?;
                if *class == 0 {
                    pop.dead_unrestricted.push(function.clone());
                    pop.live_unrestricted.retain(|f| f != function);
                } else {
                    pop.dead_secrets.push((*secret, function.clone()));
                    pop.live_transferable.retain(|(s, _)| s != secret);
                    pop.live_assigned.retain(|(s, _, _)| s != secret);
                }
            }
        }
        chain.flush(storage_arcs).await.unwrap();

        Ok(pop)
    }

    /// The core equivalence test: over a randomised population of 240 grants
    /// with updates and deletes applied, the rewritten lookup and the old
    /// implementation must return the *same candidate vector in the same
    /// order*, and `SourceChain::valid_cap_grant` must return the *same grant*
    /// (not merely the same allow/deny) for every probe.
    #[tokio::test(flavor = "multi_thread")]
    async fn cap_grant_lookup_matches_reference_over_random_population() -> SourceChainResult<()> {
        const SEED: u64 = 0xE101_0001;
        let TestCase {
            chain,
            agent_key: alice,
            dht_store,
            keystore,
            ..
        } = TestCase::new().await;

        drop(chain);
        let pop = seed_population(&dht_store, &keystore, &alice, SEED, 240).await?;
        let chain = fresh_chain(&dht_store, &keystore, &alice).await?;
        assert!(
            pop.live_transferable.len() > 20 && pop.live_assigned.len() > 20,
            "seed {SEED} did not produce a useful population"
        );
        assert!(
            pop.live_unrestricted.len() > 20 && pop.dead_unrestricted.len() > 5,
            "seed {SEED} produced no revoked unrestricted grants, so the anti-joins \
             are untested on the no-secret path ({} live / {} dead)",
            pop.live_unrestricted.len(),
            pop.dead_unrestricted.len()
        );

        let bob = keystore.new_sign_keypair_random().await.unwrap();

        // 1. Candidate-vector equivalence, including order and duplicates.
        //    The candidate set depends only on whether a secret was supplied,
        //    so both shapes are covered here.
        for probe_secret in [None, Some(pop.live_transferable[0].0)] {
            let new = dht_store
                .as_read()
                .valid_cap_grants(&alice, probe_secret.as_ref())
                .await?;
            let old = dht_store
                .as_read()
                .valid_cap_grants_reference(&alice, probe_secret.as_ref())
                .await?;
            assert_eq!(
                new,
                old,
                "candidate vectors diverged (seed {SEED}, secret supplied: {})",
                probe_secret.is_some()
            );
            assert!(!new.is_empty(), "population produced no candidates");
        }

        // 2. Decision equivalence — the exact grant returned, for every probe
        //    class: live secrets, dead secrets, updated secrets, wrong agent,
        //    wrong function, no secret.
        let mut probes: Vec<(GrantedFunction, AgentPubKey, Option<CapSecret>)> = Vec::new();
        for (secret, function) in pop.live_transferable.iter().take(15) {
            probes.push((function.clone(), bob.clone(), Some(*secret)));
            // Right secret, wrong function.
            probes.push((("zome_z".into(), "nope".into()), bob.clone(), Some(*secret)));
        }
        for (secret, function, assignee) in pop.live_assigned.iter().take(15) {
            probes.push((function.clone(), assignee.clone(), Some(*secret)));
            // Right secret, non-assignee caller.
            probes.push((function.clone(), bob.clone(), Some(*secret)));
        }
        for (secret, function) in pop.dead_secrets.iter().take(15) {
            probes.push((function.clone(), bob.clone(), Some(*secret)));
        }
        for (secret, function) in pop.updated_secrets.iter().take(15) {
            probes.push((function.clone(), bob.clone(), Some(*secret)));
        }
        // No secret at all — the unrestricted path. These are the probes that
        // drive the anti-joins with `check_secret == None`.
        for function in pop.live_unrestricted.iter().take(15) {
            probes.push((function.clone(), bob.clone(), None));
        }
        for function in pop.dead_unrestricted.iter().take(15) {
            probes.push((function.clone(), bob.clone(), None));
        }
        // A revoked unrestricted grant must also stay revoked when a secret is
        // offered (it is not even a candidate then).
        for function in pop.dead_unrestricted.iter().take(5) {
            probes.push((function.clone(), bob.clone(), Some(secret_from(u64::MAX))));
        }
        probes.push((("zome_a".into(), "fn_one".into()), bob.clone(), None));
        probes.push((("zome_a".into(), "fn_two".into()), bob.clone(), None));
        probes.push((("zome_z".into(), "nope".into()), bob.clone(), None));
        // A secret that was never granted.
        probes.push((
            ("zome_a".into(), "fn_one".into()),
            bob.clone(),
            Some(secret_from(u64::MAX)),
        ));
        // The author's own fast path.
        probes.push((("zome_a".into(), "fn_one".into()), alice.clone(), None));

        for (function, agent, secret) in probes {
            let new = chain
                .valid_cap_grant(function.clone(), agent.clone(), secret)
                .await?;
            let old = oracle_decision(&dht_store, &alice, &function, &agent, secret).await?;
            assert_eq!(
                new,
                old,
                "decision diverged (seed {SEED}, fn {function:?}, agent {agent:?}, \
                 secret supplied: {})",
                secret.is_some()
            );
        }

        Ok(())
    }

    /// Order is observable: `call_info` hands the *returned* grant to wasm, so
    /// first-match must be preserved exactly. The old implementation scanned
    /// `Transferable` grants (access class 1) before `Assigned` grants (class
    /// 2), irrespective of chain order — so an `Assigned` grant committed
    /// *earlier* loses to a `Transferable` grant committed later when both are
    /// valid for the same (function, agent, secret). A rewrite that collapsed
    /// both classes into one `ORDER BY seq` query would silently flip this.
    #[tokio::test(flavor = "multi_thread")]
    async fn cap_grant_first_match_prefers_transferable_over_earlier_assigned(
    ) -> SourceChainResult<()> {
        let TestCase {
            chain,
            agent_key: alice,
            dht_store,
            keystore,
            ..
        } = TestCase::new().await;

        let bob = keystore.new_sign_keypair_random().await.unwrap();
        let secret = secret_from(41);
        let function: GrantedFunction = ("zome_a".into(), "fn_one".into());

        // Assigned FIRST (lower Action.seq) …
        let mut assignees = BTreeSet::new();
        assignees.insert(bob.clone());
        let assigned = ZomeCallCapGrant::new(
            "assigned".into(),
            CapAccess::Assigned { secret, assignees },
            listed(&[("zome_a", "fn_one")]),
        );
        put_cap_grant(&chain, &assigned).await?;

        // … Transferable SECOND (higher Action.seq), same secret and function.
        let transferable = ZomeCallCapGrant::new(
            "transferable".into(),
            CapAccess::Transferable { secret },
            listed(&[("zome_a", "fn_one")]),
        );
        put_cap_grant(&chain, &transferable).await?;
        chain.flush(vec![DhtArc::Empty]).await.unwrap();

        let got = chain
            .valid_cap_grant(function.clone(), bob.clone(), Some(secret))
            .await?;
        assert_eq!(
            got,
            Some(transferable.clone().into()),
            "class order (Transferable before Assigned) was not preserved"
        );
        assert_eq!(
            got,
            oracle_decision(&dht_store, &alice, &function, &bob, Some(secret)).await?
        );

        // And the candidate vector itself is the Transferable block followed by
        // the Assigned block, not chain order.
        let candidates = dht_store
            .as_read()
            .valid_cap_grants(&alice, Some(&secret))
            .await?;
        assert_eq!(
            candidates,
            vec![
                CapGrant::from(transferable.clone()),
                CapGrant::from(assigned.clone())
            ]
        );
        Ok(())
    }

    /// The whole point of the change: the matching grant is found among
    /// hundreds of decoys, and a secret that was never granted is refused.
    #[tokio::test(flavor = "multi_thread")]
    async fn cap_grant_secret_match_among_many_grants() -> SourceChainResult<()> {
        const SEED: u64 = 0x00BE_EF01;
        let TestCase {
            chain,
            agent_key: alice,
            dht_store,
            keystore,
        } = TestCase::new().await;

        drop(chain);
        let pop = seed_population(&dht_store, &keystore, &alice, SEED, 300).await?;
        let chain = fresh_chain(&dht_store, &keystore, &alice).await?;
        let bob = keystore.new_sign_keypair_random().await.unwrap();

        let (secret, function) = pop.live_transferable.last().cloned().unwrap();
        assert!(
            matches!(
                chain
                    .valid_cap_grant(function.clone(), bob.clone(), Some(secret))
                    .await?,
                Some(CapGrant::RemoteAgent(_))
            ),
            "a live transferable secret must authorise even with hundreds of decoys present"
        );

        // A secret of the right shape that was never committed.
        assert_eq!(
            chain
                .valid_cap_grant(
                    function.clone(),
                    bob.clone(),
                    Some(secret_from(u64::MAX - 1))
                )
                .await?,
            None,
            "an ungranted secret must never authorise"
        );

        // No secret at all must not reach a secret-bearing grant.
        assert_eq!(
            chain.valid_cap_grant(function, bob, None).await?,
            None,
            "a secret-bearing grant must not be reachable without the secret"
        );

        // Sanity: alice is unaffected by the decoys.
        assert_eq!(
            chain
                .valid_cap_grant(("zome_a".into(), "fn_one".into()), alice.clone(), None)
                .await?,
            Some(CapGrant::ChainAuthor(alice)),
        );
        Ok(())
    }

    /// Deleting one grant among many revokes exactly that grant.
    #[tokio::test(flavor = "multi_thread")]
    async fn cap_grant_delete_revokes_only_the_deleted_grant() -> SourceChainResult<()> {
        const SEED: u64 = 0x00DE_AD02;
        let TestCase {
            chain,
            agent_key: alice,
            dht_store,
            keystore,
            ..
        } = TestCase::new().await;

        drop(chain);
        let pop = seed_population(&dht_store, &keystore, &alice, SEED, 200).await?;
        let chain = fresh_chain(&dht_store, &keystore, &alice).await?;
        let bob = keystore.new_sign_keypair_random().await.unwrap();

        // Every secret the population marked dead (deleted or superseded) must
        // be refused; every live one must still work.
        for (secret, function) in &pop.dead_secrets {
            assert_eq!(
                chain
                    .valid_cap_grant(function.clone(), bob.clone(), Some(*secret))
                    .await?,
                None,
                "a deleted/superseded grant must not authorise"
            );
        }
        for (secret, function) in pop.live_transferable.iter().take(10) {
            assert!(
                chain
                    .valid_cap_grant(function.clone(), bob.clone(), Some(*secret))
                    .await?
                    .is_some(),
                "a neighbouring live grant must be unaffected by the deletes"
            );
        }

        // Now delete one more, explicitly, and watch it flip.
        let target = ZomeCallCapGrant::new(
            "explicit-target".into(),
            CapAccess::Transferable {
                secret: secret_from(999),
            },
            listed(&[("zome_a", "fn_one")]),
        );
        let function: GrantedFunction = ("zome_a".into(), "fn_one".into());
        let (action, entry) = put_cap_grant(&chain, &target).await?;
        chain.flush(vec![DhtArc::Empty]).await.unwrap();
        assert_eq!(
            chain
                .valid_cap_grant(function.clone(), bob.clone(), Some(secret_from(999)))
                .await?,
            Some(target.clone().into())
        );

        let chain = fresh_chain(&dht_store, &keystore, &alice).await?;
        delete_cap_grant(&chain, action, entry).await?;
        chain.flush(vec![DhtArc::Empty]).await.unwrap();
        let after = chain
            .valid_cap_grant(function.clone(), bob.clone(), Some(secret_from(999)))
            .await?;
        assert_eq!(after, None, "delete must revoke immediately");
        assert_eq!(
            after,
            oracle_decision(&dht_store, &alice, &function, &bob, Some(secret_from(999))).await?
        );
        Ok(())
    }

    /// Updating a grant retires the old secret and activates the new one, with
    /// hundreds of decoys present.
    #[tokio::test(flavor = "multi_thread")]
    async fn cap_grant_update_retires_old_secret_among_many() -> SourceChainResult<()> {
        const SEED: u64 = 0x00FE_ED03;
        let TestCase {
            chain,
            agent_key: alice,
            dht_store,
            keystore,
            ..
        } = TestCase::new().await;

        drop(chain);
        seed_population(&dht_store, &keystore, &alice, SEED, 200).await?;
        let chain = fresh_chain(&dht_store, &keystore, &alice).await?;
        let bob = keystore.new_sign_keypair_random().await.unwrap();

        let old_secret = secret_from(4_242);
        let new_secret = secret_from(4_243);
        let function: GrantedFunction = ("zome_b".into(), "fn_one".into());

        let original = ZomeCallCapGrant::new(
            "update-target".into(),
            CapAccess::Transferable { secret: old_secret },
            listed(&[("zome_b", "fn_one")]),
        );
        let (action, entry) = put_cap_grant(&chain, &original).await?;
        chain.flush(vec![DhtArc::Empty]).await.unwrap();
        assert_eq!(
            chain
                .valid_cap_grant(function.clone(), bob.clone(), Some(old_secret))
                .await?,
            Some(original.clone().into())
        );

        let updated = ZomeCallCapGrant::new(
            "update-target".into(),
            CapAccess::Transferable { secret: new_secret },
            listed(&[("zome_b", "fn_one")]),
        );
        let chain = fresh_chain(&dht_store, &keystore, &alice).await?;
        update_cap_grant(&chain, action, entry, &updated).await?;
        chain.flush(vec![DhtArc::Empty]).await.unwrap();

        assert_eq!(
            chain
                .valid_cap_grant(function.clone(), bob.clone(), Some(old_secret))
                .await?,
            None,
            "the superseded secret must stop authorising"
        );
        assert_eq!(
            chain
                .valid_cap_grant(function.clone(), bob.clone(), Some(new_secret))
                .await?,
            Some(updated.clone().into()),
            "the updated secret must authorise"
        );
        for secret in [old_secret, new_secret] {
            assert_eq!(
                chain
                    .valid_cap_grant(function.clone(), bob.clone(), Some(secret))
                    .await?,
                oracle_decision(&dht_store, &alice, &function, &bob, Some(secret)).await?
            );
        }
        Ok(())
    }

    /// Assignee enforcement and function scoping survive the rewrite at scale.
    #[tokio::test(flavor = "multi_thread")]
    async fn cap_grant_assignee_and_function_scope_among_many() -> SourceChainResult<()> {
        const SEED: u64 = 0x00A5_5104;
        let TestCase {
            chain,
            agent_key: alice,
            dht_store,
            keystore,
            ..
        } = TestCase::new().await;

        drop(chain);
        seed_population(&dht_store, &keystore, &alice, SEED, 200).await?;
        let chain = fresh_chain(&dht_store, &keystore, &alice).await?;
        let bob = keystore.new_sign_keypair_random().await.unwrap();
        let carol = keystore.new_sign_keypair_random().await.unwrap();

        let secret = secret_from(77_777);
        let mut assignees = BTreeSet::new();
        assignees.insert(bob.clone());
        let grant = ZomeCallCapGrant::new(
            "assigned-target".into(),
            CapAccess::Assigned {
                secret,
                assignees: assignees.clone(),
            },
            listed(&[("zome_c", "fn_three")]),
        );
        put_cap_grant(&chain, &grant).await?;
        chain.flush(vec![DhtArc::Empty]).await.unwrap();

        let granted: GrantedFunction = ("zome_c".into(), "fn_three".into());
        let other: GrantedFunction = ("zome_c".into(), "fn_four".into());

        // Assignee + right function + right secret: allowed.
        assert_eq!(
            chain
                .valid_cap_grant(granted.clone(), bob.clone(), Some(secret))
                .await?,
            Some(grant.clone().into())
        );
        // Non-assignee with the right secret: denied.
        assert_eq!(
            chain
                .valid_cap_grant(granted.clone(), carol.clone(), Some(secret))
                .await?,
            None
        );
        // Assignee, right secret, ungranted function: denied.
        assert_eq!(
            chain
                .valid_cap_grant(other.clone(), bob.clone(), Some(secret))
                .await?,
            None
        );
        // Assignee, granted function, no secret: denied.
        assert_eq!(
            chain
                .valid_cap_grant(granted.clone(), bob.clone(), None)
                .await?,
            None
        );

        for (f, a, s) in [
            (granted.clone(), bob.clone(), Some(secret)),
            (granted.clone(), carol.clone(), Some(secret)),
            (other, bob.clone(), Some(secret)),
            (granted, bob, None),
        ] {
            assert_eq!(
                chain.valid_cap_grant(f.clone(), a.clone(), s).await?,
                oracle_decision(&dht_store, &alice, &f, &a, s).await?
            );
        }
        Ok(())
    }

    /// The unrestricted path is untouched: an `Unrestricted` grant authorises
    /// any agent for its listed functions with no secret, is not reachable
    /// when a secret *is* supplied, and is scoped to its functions — all with
    /// hundreds of secret-bearing decoys in the table.
    #[tokio::test(flavor = "multi_thread")]
    async fn cap_grant_unrestricted_path_unchanged_among_many() -> SourceChainResult<()> {
        const SEED: u64 = 0x000F_EE05;
        let TestCase {
            chain,
            agent_key: alice,
            dht_store,
            keystore,
            ..
        } = TestCase::new().await;

        drop(chain);
        seed_population(&dht_store, &keystore, &alice, SEED, 200).await?;
        let chain = fresh_chain(&dht_store, &keystore, &alice).await?;
        let bob = keystore.new_sign_keypair_random().await.unwrap();

        let grant = ZomeCallCapGrant::new(
            "open".into(),
            CapAccess::Unrestricted,
            listed(&[("zome_open", "hello")]),
        );
        put_cap_grant(&chain, &grant).await?;
        chain.flush(vec![DhtArc::Empty]).await.unwrap();

        let open: GrantedFunction = ("zome_open".into(), "hello".into());
        let closed: GrantedFunction = ("zome_open".into(), "goodbye".into());

        assert_eq!(
            chain
                .valid_cap_grant(open.clone(), bob.clone(), None)
                .await?,
            Some(grant.clone().into())
        );
        assert_eq!(
            chain
                .valid_cap_grant(closed.clone(), bob.clone(), None)
                .await?,
            None
        );
        // Supplying a secret must NOT reach an unrestricted grant — the
        // candidate set is the secret-bearing classes only.
        assert_eq!(
            chain
                .valid_cap_grant(open.clone(), bob.clone(), Some(secret_from(5)))
                .await?,
            None
        );
        for (f, s) in [
            (open.clone(), None),
            (closed, None),
            (open, Some(secret_from(5))),
        ] {
            assert_eq!(
                chain.valid_cap_grant(f.clone(), bob.clone(), s).await?,
                oracle_decision(&dht_store, &alice, &f, &bob, s).await?
            );
        }
        Ok(())
    }

    /// Two agents of the same DNA share the `CapGrant`, `Action` and
    /// `PrivateEntry` tables. A grant authored by one must never authorise a
    /// call on the other's chain — the `Action.author` predicate is the only
    /// thing preventing a cross-agent capability leak, so it is pinned here
    /// against a populated table.
    #[tokio::test(flavor = "multi_thread")]
    async fn cap_grant_does_not_leak_across_authors_in_the_same_db() -> SourceChainResult<()> {
        let keystore = test_keystore();
        let dna_hash = fixt!(DnaHash);
        let dht_store = crate::test_utils::test_dht_store(dna_hash.clone()).await;

        let alice = keystore.new_sign_keypair_random().await.unwrap();
        let carol = keystore.new_sign_keypair_random().await.unwrap();
        for agent in [&alice, &carol] {
            genesis(
                dht_store.clone(),
                keystore.clone(),
                dna_hash.clone(),
                agent.clone(),
                None,
            )
            .await
            .unwrap();
        }
        // Populate alice's chain, then grant carol's caller a secret on
        // *carol's* chain only.
        seed_population(&dht_store, &keystore, &alice, 0x00CA_1106, 120).await?;
        let alice_chain = fresh_chain(&dht_store, &keystore, &alice).await?;
        let carol_chain = fresh_chain(&dht_store, &keystore, &carol).await?;

        let bob = keystore.new_sign_keypair_random().await.unwrap();
        let secret = secret_from(31_337);
        let function: GrantedFunction = ("zome_a".into(), "fn_one".into());
        let carol_grant = ZomeCallCapGrant::new(
            "carols".into(),
            CapAccess::Transferable { secret },
            listed(&[("zome_a", "fn_one")]),
        );
        put_cap_grant(&carol_chain, &carol_grant).await?;
        carol_chain.flush(vec![DhtArc::Empty]).await.unwrap();

        // Works on carol's chain …
        assert_eq!(
            carol_chain
                .valid_cap_grant(function.clone(), bob.clone(), Some(secret))
                .await?,
            Some(carol_grant.into())
        );
        // … and must NOT work on alice's, despite sharing the tables.
        assert_eq!(
            alice_chain
                .valid_cap_grant(function.clone(), bob.clone(), Some(secret))
                .await?,
            None,
            "a grant authored by carol must never authorise a call on alice's chain"
        );

        // Alice's own grants must likewise not appear in carol's candidates.
        let carol_candidates = dht_store
            .as_read()
            .valid_cap_grants(&carol, Some(&secret))
            .await?;
        assert_eq!(carol_candidates.len(), 1);
        assert_eq!(
            carol_candidates,
            dht_store
                .as_read()
                .valid_cap_grants_reference(&carol, Some(&secret))
                .await?
        );
        Ok(())
    }

    /// Revoking an `Unrestricted` grant. This is the highest-blast-radius case
    /// in the whole surface: an unrestricted grant authorises ANY agent with NO
    /// secret, so if a delete failed to take effect the grant would stay open
    /// to the world. It is also the only shape that exercises the two `NOT IN`
    /// anti-joins on the `check_secret == None` path.
    #[tokio::test(flavor = "multi_thread")]
    async fn cap_grant_delete_revokes_unrestricted_grant() -> SourceChainResult<()> {
        let TestCase {
            chain,
            agent_key: alice,
            dht_store,
            keystore,
        } = TestCase::new().await;

        let bob = keystore.new_sign_keypair_random().await.unwrap();
        let open: GrantedFunction = ("zome_open".into(), "hello".into());
        let neighbour: GrantedFunction = ("zome_open".into(), "neighbour".into());

        let target = ZomeCallCapGrant::new(
            "open-target".into(),
            CapAccess::Unrestricted,
            listed(&[("zome_open", "hello")]),
        );
        let bystander = ZomeCallCapGrant::new(
            "open-bystander".into(),
            CapAccess::Unrestricted,
            listed(&[("zome_open", "neighbour")]),
        );
        let (action, entry) = put_cap_grant(&chain, &target).await?;
        put_cap_grant(&chain, &bystander).await?;
        chain.flush(vec![DhtArc::Empty]).await.unwrap();

        assert_eq!(
            chain
                .valid_cap_grant(open.clone(), bob.clone(), None)
                .await?,
            Some(target.clone().into()),
            "an unrestricted grant must authorise any agent with no secret"
        );

        let chain = fresh_chain(&dht_store, &keystore, &alice).await?;
        delete_cap_grant(&chain, action, entry).await?;
        chain.flush(vec![DhtArc::Empty]).await.unwrap();

        assert_eq!(
            chain
                .valid_cap_grant(open.clone(), bob.clone(), None)
                .await?,
            None,
            "deleting an unrestricted grant must close it to the world immediately"
        );
        assert_eq!(
            chain
                .valid_cap_grant(neighbour.clone(), bob.clone(), None)
                .await?,
            Some(bystander.into()),
            "the neighbouring unrestricted grant must be unaffected"
        );
        for f in [open, neighbour] {
            assert_eq!(
                chain.valid_cap_grant(f.clone(), bob.clone(), None).await?,
                oracle_decision(&dht_store, &alice, &f, &bob, None).await?
            );
        }
        Ok(())
    }

    /// The update twin of the above: superseding an `Unrestricted` grant closes
    /// the old function and opens the new one, on the no-secret path.
    #[tokio::test(flavor = "multi_thread")]
    async fn cap_grant_update_retires_unrestricted_grant() -> SourceChainResult<()> {
        let TestCase {
            chain,
            agent_key: alice,
            dht_store,
            keystore,
        } = TestCase::new().await;

        let bob = keystore.new_sign_keypair_random().await.unwrap();
        let before: GrantedFunction = ("zome_open".into(), "before".into());
        let after: GrantedFunction = ("zome_open".into(), "after".into());

        let original = ZomeCallCapGrant::new(
            "open-update".into(),
            CapAccess::Unrestricted,
            listed(&[("zome_open", "before")]),
        );
        let (action, entry) = put_cap_grant(&chain, &original).await?;
        chain.flush(vec![DhtArc::Empty]).await.unwrap();
        assert_eq!(
            chain
                .valid_cap_grant(before.clone(), bob.clone(), None)
                .await?,
            Some(original.into())
        );

        let updated = ZomeCallCapGrant::new(
            "open-update".into(),
            CapAccess::Unrestricted,
            listed(&[("zome_open", "after")]),
        );
        let chain = fresh_chain(&dht_store, &keystore, &alice).await?;
        update_cap_grant(&chain, action, entry, &updated).await?;
        chain.flush(vec![DhtArc::Empty]).await.unwrap();

        assert_eq!(
            chain
                .valid_cap_grant(before.clone(), bob.clone(), None)
                .await?,
            None,
            "the superseded unrestricted function must stop authorising"
        );
        assert_eq!(
            chain
                .valid_cap_grant(after.clone(), bob.clone(), None)
                .await?,
            Some(updated.into()),
            "the updated unrestricted function must authorise"
        );
        for f in [before, after] {
            assert_eq!(
                chain.valid_cap_grant(f.clone(), bob.clone(), None).await?,
                oracle_decision(&dht_store, &alice, &f, &bob, None).await?
            );
        }
        Ok(())
    }

    /// A private grant's ENTRY HASH is not a secret: it travels in the clear on
    /// the `Create` action, so any agent can author a `Delete` or an `Update`
    /// naming another agent's grant entry hash and have it integrated into
    /// `DeletedRecord` / `UpdatedRecord`. The `ua.author` / `da.author`
    /// predicates in the anti-joins are the ONLY thing stopping that from
    /// revoking alice's capabilities network-wide — a denial-of-service on
    /// every grant she holds. Pinned here with carol genuinely genesis'd into
    /// the same DNA database, so the shared index tables really do contain her
    /// rows.
    #[tokio::test(flavor = "multi_thread")]
    async fn cap_grant_foreign_author_cannot_revoke_a_grant() -> SourceChainResult<()> {
        let keystore = test_keystore();
        let dna_hash = fixt!(DnaHash);
        let dht_store = crate::test_utils::test_dht_store(dna_hash.clone()).await;

        let alice = keystore.new_sign_keypair_random().await.unwrap();
        let carol = keystore.new_sign_keypair_random().await.unwrap();
        for agent in [&alice, &carol] {
            genesis(
                dht_store.clone(),
                keystore.clone(),
                dna_hash.clone(),
                agent.clone(),
                None,
            )
            .await
            .unwrap();
        }

        let bob = keystore.new_sign_keypair_random().await.unwrap();
        let secret = secret_from(24_680);
        let guarded: GrantedFunction = ("zome_a".into(), "fn_one".into());
        let open: GrantedFunction = ("zome_open".into(), "hello".into());

        // Alice commits one secret-bearing and one unrestricted grant.
        let alice_chain = fresh_chain(&dht_store, &keystore, &alice).await?;
        let transferable = ZomeCallCapGrant::new(
            "alice-transferable".into(),
            CapAccess::Transferable { secret },
            listed(&[("zome_a", "fn_one")]),
        );
        let unrestricted = ZomeCallCapGrant::new(
            "alice-unrestricted".into(),
            CapAccess::Unrestricted,
            listed(&[("zome_open", "hello")]),
        );
        let (t_action, t_entry) = put_cap_grant(&alice_chain, &transferable).await?;
        let (u_action, u_entry) = put_cap_grant(&alice_chain, &unrestricted).await?;
        alice_chain.flush(vec![DhtArc::Empty]).await.unwrap();

        // Carol authors a Delete and an Update naming ALICE's grant entry
        // hashes, on her own chain. Nothing stops her: the hashes are public.
        let carol_chain = fresh_chain(&dht_store, &keystore, &carol).await?;
        delete_cap_grant(&carol_chain, t_action, t_entry.clone()).await?;
        let hijack = ZomeCallCapGrant::new(
            "carols-hijack".into(),
            CapAccess::Unrestricted,
            listed(&[("zome_open", "hijacked")]),
        );
        update_cap_grant(&carol_chain, u_action, u_entry.clone(), &hijack).await?;
        carol_chain.flush(vec![DhtArc::Empty]).await.unwrap();

        // The foreign modifications really did land in the shared index tables.
        assert!(
            !dht_store
                .as_read()
                .db()
                .get_delete_actions_for_entry(&t_entry)
                .await
                .unwrap()
                .is_empty(),
            "test precondition: carol's Delete must be indexed against alice's grant entry"
        );
        assert!(
            !dht_store
                .as_read()
                .db()
                .get_update_actions_for_entry(&u_entry)
                .await
                .unwrap()
                .is_empty(),
            "test precondition: carol's Update must be indexed against alice's grant entry"
        );

        // …and neither of them revokes anything of alice's.
        assert_eq!(
            alice_chain
                .valid_cap_grant(guarded.clone(), bob.clone(), Some(secret))
                .await?,
            Some(transferable.into()),
            "a foreign Delete must not revoke alice's transferable grant"
        );
        assert_eq!(
            alice_chain
                .valid_cap_grant(open.clone(), bob.clone(), None)
                .await?,
            Some(unrestricted.into()),
            "a foreign Update must not supersede alice's unrestricted grant"
        );

        // And the rewrite agrees with the reference on both.
        for (f, sec) in [(guarded, Some(secret)), (open, None)] {
            assert_eq!(
                alice_chain
                    .valid_cap_grant(f.clone(), bob.clone(), sec)
                    .await?,
                oracle_decision(&dht_store, &alice, &f, &bob, sec).await?
            );
            assert_eq!(
                dht_store
                    .as_read()
                    .valid_cap_grants(&alice, sec.as_ref())
                    .await?,
                dht_store
                    .as_read()
                    .valid_cap_grants_reference(&alice, sec.as_ref())
                    .await?
            );
        }
        Ok(())
    }

    /// A corrupt action on a LIVE grant must fail the authorisation read CLOSED
    /// — `Err`, which `verify_grant` turns into a denial — exactly as the old
    /// per-row `get_action` did (its `else { continue }` covered a MISSING row;
    /// a row that failed to decode propagated `sqlx::Error::Decode`).
    ///
    /// This matters because `Action.entry_hash` is a fixed-width value on the
    /// B-tree leaf while the variable-length `action_data` spills to overflow
    /// pages: one bad block can corrupt the blob and leave the row readable, so
    /// a rewrite that trusted the column alone would silently fail OPEN.
    #[tokio::test(flavor = "multi_thread")]
    async fn cap_grant_corrupt_live_action_fails_closed() -> SourceChainResult<()> {
        let TestCase {
            chain,
            agent_key: alice,
            dht_store,
            keystore,
        } = TestCase::new().await;

        let bob = keystore.new_sign_keypair_random().await.unwrap();
        let secret = secret_from(5_150);
        let function: GrantedFunction = ("zome_a".into(), "fn_one".into());
        let grant = ZomeCallCapGrant::new(
            "corruptible".into(),
            CapAccess::Transferable { secret },
            listed(&[("zome_a", "fn_one")]),
        );
        let (action, entry) = put_cap_grant(&chain, &grant).await?;
        chain.flush(vec![DhtArc::Empty]).await.unwrap();

        // Healthy first.
        assert_eq!(
            chain
                .valid_cap_grant(function.clone(), bob.clone(), Some(secret))
                .await?,
            Some(grant.into())
        );

        // Corrupt the action_data blob in place, leaving every other column —
        // including entry_hash — perfectly readable.
        sqlx::query("UPDATE Action SET action_data = ? WHERE hash = ?")
            .bind(vec![0xFF_u8; 24])
            .bind(action.get_raw_36())
            .execute(dht_store.db().pool())
            .await
            .unwrap();

        let new = dht_store
            .as_read()
            .valid_cap_grants(&alice, Some(&secret))
            .await;
        let old = dht_store
            .as_read()
            .valid_cap_grants_reference(&alice, Some(&secret))
            .await;
        assert!(
            new.is_err(),
            "a corrupt action on a live grant must fail the read closed, got {new:?}"
        );
        assert!(old.is_err(), "the reference must also fail closed");

        // And the decision path denies rather than authorising.
        assert!(
            chain
                .valid_cap_grant(function, bob.clone(), Some(secret))
                .await
                .is_err(),
            "a corrupt live grant must not authorise"
        );

        // A corrupt action on an ALREADY-REVOKED grant is filtered out before
        // anything is decoded, so it no longer errors. That is the one
        // deliberate divergence from the old behaviour: strictly more
        // available, and it cannot authorise anything that was not already
        // authorised.
        let chain = fresh_chain(&dht_store, &keystore, &alice).await?;
        delete_cap_grant(&chain, action, entry).await?;
        chain.flush(vec![DhtArc::Empty]).await.unwrap();
        let after = dht_store
            .as_read()
            .valid_cap_grants(&alice, Some(&secret))
            .await;
        assert!(
            matches!(&after, Ok(v) if v.is_empty()),
            "a corrupt action on a revoked grant is filtered before decode, got {after:?}"
        );
        Ok(())
    }

    /// Missing private bytes must not hide a corrupt indexed grant action.
    /// The reference reader decodes that action before deciding its entry is
    /// absent, so a later valid grant must not turn corruption into access.
    #[tokio::test(flavor = "multi_thread")]
    async fn cap_grant_missing_private_entry_still_decodes_action() -> SourceChainResult<()> {
        for corruption in ["signature", "action_data", "null_entry_hash"] {
            let TestCase {
                chain,
                agent_key: alice,
                dht_store,
                keystore,
            } = TestCase::new().await;

            let bob = keystore.new_sign_keypair_random().await.unwrap();
            let secret = secret_from(5_151);
            let function: GrantedFunction = ("zome_a".into(), "fn_one".into());
            let first = ZomeCallCapGrant::new(
                "missing-private-first".into(),
                CapAccess::Transferable { secret },
                listed(&[("zome_a", "fn_one")]),
            );
            let second = ZomeCallCapGrant::new(
                "valid-second".into(),
                CapAccess::Transferable { secret },
                listed(&[("zome_a", "fn_one")]),
            );
            let (first_action, first_entry) = put_cap_grant(&chain, &first).await?;
            chain.flush(vec![DhtArc::Empty]).await.unwrap();
            let chain = fresh_chain(&dht_store, &keystore, &alice).await?;
            put_cap_grant(&chain, &second).await?;
            chain.flush(vec![DhtArc::Empty]).await.unwrap();
            let chain = fresh_chain(&dht_store, &keystore, &alice).await?;

            sqlx::query("DELETE FROM PrivateEntry WHERE hash = ? AND author = ?")
                .bind(first_entry.get_raw_36())
                .bind(alice.get_raw_36())
                .execute(dht_store.db().pool())
                .await
                .unwrap();

            // Absence alone is a legitimate skip: the second grant works.
            let new = dht_store
                .as_read()
                .valid_cap_grants(&alice, Some(&secret))
                .await?;
            let old = dht_store
                .as_read()
                .valid_cap_grants_reference(&alice, Some(&secret))
                .await?;
            assert_eq!(new, old, "{corruption}: missing bytes alone must match");
            assert_eq!(new.len(), 1, "{corruption}: only the second grant remains");

            match corruption {
                "signature" => {
                    sqlx::query("UPDATE Action SET signature = ? WHERE hash = ?")
                        .bind(vec![0_u8; 3])
                        .bind(first_action.get_raw_36())
                        .execute(dht_store.db().pool())
                        .await
                        .unwrap();
                }
                "action_data" => {
                    sqlx::query("UPDATE Action SET action_data = ? WHERE hash = ?")
                        .bind(vec![0xFF_u8; 24])
                        .bind(first_action.get_raw_36())
                        .execute(dht_store.db().pool())
                        .await
                        .unwrap();
                }
                "null_entry_hash" => {
                    sqlx::query(
                        "UPDATE Action SET entry_hash = NULL, signature = ? WHERE hash = ?",
                    )
                    .bind(vec![0_u8; 3])
                    .bind(first_action.get_raw_36())
                    .execute(dht_store.db().pool())
                    .await
                    .unwrap();
                }
                _ => unreachable!(),
            }

            let new = dht_store
                .as_read()
                .valid_cap_grants(&alice, Some(&secret))
                .await;
            let old = dht_store
                .as_read()
                .valid_cap_grants_reference(&alice, Some(&secret))
                .await;
            assert!(
                new.is_err(),
                "{corruption}: optimized read must deny, got {new:?}"
            );
            assert!(
                old.is_err(),
                "{corruption}: reference read must deny, got {old:?}"
            );
            assert!(
                chain
                    .valid_cap_grant(function.clone(), bob.clone(), Some(secret))
                    .await
                    .is_err(),
                "{corruption}: later valid grant must not authorize"
            );
        }
        Ok(())
    }

    /// Structural guard against the regression this change removes: the old
    /// lookup paid `3N + ceil(N/500) + 1` queries (and as many pool
    /// acquisitions) for `N` grants of a class; the new one pays exactly one
    /// per access class. The two are compared over the *same* populated store,
    /// so a shared slowdown (loaded CI host, cold cache) moves both sides
    /// together and only the per-grant query fan-out shows up in the ratio.
    /// The real gap is two orders of magnitude; the threshold is 3x so this
    /// can only fail if the per-row reads come back.
    ///
    /// A direct query-count assertion would be strictly better, and was
    /// considered. There is no statement counter on `DbRead`/`sqlx::Pool`, and
    /// the only hook is sqlx's `tracing` event per statement, which needs a
    /// GLOBAL subscriber — process-wide, so it would count the queries of every
    /// other test running in parallel and would have to be serialised behind a
    /// mutex. That machinery was judged not worth it for a property that is
    /// provable by reading `get_live_cap_grant_entries`: one `fetch_all`, no
    /// loop. Left as a timing ratio deliberately; if it ever flakes, delete it
    /// rather than widening the threshold.
    #[tokio::test(flavor = "multi_thread")]
    async fn cap_grant_lookup_cost_does_not_scale_with_grant_count() -> SourceChainResult<()> {
        const SEED: u64 = 0x005C_A107;
        let TestCase {
            chain,
            agent_key: alice,
            dht_store,
            keystore,
            ..
        } = TestCase::new().await;

        drop(chain);
        seed_population(&dht_store, &keystore, &alice, SEED, 600).await?;
        let probe = secret_from(1);

        // Warm the pool and the page cache for both paths before timing.
        let warm_new = dht_store
            .as_read()
            .valid_cap_grants(&alice, Some(&probe))
            .await?;
        let warm_old = dht_store
            .as_read()
            .valid_cap_grants_reference(&alice, Some(&probe))
            .await?;
        assert_eq!(warm_new, warm_old);
        assert!(
            warm_new.len() > 200,
            "expected a large candidate set, got {}",
            warm_new.len()
        );

        let t0 = std::time::Instant::now();
        for _ in 0..3 {
            dht_store
                .as_read()
                .valid_cap_grants(&alice, Some(&probe))
                .await?;
        }
        let new_elapsed = t0.elapsed();

        let t1 = std::time::Instant::now();
        for _ in 0..3 {
            dht_store
                .as_read()
                .valid_cap_grants_reference(&alice, Some(&probe))
                .await?;
        }
        let old_elapsed = t1.elapsed();

        assert!(
            new_elapsed * 3 < old_elapsed,
            "the per-grant query fan-out appears to have returned: \
             new {new_elapsed:?} vs reference {old_elapsed:?} over {} candidates",
            warm_new.len()
        );
        Ok(())
    }

    /// A capability grant is resolved ONLY from the author's `PrivateEntry`,
    /// never from the public `Entry` table.
    ///
    /// A cap grant is always a private entry (`EntryType::CapGrant` =>
    /// `EntryVisibility::Private`) and the source-chain flush routes a private
    /// entry only to `PrivateEntry`, so the author's real grant lives there and
    /// a row in the public `Entry` table at a grant entry hash is not a
    /// legitimate grant. This test puts a *different* grant blob in the public
    /// `Entry` table at the owner's grant entry hash (a raw INSERT) and pins
    /// that the read resolves the owner's real private grant and never the
    /// public-table row. It also records that the former public-first read
    /// resolved a different row, so a regression is unambiguous.
    #[tokio::test(flavor = "multi_thread")]
    async fn cap_grant_reads_only_the_private_entry() -> SourceChainResult<()> {
        let TestCase {
            chain,
            agent_key: owner,
            dht_store,
            keystore,
        } = TestCase::new().await;

        let caller = keystore.new_sign_keypair_random().await.unwrap();

        // The owner's real grant: Transferable, one specific function, with a
        // secret. This is the only legitimate grant at its entry hash.
        let owner_secret = secret_from(0x5EC1);
        let owner_fn: GrantedFunction = ("zome_owner".into(), "fn_real".into());
        let owner_grant = ZomeCallCapGrant::new(
            "owner-real".into(),
            CapAccess::Transferable {
                secret: owner_secret,
            },
            listed(&[("zome_owner", "fn_real")]),
        );
        let (_action, grant_entry_hash) = put_cap_grant(&chain, &owner_grant).await?;
        chain.flush(vec![DhtArc::Empty]).await.unwrap();

        // A different grant blob (Unrestricted + All — it would authorise any
        // agent for any function and ignore the secret) placed in the PUBLIC
        // `Entry` table at the owner's grant entry hash. The owner's real grant
        // lives in `PrivateEntry`, so this hash is empty in the public table and
        // the insert lands cleanly. It is not a legitimate grant and the read
        // must never consult it.
        let public_row_grant = ZomeCallCapGrant::new(
            "public-row".into(),
            CapAccess::Unrestricted,
            GrantedFunctions::All,
        );
        let public_row_entry = Entry::CapGrant(public_row_grant.clone());
        let public_row_blob =
            holochain_serialized_bytes::encode(&public_row_entry).expect("encode entry");
        sqlx::query("INSERT INTO Entry (hash, blob) VALUES (?, ?)")
            .bind(grant_entry_hash.get_raw_36())
            .bind(public_row_blob)
            .execute(dht_store.db().pool())
            .await
            .unwrap();

        // A caller with an unrelated secret and an unrelated function. The
        // access-class filter only needs *some* secret to reach the
        // secret-bearing classes; the public-table grant, being Unrestricted,
        // would then ignore the secret and the function.
        let unrelated_secret = secret_from(0xBAD1);
        let unrelated_fn: GrantedFunction = ("anything".into(), "at_all".into());

        // (1) The former public-first read resolved the public-table row rather
        //     than the owner's real grant. The reference oracle preserves that
        //     old behaviour verbatim, so this documents the exact difference a
        //     regression would reintroduce.
        let reference_decision = oracle_decision(
            &dht_store,
            &owner,
            &unrelated_fn,
            &caller,
            Some(unrelated_secret),
        )
        .await?;
        assert_eq!(
            reference_decision,
            Some(CapGrant::from(public_row_grant.clone())),
            "the former public-first read resolved the public-table row"
        );

        // (2) The fixed read consults only `PrivateEntry`.
        //     - the candidate set never contains the public-table row;
        let candidates = dht_store
            .as_read()
            .valid_cap_grants(&owner, Some(&owner_secret))
            .await?;
        assert!(
            !candidates.contains(&CapGrant::from(public_row_grant.clone())),
            "the public-table row must never appear as a candidate"
        );
        assert_eq!(
            candidates,
            vec![CapGrant::from(owner_grant.clone())],
            "only the owner's real private grant is a candidate"
        );

        //     - and the public-table grant authorises nothing, for any secret
        //       shape.
        for probe_secret in [Some(unrelated_secret), Some(owner_secret), None] {
            assert_eq!(
                chain
                    .valid_cap_grant(unrelated_fn.clone(), caller.clone(), probe_secret)
                    .await?,
                None,
                "the public-table row must not authorise (secret: {:?})",
                probe_secret.is_some()
            );
        }

        // (3) The owner's own legitimate access is unaffected.
        let legit = keystore.new_sign_keypair_random().await.unwrap();
        assert_eq!(
            chain
                .valid_cap_grant(owner_fn.clone(), legit.clone(), Some(owner_secret))
                .await?,
            Some(owner_grant.into()),
            "the owner's real grant must still authorise its legitimate caller"
        );
        Ok(())
    }

    /// Two grants with identical content share one entry hash but have distinct
    /// actions. The old code produced one candidate per *action* (duplicates
    /// preserved) and a delete keyed on the shared entry hash revoked both;
    /// the rewrite must behave the same.
    #[tokio::test(flavor = "multi_thread")]
    async fn cap_grant_duplicate_entries_match_reference() -> SourceChainResult<()> {
        let TestCase {
            chain,
            agent_key: alice,
            dht_store,
            keystore,
            ..
        } = TestCase::new().await;

        let bob = keystore.new_sign_keypair_random().await.unwrap();
        let secret = secret_from(12_345);
        let function: GrantedFunction = ("zome_a".into(), "fn_one".into());
        let grant = ZomeCallCapGrant::new(
            "dupe".into(),
            CapAccess::Transferable { secret },
            listed(&[("zome_a", "fn_one")]),
        );

        let (first_action, entry) = put_cap_grant(&chain, &grant).await?;
        chain.flush(vec![DhtArc::Empty]).await.unwrap();
        let chain = fresh_chain(&dht_store, &keystore, &alice).await?;
        let (_second_action, entry2) = put_cap_grant(&chain, &grant).await?;
        chain.flush(vec![DhtArc::Empty]).await.unwrap();
        assert_eq!(entry, entry2, "identical grants must share an entry hash");

        let new = dht_store
            .as_read()
            .valid_cap_grants(&alice, Some(&secret))
            .await?;
        let old = dht_store
            .as_read()
            .valid_cap_grants_reference(&alice, Some(&secret))
            .await?;
        assert_eq!(new, old);
        assert_eq!(new.len(), 2, "one candidate per action, duplicates kept");

        // Deleting one action deletes the shared entry hash, so both go.
        let chain = fresh_chain(&dht_store, &keystore, &alice).await?;
        delete_cap_grant(&chain, first_action, entry).await?;
        chain.flush(vec![DhtArc::Empty]).await.unwrap();
        let new = dht_store
            .as_read()
            .valid_cap_grants(&alice, Some(&secret))
            .await?;
        assert_eq!(
            new,
            dht_store
                .as_read()
                .valid_cap_grants_reference(&alice, Some(&secret))
                .await?
        );
        assert_eq!(
            chain.valid_cap_grant(function, bob, Some(secret)).await?,
            None
        );
        Ok(())
    }

    struct TestCase {
        chain: SourceChain,
        agent_key: AgentPubKey,
        dht_store: DhtStore,
        keystore: MetaLairClient,
    }

    impl TestCase {
        async fn new() -> Self {
            let keystore = test_keystore();
            let dna_hash = fixt!(DnaHash);
            let dht_store = crate::test_utils::test_dht_store(dna_hash.clone()).await;
            let agent_key = keystore.new_sign_keypair_random().await.unwrap();
            genesis(
                dht_store.clone(),
                keystore.clone(),
                dna_hash,
                agent_key.clone(),
                None,
            )
            .await
            .unwrap();
            let chain = SourceChain::new(dht_store.clone(), keystore.clone(), agent_key.clone())
                .await
                .unwrap();
            Self {
                chain,
                agent_key,
                dht_store,
                keystore,
            }
        }
    }

    async fn create_signed_warrant(
        author: &AgentPubKey,
        warrantee: &AgentPubKey,
        keystore: &MetaLairClient,
    ) -> SignedWarrant {
        let warrant = Warrant::new(
            WarrantProof::ChainIntegrity(ChainIntegrityWarrant::InvalidChainOp {
                action_author: warrantee.clone(),
                action: (fixt!(ActionHash), fixt!(Signature)),
                chain_op_type: ChainOpType::AgentActivity,
                reason: "invalid chain op".into(),
            }),
            author.clone(),
            Timestamp::now(),
            warrantee.clone(),
        );
        SignedWarrant::new(
            warrant.clone(),
            author.sign(keystore, warrant).await.unwrap(),
        )
    }
}
