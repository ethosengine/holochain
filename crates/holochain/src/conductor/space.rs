//! This module contains data and functions for running operations
//! at the level of a [`DnaHash`] space.
//! Multiple [`Cell`](crate::conductor::Cell)'s could share the same space.
use super::{conductor::RwShare, error::ConductorResult};
use crate::conductor::error::ConductorError;
use crate::core::workflow::countersigning_workflow::CountersigningWorkspace;
use crate::core::{
    queue_consumer::QueueConsumerMap,
    workflow::{
        incoming_dht_ops_workflow::{
            incoming_dht_ops_workflow, IncomingOpHashes, IncomingOpsBatch,
        },
        witnessing_workflow::{receive_incoming_countersigning_ops, WitnessingWorkspace},
    },
};
use holo_hash::{AgentPubKey, DhtOpHash, DnaHash};
use holochain_conductor_api::conductor::paths::DatabasesRootPath;
use holochain_conductor_api::conductor::ConductorConfig;
use holochain_conductor_api::state::ConductorState;
use holochain_keystore::MetaLairClient;
use holochain_p2p::actor::DynHcP2p;
use holochain_state::data::{DbKey, DbSyncLevel};
use holochain_state::{host_fn_workspace::SourceChainWorkspace, prelude::*};
use holochain_util::timed;
use lair_keystore_api::prelude::SharedLockedArray;
use std::convert::TryInto;
use std::path::PathBuf;
use std::{
    cell::Cell,
    collections::{hash_map, HashMap},
    sync::Arc,
};

/// This is the set of all current
/// [`DnaHash`] spaces for all cells
/// installed on this conductor.
#[derive(Clone)]
pub struct Spaces {
    map: RwShare<HashMap<DnaHash, Space>>,
    pub(crate) db_dir: Arc<DatabasesRootPath>,
    pub(crate) config: Arc<ConductorConfig>,
    /// The map of running queue consumer workflows.
    pub(crate) queue_consumer_map: QueueConsumerMap,
    /// Conductor database for normalized ConductorState
    pub(crate) conductor_store: holochain_state::conductor::ConductorStore,
    pub(crate) wasm_store: holochain_state::wasm::WasmStore,
    pub(crate) dna_def_store: holochain_state::dna_def::DnaDefStore,
    pub(crate) entry_def_store: holochain_state::entry_def::EntryDefStore,
    pub(crate) space_data_config: holochain_state::data::HolochainDataConfig,
    data_db_key: holochain_state::data::DbKey,
    /// ELOHIM PATCH (per-call grant walk): when the capability-grant
    /// lookup-key backfill may run, and where it already does.
    cap_grant_backfill: Arc<CapGrantBackfillGate>,
}

/// Holds the capability-grant lookup-key backfill back until the conductor's
/// cells are running.
///
/// The backfill is strictly background work: a grant it has not reached is
/// authorised at the cost it had before the lookup columns existed. Starting
/// the conductor is not background work — creating cells, joining the network
/// and the workflows those cells trigger all read and write the same per-DNA
/// database, through the same single writer and the same connection pool. So
/// a DNA's store is not backfilled when it is opened; it is backfilled once
/// the conductor has finished enabling its apps, and, for a store opened
/// later, once the cells created with it are running.
#[derive(Default)]
struct CapGrantBackfillGate {
    /// Set when conductor startup has enabled every app.
    cells_running: std::sync::atomic::AtomicBool,
    /// The DNAs whose store already has a backfill task.
    started: parking_lot::Mutex<std::collections::HashSet<DnaHash>>,
}

/// Test-only override of when the capability-grant backfill starts, for
/// measuring what it costs: `0` normal, `1` never, `2` as soon as a store is
/// opened and without the start delay.
#[cfg(test)]
pub(crate) static CAP_GRANT_BACKFILL_TEST_MODE: std::sync::atomic::AtomicU8 =
    std::sync::atomic::AtomicU8::new(0);

/// This is the set of data required at the
/// [`DnaHash`] space level.
/// All cells in the same [`DnaHash`] space
/// will share these.
#[derive(Clone)]
pub struct Space {
    /// The dna hash for this space.
    pub dna_hash: Arc<DnaHash>,

    /// DHT store wrapping the new holochain_data database.
    pub dht_store: DhtStore,

    /// The peer meta store. One per unique Dna.
    pub peer_meta_store: holochain_state::peer_metadata_store::PeerMetaStore,

    /// Countersigning workspace for session state.
    pub countersigning_workspaces:
        Arc<parking_lot::Mutex<HashMap<CellId, Arc<CountersigningWorkspace>>>>,

    /// Witnessing workspace that is shared across this cell.
    pub witnessing_workspace: WitnessingWorkspace,

    /// Incoming op hashes that are queued for processing.
    pub incoming_op_hashes: IncomingOpHashes,

    /// Incoming ops batch for this space.
    pub incoming_ops_batch: IncomingOpsBatch,
}

/// Test spaces
#[cfg(test)]
pub struct TestSpaces {
    /// The spaces
    pub spaces: Spaces,
    /// The test spaces
    pub test_spaces: HashMap<DnaHash, TestSpace>,
    /// The queue consumer map
    pub queue_consumer_map: QueueConsumerMap,
}

/// A test space
#[cfg(test)]
pub struct TestSpace {
    /// The space
    pub space: Space,
    _temp_dir: tempfile::TempDir,
}

thread_local!(static DANGER_PRINT_DB_SECRETS: Cell<bool> = const { Cell::new(false) });

/// WARNING!! DANGER!! This exposes your database decryption secrets!
/// Print the database decryption secrets to stderr.
/// With these PRAGMA commands, you'll be able to run sqlcipher
/// directly to manipulate holochain databases.
pub fn set_danger_print_db_secrets(v: bool) {
    DANGER_PRINT_DB_SECRETS.set(v);
}

impl Spaces {
    /// Create a new empty set of [`DnaHash`] spaces.
    pub async fn new(
        config: Arc<ConductorConfig>,
        passphrase: SharedLockedArray,
    ) -> ConductorResult<Self> {
        // do this before any awaits
        let danger_print_db_secrets = DANGER_PRINT_DB_SECRETS.get();
        // clear the value
        DANGER_PRINT_DB_SECRETS.set(false);

        let root_db_dir: DatabasesRootPath = config
            .data_root_path
            .clone()
            .ok_or(ConductorError::NoDataRootPath)?
            .try_into()?;

        let db_key_path = root_db_dir.join("db.key");
        let db_key = match tokio::fs::read_to_string(db_key_path.clone()).await {
            Ok(locked) => DbKey::load(locked, passphrase.clone()).await?,
            Err(_) => {
                let db_key = DbKey::generate(passphrase.clone()).await?;
                tokio::fs::write(db_key_path, db_key.locked.clone()).await?;
                db_key
            }
        };

        if danger_print_db_secrets {
            eprintln!(
                "--beg-db-secrets--{}--end-db-secrets--",
                &String::from_utf8_lossy(&*db_key.key.lock().unwrap().lock())
            );
        }

        let db_sync = convert_db_sync_level(config.db_sync_level);

        let data_db_key = DbKey::load(db_key.locked.clone(), passphrase.clone())
            .await
            .map_err(ConductorError::other)?;

        let conductor_db = holochain_state::data::open_db(
            root_db_dir.as_ref(),
            holochain_state::data::Conductor,
            holochain_state::data::HolochainDataConfig {
                key: Some(data_db_key.clone()),
                sync_level: db_sync,
                max_readers: config.db_max_readers,
            },
        )
        .await
        .map_err(ConductorError::other)?;
        let conductor_store = holochain_state::conductor::ConductorStore::new(conductor_db);

        let wasm_db = holochain_state::data::open_db(
            root_db_dir.as_ref(),
            holochain_state::data::Wasm,
            holochain_state::data::HolochainDataConfig {
                key: Some(data_db_key.clone()),
                sync_level: db_sync,
                max_readers: config.db_max_readers,
            },
        )
        .await
        .map_err(ConductorError::other)?;

        // Create store instances from the wasm database
        let wasm_store = holochain_state::wasm::WasmStore::new(wasm_db.clone());
        let dna_def_store = holochain_state::dna_def::DnaDefStore::new(wasm_db.clone());
        let entry_def_store = holochain_state::entry_def::EntryDefStore::new(wasm_db);

        let space_data_config = holochain_state::data::HolochainDataConfig {
            key: Some(data_db_key.clone()),
            sync_level: db_sync,
            max_readers: config.db_max_readers,
        };

        Ok(Spaces {
            map: RwShare::new(HashMap::new()),
            db_dir: Arc::new(root_db_dir),
            config,
            queue_consumer_map: QueueConsumerMap::new(),
            conductor_store,
            wasm_store,
            dna_def_store,
            entry_def_store,
            space_data_config,
            data_db_key,
            cap_grant_backfill: Default::default(),
        })
    }

    /// Conductor startup has enabled every app: the cells are running, and the
    /// capability-grant lookup-key backfill may start on every store that is
    /// open, and on any opened from now on once its cells are running.
    pub(crate) fn conductor_cells_running(&self) {
        self.cap_grant_backfill
            .cells_running
            .store(true, std::sync::atomic::Ordering::SeqCst);
        self.start_pending_cap_grant_backfills();
    }

    /// Start the capability-grant lookup-key backfill on every open store that
    /// does not have one yet — if, and only if, the conductor's cells are
    /// running. Called when startup completes and whenever cells are created
    /// afterwards. Starts each store's backfill at most once.
    pub(crate) fn start_pending_cap_grant_backfills(&self) {
        let gate = &self.cap_grant_backfill;
        if !gate.cells_running.load(std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        #[cfg(test)]
        if CAP_GRANT_BACKFILL_TEST_MODE.load(std::sync::atomic::Ordering::SeqCst) != 0 {
            return;
        }
        let stores: Vec<(DnaHash, DhtStore)> = self.map.share_ref(|spaces| {
            spaces
                .iter()
                .map(|(dna_hash, space)| (dna_hash.clone(), space.dht_store.clone()))
                .collect()
        });
        for (dna_hash, dht_store) in stores {
            if gate.started.lock().insert(dna_hash.clone()) {
                tracing::info!(
                    %dna_hash,
                    "capability-grant lookup-key backfill: cells are running, starting"
                );
                drop(dht_store.spawn_cap_grant_lookup_backfill());
            }
        }
    }

    /// Whether the capability-grant backfill has been started for a DNA's
    /// store.
    #[cfg(test)]
    pub(crate) fn cap_grant_backfill_started(&self, dna_hash: &DnaHash) -> bool {
        self.cap_grant_backfill.started.lock().contains(dna_hash)
    }

    /// Block some target.
    pub async fn block(&self, input: Block) -> StateMutationResult<()> {
        self.conductor_store.block(input).await
    }

    /// Check if some target is blocked.
    pub async fn is_blocked(
        &self,
        target_id: BlockTargetId,
        timestamp: Timestamp,
        _holochain_p2p: DynHcP2p,
    ) -> ConductorResult<bool> {
        let cell_ids = match &target_id {
            BlockTargetId::Cell(cell_id) => vec![cell_id.to_owned()],
            // @todo
            BlockTargetId::Ip(_) => {
                vec![]
            }
        };

        // If node_agents_in_spaces is not yet initialized, we can't know anything about
        // which cells are blocked, so avoid the race condition by returning false
        // TODO: actually fix the preflight, because this could be a loophole for someone
        //       to evade a block in some circumstances
        if cell_ids.is_empty() {
            return Ok(false);
        }

        // Check if the target_id itself is directly blocked
        let target_blocked = self
            .conductor_store
            .as_read()
            .is_blocked(target_id.clone(), timestamp)
            .await
            .map_err(ConductorError::other)?;

        if target_blocked {
            return Ok(true);
        }

        // Check if any of the cell_ids are blocked
        let cell_targets: Vec<BlockTargetId> =
            cell_ids.into_iter().map(BlockTargetId::Cell).collect();

        let any_cells_blocked = self
            .conductor_store
            .as_read()
            .is_any_blocked(cell_targets, timestamp)
            .await
            .map_err(ConductorError::other)?;

        Ok(any_cells_blocked)
    }

    /// Get the holochain conductor state
    #[cfg_attr(feature = "instrument", tracing::instrument(skip_all))]
    pub async fn get_state(&self) -> ConductorResult<ConductorState> {
        timed!([1, 10, 1000], "get_state", {
            match self.conductor_store.as_read().load_state().await? {
                Some(state) => Ok(state),
                // Initialize by running an identity update — writes the default
                // state atomically on first access.
                None => self.update_state(Ok).await,
            }
        })
    }

    /// Update the internal state with a pure function mapping old state to new
    #[cfg_attr(feature = "instrument", tracing::instrument(skip_all))]
    pub async fn update_state<F>(&self, f: F) -> ConductorResult<ConductorState>
    where
        F: Send + FnOnce(ConductorState) -> ConductorResult<ConductorState> + 'static,
    {
        let (state, _) = self
            .update_state_prime(|s| Ok((f(s)?, ())), "", &InitPropertiesMap::new())
            .await?;
        Ok(state)
    }

    /// Update the internal state with a pure function mapping old state
    /// to new, and atomically persist the result alongside any `init_properties`
    /// for `app_id`. This may also produce an output value which will be the output
    /// of this function. When `init_properties` is empty the `app_id` is not used.
    ///
    /// The load, transform, and save steps run atomically inside a single
    /// database transaction on the conductor store, and concurrent callers
    /// are serialized — so no read-modify-write interleaving can silently
    /// drop updates.
    #[cfg_attr(feature = "instrument", tracing::instrument(skip_all))]
    pub async fn update_state_prime<F, O>(
        &self,
        f: F,
        app_id: &str,
        init_properties: &InitPropertiesMap,
    ) -> ConductorResult<(ConductorState, O)>
    where
        F: FnOnce(ConductorState) -> ConductorResult<(ConductorState, O)> + Send + 'static,
        O: Send + 'static,
    {
        timed!([1, 10, 1000], "update_state_prime", {
            self.conductor_store
                .update_state(
                    move |state| -> ConductorResult<_> {
                        let state = state.unwrap_or_default();
                        let (new_state, output) = f(state)?;
                        Ok((new_state.clone(), (new_state, output)))
                    },
                    app_id,
                    init_properties,
                )
                .await
        })
    }

    /// Get something from every space
    pub fn get_from_spaces<R, F: FnMut(&Space) -> R>(&self, f: F) -> Vec<R> {
        self.map
            .share_ref(|spaces| spaces.values().map(f).collect())
    }

    /// Get the space if it exists or create it if it doesn't.
    pub fn get_or_create_space(&self, dna_hash: &DnaHash) -> ConductorResult<Space> {
        self.get_or_create_space_ref(dna_hash, |s| s.clone())
    }

    /// Drop the cached space for a DNA, releasing its database handles and
    /// queue consumer triggers.
    ///
    /// Called once the last cell for a DNA has been removed and its database
    /// files deleted. Without this, a reinstall of the same DNA would reuse the
    /// cached space's connection pools, which point at the deleted files; the
    /// pool would lazily reopen them as empty, un-migrated databases (migrations
    /// only run when a database is opened). Dropping the space forces a
    /// subsequent install to open fresh, migrated databases.
    pub(crate) fn remove_space(&self, dna_hash: &DnaHash) {
        self.map.share_mut(|spaces| {
            spaces.remove(dna_hash);
        });
        // A store opened afresh for this DNA gets its own backfill.
        self.cap_grant_backfill.started.lock().remove(dna_hash);
        self.queue_consumer_map.remove_all_for_dna(dna_hash);
    }

    fn get_or_create_space_ref<F, R>(&self, dna_hash: &DnaHash, f: F) -> ConductorResult<R>
    where
        F: Fn(&Space) -> R,
    {
        match self.map.share_ref(|spaces| spaces.get(dna_hash).map(&f)) {
            Some(r) => Ok(r),
            None => self
                .map
                .share_mut(|spaces| match spaces.entry(dna_hash.clone()) {
                    hash_map::Entry::Occupied(entry) => Ok(f(entry.get())),
                    hash_map::Entry::Vacant(entry) => {
                        let space = Space::new(
                            Arc::new(dna_hash.clone()),
                            self.db_dir.to_path_buf(),
                            convert_db_sync_level(self.config.db_sync_level),
                            self.config.db_max_readers,
                            self.space_data_config.clone(),
                            Some(self.data_db_key.clone()),
                        )?;

                        if !self
                            .cap_grant_backfill
                            .cells_running
                            .load(std::sync::atomic::Ordering::SeqCst)
                        {
                            tracing::info!(
                                %dna_hash,
                                "capability-grant lookup-key backfill deferred until the \
                                 conductor's cells are running"
                            );
                        }
                        #[cfg(test)]
                        if CAP_GRANT_BACKFILL_TEST_MODE.load(std::sync::atomic::Ordering::SeqCst)
                            == 2
                        {
                            let mut config = DhtStore::test_cap_grant_backfill_config();
                            config.start_delay = std::time::Duration::ZERO;
                            drop(
                                space
                                    .dht_store
                                    .test_spawn_cap_grant_lookup_backfill_with(config),
                            );
                        }

                        let r = f(&space);
                        entry.insert(space);
                        Ok(r)
                    }
                }),
        }
    }

    /// Get the new-schema DHT store (this will create the space if it doesn't already exist).
    pub fn dht_store(&self, dna_hash: &DnaHash) -> ConductorResult<DhtStore> {
        self.get_or_create_space_ref(dna_hash, |space| space.dht_store.clone())
    }

    /// Get the peer meta store for a DNA space.
    pub fn peer_meta_store(
        &self,
        dna_hash: &DnaHash,
    ) -> ConductorResult<holochain_state::peer_metadata_store::PeerMetaStore> {
        self.get_or_create_space_ref(dna_hash, |space| space.peer_meta_store.clone())
    }

    /// Handle a "publish" event received from the network, passing the ops
    /// straight through to the incoming ops workflow.
    #[cfg_attr(feature = "instrument", tracing::instrument(skip(self, ops)))]
    pub async fn handle_publish(
        &self,
        dna_hash: &DnaHash,
        ops: Vec<(DhtOp, bool)>,
    ) -> ConductorResult<()> {
        let space = self.get_or_create_space(dna_hash)?;
        let trigger = match self
            .queue_consumer_map
            .sys_validation_trigger(space.dna_hash.clone())
        {
            Some(t) => t,
            // If the workflow has not been spawned yet we can't handle incoming messages.
            // Note this is not an error because only a validation receipt is proof of a publish.
            None => {
                tracing::warn!("No sys validation trigger yet for space: {}", dna_hash);
                return Ok(());
            }
        };

        incoming_dht_ops_workflow(space, trigger, ops).await?;

        Ok(())
    }

    /// Receive a publish countersign event from the network.
    #[cfg_attr(feature = "instrument", tracing::instrument(skip(self, ops)))]
    pub async fn handle_publish_countersign(
        &self,
        dna_hash: &DnaHash,
        op: ChainOp,
    ) -> ConductorResult<()> {
        let hash = DhtOpHash::with_data_sync(&op);

        let (workspace, trigger) = self.get_or_create_space_ref(dna_hash, |space| {
            (
                space.witnessing_workspace.clone(),
                self.queue_consumer_map
                    .witnessing_trigger(space.dna_hash.clone()),
            )
        })?;

        let trigger = match trigger {
            Some(t) => t,
            // If the workflow has not been spawned yet, we can't handle incoming messages.
            None => {
                tracing::warn!("No witnessing trigger yet for space: {}", dna_hash);
                return Ok(());
            }
        };

        receive_incoming_countersigning_ops(vec![(hash, op)], &workspace, trigger)?;

        Ok(())
    }
}

/// ELOHIM PATCH (fleet CPU storm, H3): how often each DHT database's WAL is
/// checkpointed explicitly (see `holochain_data::wal`).
const DHT_WAL_MAINTENANCE_PERIOD: std::time::Duration = std::time::Duration::from_secs(60);

/// Run a bounded WAL maintenance pass on a DHT database every
/// [`DHT_WAL_MAINTENANCE_PERIOD`] until its pool is closed. A pass is a
/// passive checkpoint plus, only while the log stays above
/// `WAL_TRUNCATE_ABOVE_FRAMES`, a truncating checkpoint whose wait for
/// readers is capped at `WAL_TRUNCATE_MAX_WAIT`. A truncation held off by a
/// reader is logged, so a pinned WAL is visible instead of silent.
fn spawn_dht_wal_maintenance(db: holochain_state::data::DbWrite<holochain_state::data::Dht>) {
    use holochain_state::data::wal::{WAL_TRUNCATE_ABOVE_FRAMES, WAL_TRUNCATE_MAX_WAIT};
    use holochain_state::data::DatabaseIdentifier;
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(DHT_WAL_MAINTENANCE_PERIOD);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // The first tick completes immediately; the store was just opened.
        tick.tick().await;
        loop {
            tick.tick().await;
            if db.pool().is_closed() {
                break;
            }
            match db
                .wal_maintenance_pass(WAL_TRUNCATE_ABOVE_FRAMES, WAL_TRUNCATE_MAX_WAIT)
                .await
            {
                Ok(outcome) => match outcome.truncate {
                    Some(t) if t.busy => tracing::info!(
                        db = db.identifier().database_id(),
                        log_frames = t.log_frames,
                        checkpointed_frames = t.checkpointed_frames,
                        "WAL truncation held off by an active reader; retrying next period"
                    ),
                    _ => tracing::debug!(
                        db = db.identifier().database_id(),
                        ?outcome,
                        "WAL maintenance pass"
                    ),
                },
                Err(e) => tracing::warn!(
                    db = db.identifier().database_id(),
                    ?e,
                    "WAL maintenance pass failed"
                ),
            }
        }
    });
}

impl Space {
    fn new(
        dna_hash: Arc<DnaHash>,
        root_db_dir: PathBuf,
        data_db_sync_level: DbSyncLevel,
        db_max_readers: u16,
        space_data_config: holochain_state::data::HolochainDataConfig,
        data_db_key: Option<holochain_state::data::DbKey>,
    ) -> ConductorResult<Self> {
        tokio::task::block_in_place(|| {
            let peer_meta_store_db = tokio::runtime::Handle::current()
                .block_on(holochain_state::data::open_db(
                    &root_db_dir,
                    holochain_state::data::PeerMetaStore::new(dna_hash.clone()),
                    holochain_state::data::HolochainDataConfig {
                        key: data_db_key,
                        sync_level: data_db_sync_level,
                        max_readers: db_max_readers,
                    },
                ))
                .map_err(ConductorError::other)?;
            let peer_meta_store =
                holochain_state::peer_metadata_store::PeerMetaStore::new(peer_meta_store_db);
            let new_dht_db = tokio::runtime::Handle::current()
                .block_on(holochain_state::data::open_db(
                    &root_db_dir,
                    holochain_state::data::Dht::new(dna_hash.clone()),
                    space_data_config,
                ))
                .map_err(ConductorError::other)?;
            spawn_dht_wal_maintenance(new_dht_db.clone());
            // ELOHIM PATCH (per-call grant walk): the capability-grant
            // lookup-key backfill is NOT started here. Opening a store is part
            // of starting its cells; see `CapGrantBackfillGate`.
            let dht_store = DhtStore::new(new_dht_db);

            Ok(Self {
                dna_hash,
                dht_store,
                peer_meta_store,
                countersigning_workspaces: Default::default(),
                witnessing_workspace: WitnessingWorkspace::default(),
                incoming_op_hashes: IncomingOpHashes::default(),
                incoming_ops_batch: IncomingOpsBatch::default(),
            })
        })
    }

    /// Construct a SourceChain for an author in this Space
    pub async fn source_chain(
        &self,
        keystore: MetaLairClient,
        author: AgentPubKey,
    ) -> SourceChainResult<SourceChain> {
        SourceChain::raw_empty(self.dht_store.clone(), keystore, author).await
    }

    /// Create a SourceChainWorkspace from this Space
    pub async fn source_chain_workspace(
        &self,
        keystore: MetaLairClient,
        author: AgentPubKey,
    ) -> ConductorResult<SourceChainWorkspace> {
        Ok(SourceChainWorkspace::new(self.dht_store.clone(), keystore, author).await?)
    }
}

#[cfg(test)]
impl TestSpaces {
    /// Create a new test space
    pub async fn new(dna_hashes: impl IntoIterator<Item = DnaHash>) -> Self {
        let queue_consumer_map = QueueConsumerMap::new();
        Self::with_queue_consumer(dna_hashes, queue_consumer_map).await
    }

    /// Create a new test space with a queue consumer
    pub async fn with_queue_consumer(
        dna_hashes: impl IntoIterator<Item = DnaHash>,
        queue_consumer_map: QueueConsumerMap,
    ) -> Self {
        let mut test_spaces: HashMap<DnaHash, _> = HashMap::new();
        for hash in dna_hashes.into_iter() {
            test_spaces.insert(hash.clone(), TestSpace::new(hash));
        }
        let temp_dir = tempfile::Builder::new()
            .prefix("holochain-test-environments")
            .tempdir()
            .unwrap();
        let spaces = Spaces::new(
            ConductorConfig {
                data_root_path: Some(temp_dir.path().to_path_buf().into()),
                ..Default::default()
            }
            .into(),
            Arc::new(std::sync::Mutex::new(sodoken::LockedArray::from(
                b"passphrase".to_vec(),
            ))),
        )
        .await
        .unwrap();
        spaces.map.share_mut(|map| {
            map.extend(
                test_spaces
                    .iter()
                    .map(|(k, v)| (k.clone(), v.space.clone())),
            );
        });
        Self {
            queue_consumer_map,
            spaces,
            test_spaces,
        }
    }
}

fn convert_db_sync_level(
    level: holochain_conductor_api::config::conductor::DbSyncLevel,
) -> DbSyncLevel {
    match level {
        holochain_conductor_api::config::conductor::DbSyncLevel::Off => DbSyncLevel::Off,
        holochain_conductor_api::config::conductor::DbSyncLevel::Normal => DbSyncLevel::Normal,
        holochain_conductor_api::config::conductor::DbSyncLevel::Full => DbSyncLevel::Full,
    }
}

#[cfg(test)]
impl TestSpace {
    /// Create a new test space
    pub fn new(dna_hash: DnaHash) -> Self {
        let temp_dir = tempfile::Builder::new()
            .prefix("holochain-test-environments")
            .tempdir()
            .unwrap();

        let test_space_data_config = holochain_state::data::HolochainDataConfig::default();
        Self {
            space: Space::new(
                Arc::new(dna_hash),
                temp_dir.path().to_path_buf(),
                Default::default(),
                ConductorConfig::default().db_max_readers,
                test_space_data_config,
                None,
            )
            .unwrap(),
            _temp_dir: temp_dir,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use holochain_conductor_api::conductor::ConductorConfig;
    use holochain_types::prelude::DnaHash;

    #[tokio::test(flavor = "multi_thread")]
    async fn db_max_readers_applied_to_pools() {
        let custom_max_readers = 24;

        let temp_dir = tempfile::Builder::new().tempdir().unwrap();

        let config_with_path = ConductorConfig {
            data_root_path: Some(temp_dir.path().to_path_buf().into()),
            db_max_readers: custom_max_readers,
            ..Default::default()
        };

        let spaces = Spaces::new(
            Arc::new(config_with_path),
            Arc::new(std::sync::Mutex::new(sodoken::LockedArray::from(
                b"passphrase".to_vec(),
            ))),
        )
        .await
        .unwrap();

        let dna_hash = DnaHash::from_raw_36(vec![0; 36]);
        let space = spaces.get_or_create_space(&dna_hash).unwrap();

        // db_max_readers is applied to the DhtStore's connection pool.
        assert_eq!(
            space.dht_store.connection_pool_max_size(),
            custom_max_readers as u32 + 1
        );
    }

    /// The capability-grant lookup-key backfill is held back until the
    /// conductor's cells are running.
    ///
    /// Opening a store does not start it, and neither does creating cells
    /// while the conductor is still starting: an un-keyed grant in the file
    /// stays un-keyed for well past the backfill's own start delay. The
    /// "cells are running" signal starts it, once per store. A store opened
    /// after that waits for its own cells.
    #[tokio::test(flavor = "multi_thread")]
    async fn cap_grant_backfill_waits_for_the_cells_running_signal() {
        let temp_dir = tempfile::Builder::new().tempdir().unwrap();
        let spaces = Spaces::new(
            Arc::new(ConductorConfig {
                data_root_path: Some(temp_dir.path().to_path_buf().into()),
                ..Default::default()
            }),
            Arc::new(std::sync::Mutex::new(sodoken::LockedArray::from(
                b"passphrase".to_vec(),
            ))),
        )
        .await
        .unwrap();

        // A store opened during startup, holding grants no one has keyed.
        let dna_hash = DnaHash::from_raw_36(vec![3; 36]);
        let space = spaces.get_or_create_space(&dna_hash).unwrap();
        space
            .dht_store
            .test_insert_unkeyed_cap_grants(&AgentPubKey::from_raw_36(vec![9; 36]), 2)
            .await
            .unwrap();
        assert_eq!(space.dht_store.count_cap_grants_unkeyed().await.unwrap(), 2);

        // Deferred: opening it did not start the backfill, and cells created
        // while the conductor is starting do not either.
        assert!(!spaces.cap_grant_backfill_started(&dna_hash));
        spaces.start_pending_cap_grant_backfills();
        assert!(!spaces.cap_grant_backfill_started(&dna_hash));
        let start_delay = DhtStore::test_cap_grant_backfill_config().start_delay;
        tokio::time::sleep(start_delay + std::time::Duration::from_millis(1500)).await;
        assert_eq!(
            space.dht_store.count_cap_grants_unkeyed().await.unwrap(),
            2,
            "the backfill ran before the conductor's cells were running"
        );

        // The signal starts it.
        spaces.conductor_cells_running();
        assert!(spaces.cap_grant_backfill_started(&dna_hash));
        let deadline = std::time::Instant::now() + start_delay + std::time::Duration::from_secs(30);
        while space.dht_store.count_cap_grants_unkeyed().await.unwrap() != 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "the cells were running but the un-keyed grants were never keyed"
            );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }

        // A store opened after startup waits for its own cells to be created.
        let later = DnaHash::from_raw_36(vec![4; 36]);
        spaces.get_or_create_space(&later).unwrap();
        assert!(!spaces.cap_grant_backfill_started(&later));
        spaces.start_pending_cap_grant_backfills();
        assert!(spaces.cap_grant_backfill_started(&later));

        // A store that is dropped and reopened gets a backfill of its own.
        spaces.remove_space(&later);
        assert!(!spaces.cap_grant_backfill_started(&later));
    }
}
