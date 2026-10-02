use crate::conductor::space::TestSpaces;
use crate::conductor::Conductor;
use crate::core::ribosome::real_ribosome::{
    module_cache::make_module_cache, RealRibosome, WasmBackend,
};
use crate::core::ribosome::Ribosome;
use crate::sweettest::SweetConductorConfig;
use crate::test_utils::fake_valid_dna_file;
use holo_hash::HasHash;
use holochain_conductor_api::conductor::paths::DataRootPath;
use holochain_keystore::SignedActionHashedExt;
use holochain_p2p::actor::MockHcP2p;
use holochain_p2p::HolochainP2pDna;
use holochain_state::prelude::*;
use holochain_trace::test_run;
use holochain_types::cell_config_overrides::CellConfigOverrides;
use std::sync::Arc;
use tokio::sync::broadcast;

#[tokio::test(flavor = "multi_thread")]
async fn test_cell_handle_publish() {
    test_run();
    let keystore = holochain_keystore::test_keystore();

    let agent_key = keystore.new_sign_keypair_random().await.unwrap();
    let dna_file = fake_valid_dna_file("test_cell_handle_publish");
    let cell_id = CellId::new(dna_file.dna_hash().clone(), agent_key);
    let dna = cell_id.dna_hash().clone();
    let agent = cell_id.agent_pubkey().clone();

    let spaces = TestSpaces::new([dna.clone()]).await;

    let holochain_p2p_cell = HolochainP2pDna::new(Arc::new(MockHcP2p::new()), dna.clone());

    let db_dir = test_db_dir().path().to_path_buf();
    let data_root_path: DataRootPath = db_dir.clone().into();
    let config = SweetConductorConfig::standard().tune_network_config(|nc| {
        nc.disable_bootstrap = true;
    });
    let handle = Conductor::builder()
        .config(config.into())
        .with_keystore(keystore.clone())
        .with_data_root_path(data_root_path.clone())
        .test()
        .await
        .unwrap();
    handle
        .register_dna_file(cell_id.clone(), dna_file.clone())
        .await
        .unwrap();
    let backend = WasmBackend::new();

    let store: WasmStore = WasmStore::test_new();
    let wasmer_module_cache = make_module_cache(backend, store.clone());

    for (hash, wasm) in dna_file.code().clone() {
        store
            .put(DnaWasmHashed::with_pre_hashed(wasm, hash))
            .await
            .unwrap();
    }

    let ribosome = RealRibosome::new(
        backend,
        dna_file.dna_def_hashed().clone(),
        Arc::new(wasmer_module_cache),
    )
    .await
    .unwrap();
    let ribosome = Ribosome::new(dna_file.dna_def_hashed().clone(), ribosome)
        .await
        .unwrap();

    let dht_store = spaces.test_spaces[&dna].space.dht_store.clone();
    super::Cell::genesis(cell_id.clone(), handle.clone(), dht_store, ribosome, None)
        .await
        .unwrap();

    let (_cell, _) = super::Cell::create(
        cell_id,
        handle.clone(),
        spaces.test_spaces[&dna].space.clone(),
        holochain_p2p_cell,
        broadcast::channel(10).0,
        CellConfigOverrides::default(),
    )
    .await
    .unwrap();

    let action = Action {
        header: ActionHeader {
            author: agent.clone(),
            timestamp: Timestamp::now(),
            action_seq: 0,
            prev_action: None,
        },
        data: ActionData::Dna(DnaData {
            dna_hash: dna.clone(),
        }),
    };
    let shh = SignedActionHashed::sign(
        &keystore,
        holo_hash::HoloHashed::from_content_sync(action.clone()),
    )
    .await
    .unwrap();
    let op = DhtOp::ChainOp(Box::new(ChainOp::CreateRecord(
        SignedAction::new(action, shh.signature().clone()),
        OpEntry::ActionOnly,
    )));
    let op_hash = DhtOpHashed::from_content_sync(op.clone()).into_hash();

    spaces
        .spaces
        .handle_publish(&dna, vec![(op, true)])
        .await
        .unwrap();

    // Reading the DhtStore limbo for the published op must not error.
    spaces.test_spaces[&dna]
        .space
        .dht_store
        .as_read()
        .limbo_op_exists(&op_hash)
        .await
        .unwrap();

    handle.shutdown().await.unwrap().unwrap();
}

/// Once a cell has seen its zomes initialised, the init check neither reads
/// the chain again nor waits on the init mutex.
#[tokio::test(flavor = "multi_thread")]
async fn initialised_cell_skips_the_init_check() {
    use crate::sweettest::{SweetConductor, SweetDnaFile};
    use holochain_wasm_test_utils::TestWasm;
    use std::sync::atomic::Ordering;

    let (dna, _, _) = SweetDnaFile::unique_from_test_wasms(vec![TestWasm::InitPass]).await;
    let mut conductor = SweetConductor::standard().await;
    let app = conductor.setup_app("app", [&dna]).await.unwrap();
    let cell_id = app.cells()[0].cell_id().clone();
    let cell = conductor.raw_handle().cell_by_id(&cell_id).await.unwrap();

    assert!(!cell.zomes_initialized.load(Ordering::Acquire));
    cell.check_or_run_zome_init().await.unwrap();
    assert!(cell.zomes_initialized.load(Ordering::Acquire));

    // Hold the init mutex. Without the latch the next check would wait on it
    // until INIT_MUTEX_TIMEOUT_SECS and fail with InitTimeout.
    let _held = cell.init_mutex.lock().await;
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        cell.check_or_run_zome_init(),
    )
    .await
    .expect("an initialised cell must not wait on the init mutex")
    .unwrap();
}

/// A failed init leaves the latch open, so the next call runs init again
/// instead of treating the cell as initialised.
#[tokio::test(flavor = "multi_thread")]
async fn failed_init_leaves_the_latch_open() {
    use crate::sweettest::{SweetConductor, SweetDnaFile};
    use holochain_wasm_test_utils::TestWasm;
    use std::sync::atomic::Ordering;

    let (dna, _, _) = SweetDnaFile::unique_from_test_wasms(vec![TestWasm::InitFail]).await;
    let mut conductor = SweetConductor::standard().await;
    let app = conductor.setup_app("app", [&dna]).await.unwrap();
    let cell_id = app.cells()[0].cell_id().clone();
    let cell = conductor.raw_handle().cell_by_id(&cell_id).await.unwrap();

    assert!(cell.check_or_run_zome_init().await.is_err());
    assert!(!cell.zomes_initialized.load(Ordering::Acquire));
    assert!(cell.check_or_run_zome_init().await.is_err());
    assert!(!cell.zomes_initialized.load(Ordering::Acquire));
}
