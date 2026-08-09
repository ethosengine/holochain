//! Wave-2 Stage-0 mechanism proof — transport-iroh conductors against the
//! sovereign relay at `https://relay.elohim.host`.
//!
//! Design: `genesis/docs/content/elohim-protocol/architecture/2026-08-05-wave2-relay-sovereignty-design.md`
//! §5.2 "Stage 0 — mechanism proof, off the live DHT" and §8 U5.
//!
//! What this proves (and does NOT touch):
//!   * Bootstrap is the in-process `kitsune2_bootstrap_srv` from
//!     `SweetLocalRendezvous` — a private bootstrap space. Alpha's bootstrap is
//!     never contacted.
//!   * The DNA is a unique inline-zome DNA (random network seed), so the DHT
//!     space is unique to this test run. Alpha's DNA space is never joined.
//!   * The ONLY live endpoint touched is the relay (an open relay; the
//!     conductors register and forward their own encrypted QUIC bytes).
//!
//! Run with:
//!   cargo test --locked -p holochain --test iroh_stage0 \
//!     --features test_utils -- --nocapture
//!
//! (the `holochain` crate's default feature set already selects
//! `transport-iroh`; `transport-tx5-backend-go-pion` must stay absent —
//! kitsune2 0.4.1 picks tx5 whenever it is compiled.)

use std::sync::Arc;

use hdk::prelude::{Entry, EntryDef, EntryDefIndex, EntryVisibility, Record};
use holo_hash::ActionHash;
use holochain::sweettest::{
    await_consistency_s, DynSweetRendezvous, SweetConductor, SweetConductorBatch,
    SweetConductorConfig, SweetDnaFile, SweetInlineZomes, SweetLocalRendezvous, SweetRendezvous,
};
use holochain_types::inline_zome::InlineZomeSet;
use holochain_zome_types::action::ChainTopOrdering;
use holochain_zome_types::entry::{CreateInput, GetInput};
use holochain_zome_types::prelude::GetOptions;

/// The sovereign relay under test. Override with `ELOHIM_RELAY_URL` if a
/// different relay (e.g. `https://relay.alpha.elohim.host`) is being probed.
const DEFAULT_RELAY_URL: &str = "https://relay.elohim.host";

/// A rendezvous that keeps the local bootstrap server but points the iroh
/// transport at OUR relay instead of the in-process test relay.
///
/// `SweetConductorConfig::apply_rendezvous` only substitutes fields whose value
/// is the literal `rendezvous:`, and it reads the relay from
/// `SweetRendezvous::relay_addr()` — so overriding that one method is the whole
/// mechanism. The inner `SweetLocalRendezvous` still spawns its own local relay;
/// it is deliberately left unused so that a failure to reach our relay shows up
/// as a failure rather than silently falling back to localhost.
struct ElohimRelayRendezvous {
    inner: Arc<SweetLocalRendezvous>,
    relay: String,
}

impl SweetRendezvous for ElohimRelayRendezvous {
    fn bootstrap_addr(&self) -> &str {
        self.inner.bootstrap_addr()
    }

    fn sig_addr(&self) -> &str {
        self.inner.sig_addr()
    }

    fn relay_addr(&self) -> &str {
        self.relay.as_str()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn stage0_two_conductors_against_sovereign_relay() {
    holochain_trace::test_run();

    let relay_url =
        std::env::var("ELOHIM_RELAY_URL").unwrap_or_else(|_| DEFAULT_RELAY_URL.to_string());
    // Host without scheme — used for the peer-URL shape assertion.
    let relay_host = relay_url
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/')
        .to_string();

    println!("STAGE0 relay_url={relay_url}");

    // --- Criterion 1: transport stack ------------------------------------
    // Compile-time proof that we are NOT on tx5. If `transport-iroh` is absent
    // or a tx5 backend feature is present, this test refuses to run rather than
    // silently proving the wrong thing.
    #[cfg(not(feature = "transport-iroh"))]
    compile_error!("iroh_stage0 requires the `transport-iroh` feature");
    #[cfg(feature = "transport-tx5-backend-go-pion")]
    compile_error!(
        "iroh_stage0 requires `transport-tx5-backend-go-pion` to be ABSENT — \
         kitsune2 0.4.1 selects tx5 whenever it is compiled"
    );
    println!("STAGE0 transport=iroh (transport-iroh on, tx5 backend absent)");

    // --- A trivial create/get DNA (inline zomes: no wasm build needed) ----
    let entry_def = EntryDef::default_from_id("entry");
    let zomes = SweetInlineZomes::new(vec![entry_def], 0)
        .function("create", move |api, _: ()| {
            let entry = Entry::app(().try_into().unwrap()).unwrap();
            let hash = api.create(CreateInput::new(
                InlineZomeSet::get_entry_location(&api, EntryDefIndex(0)),
                EntryVisibility::Public,
                entry,
                ChainTopOrdering::default(),
            ))?;
            Ok(hash)
        })
        .function("get", move |api, hash: ActionHash| {
            let records = api.get(vec![GetInput::new(hash.into(), GetOptions::network())])?;
            Ok(records)
        })
        .0;

    // Unique network seed => a DHT space that exists only for this test run.
    let (dna, _, _) = SweetDnaFile::unique_from_inline_zomes(zomes).await;
    println!("STAGE0 dna_hash={}", dna.dna_hash());

    // --- Two conductors, local bootstrap, OUR relay ----------------------
    let inner = SweetLocalRendezvous::new_raw().await;
    let rendezvous: DynSweetRendezvous = Arc::new(ElohimRelayRendezvous {
        inner,
        relay: relay_url.clone(),
    });
    println!(
        "STAGE0 bootstrap_addr={} (local, private space)",
        rendezvous.bootstrap_addr()
    );

    let config = SweetConductorConfig::rendezvous(true);
    let c0 = SweetConductor::from_config_rendezvous(config.clone(), rendezvous.clone()).await;
    let c1 = SweetConductor::from_config_rendezvous(config.clone(), rendezvous.clone()).await;

    // Confirm the config the conductors actually booted with.
    for (i, c) in [&c0, &c1].into_iter().enumerate() {
        let cfg = c.raw_handle();
        let net = &cfg.config.network;
        println!(
            "STAGE0 conductor{i} relay_url={} bootstrap_url={} signal_url={}",
            net.relay_url, net.bootstrap_url, net.signal_url
        );
        assert_eq!(
            net.relay_url.as_str().trim_end_matches('/'),
            relay_url.trim_end_matches('/'),
            "conductor {i} did not take the sovereign relay URL"
        );
    }

    let mut conductors = SweetConductorBatch::new(vec![c0, c1]);

    // App install waits (under transport-iroh) for the agent info to reach the
    // peer store, which cannot happen until the home relay hands out a URL.
    let apps = conductors.setup_app("stage0", [&dna]).await.unwrap();
    let ((alice,), (bob,)) = apps.into_tuples();

    // --- Criterion 3: peer URL shape -------------------------------------
    let mut seen_urls: Vec<String> = Vec::new();
    for (i, c) in conductors.iter().enumerate() {
        let infos = c.raw_handle().get_agent_infos(None).await.unwrap();
        for info in infos {
            let url = info
                .url
                .as_ref()
                .map(|u| u.to_string())
                .unwrap_or_else(|| "<none>".to_string());
            println!(
                "STAGE0-PEER-URL conductor{i} agent={} url={url}",
                info.agent
            );
            seen_urls.push(url);
        }
    }

    assert!(
        !seen_urls.is_empty(),
        "no agent infos in any peer store — nothing registered"
    );
    for url in &seen_urls {
        assert!(
            !url.contains("relay.iroh.network"),
            "n0 contamination — peer URL points at a public n0 relay: {url}"
        );
        assert!(
            !url.starts_with("wss://"),
            "tx5-shaped peer URL (wss://) — the transport did not flip: {url}"
        );
        // NOTE (Stage-0 finding): iroh's `RelayUrl` normalizes the host to a
        // fully-qualified DNS name, so the canonical peer URL carries a
        // TRAILING DOT on the host — `https://relay.elohim.host.:443/{id}`,
        // not `https://relay.elohim.host:443/{id}`. Any n0-contamination probe
        // that compares the agent-info host for equality must normalize this,
        // or it reports a false negative on a correctly-homed conductor.
        assert!(
            url.starts_with(&format!("https://{relay_host}:443/"))
                || url.starts_with(&format!("https://{relay_host}.:443/")),
            "peer URL is not https://{relay_host}[.]:443/{{endpoint_id}}: {url}"
        );
    }
    println!(
        "STAGE0 peer-url-shape OK ({} urls, all https://{relay_host}:443/*)",
        seen_urls.len()
    );

    // --- Criterion 4: two peers exchange ops ------------------------------
    let alice_zome = alice.zome(SweetInlineZomes::COORDINATOR);
    let hash: ActionHash = conductors[0].call(&alice_zome, "create", ()).await;
    println!("STAGE0 alice created action={hash}");

    await_consistency_s(120u64, [&alice, &bob])
        .await
        .expect("ops did not converge between the two conductors");
    println!("STAGE0 consistency reached");

    let bob_zome = bob.zome(SweetInlineZomes::COORDINATOR);
    let records: Vec<Option<Record>> = conductors[1].call(&bob_zome, "get", hash.clone()).await;
    assert!(
        records.iter().any(|r| r.is_some()),
        "bob could not get alice's record over the iroh transport"
    );
    println!("STAGE0 bob read alice's record — ops exchanged over iroh/relay.elohim.host");
    println!("STAGE0 PASS");
}

/// Doorway-A relay, the OTHER half of the Wave-2 per-doorway relay split.
/// Override with `ELOHIM_RELAY_URL_A`.
const DEFAULT_RELAY_URL_A: &str = "https://relay.alpha.elohim.host";

/// Stage-0b — the CROSS-RELAY mechanism proof.
///
/// Wave-2 relay sovereignty (design doc D2) homes each conductor to its own
/// doorway's relay: doorway A -> `relay.alpha.elohim.host`, doorway B ->
/// `relay.elohim.host`. D2's rationale states that peers need not share a
/// relay, because a peer URL embeds *that peer's* home relay and the dialing
/// side connects through the other peer's relay.
///
/// `stage0_two_conductors_against_sovereign_relay` above cannot test that
/// claim: it homes BOTH conductors to the SAME relay. This test homes them to
/// DIFFERENT relays — the actual alpha topology — while sharing one local
/// bootstrap server, so the only variable is the relay split.
///
/// Regression guard for the 2026-08-09 seam: `kitsune2_transport_iroh`'s
/// `IrohTransport::own_url_for_preflight` failed CLOSED whenever a peer homed
/// to a relay the local node did not home to, so every doorway-B -> doorway-A
/// initiation died. It surfaced as `Connection attempted before home relay URL
/// is known` — an error naming a DIFFERENT condition (no local URL at all) on
/// conductors whose home relay was confirmed and whose per-space relays had
/// all been inserted. Fixed by the vendored `patches/kitsune2_transport_iroh`
/// [patch.crates-io] entry; see its ELOHIM PATCH note.
///
/// Run with:
///   cargo test --locked -p holochain --test iroh_stage0 \
///     --features test_utils -- --nocapture stage0b
///
/// Requires BOTH relays reachable from the runner.
#[tokio::test(flavor = "multi_thread")]
async fn stage0b_cross_relay_two_doorway_relays() {
    holochain_trace::test_run();

    let relay_b =
        std::env::var("ELOHIM_RELAY_URL").unwrap_or_else(|_| DEFAULT_RELAY_URL.to_string());
    let relay_a =
        std::env::var("ELOHIM_RELAY_URL_A").unwrap_or_else(|_| DEFAULT_RELAY_URL_A.to_string());
    assert_ne!(
        relay_a.trim_end_matches('/'),
        relay_b.trim_end_matches('/'),
        "stage0b is meaningless unless the two conductors home to DIFFERENT \
         relays — that split IS the thing under test"
    );
    println!("STAGE0b relay_a={relay_a} relay_b={relay_b}");

    #[cfg(not(feature = "transport-iroh"))]
    compile_error!("iroh_stage0 requires the `transport-iroh` feature");
    #[cfg(feature = "transport-tx5-backend-go-pion")]
    compile_error!(
        "iroh_stage0 requires `transport-tx5-backend-go-pion` to be ABSENT — \
         kitsune2 0.4.1 selects tx5 whenever it is compiled"
    );

    let entry_def = EntryDef::default_from_id("entry");
    let zomes = SweetInlineZomes::new(vec![entry_def], 0)
        .function("create", move |api, _: ()| {
            let entry = Entry::app(().try_into().unwrap()).unwrap();
            let hash = api.create(CreateInput::new(
                InlineZomeSet::get_entry_location(&api, EntryDefIndex(0)),
                EntryVisibility::Public,
                entry,
                ChainTopOrdering::default(),
            ))?;
            Ok(hash)
        })
        .function("get", move |api, hash: ActionHash| {
            let records = api.get(vec![GetInput::new(hash.into(), GetOptions::network())])?;
            Ok(records)
        })
        .0;

    let (dna, _, _) = SweetDnaFile::unique_from_inline_zomes(zomes).await;
    println!("STAGE0b dna_hash={}", dna.dna_hash());

    // ONE bootstrap server, TWO relay homes. Sharing `inner` is what keeps the
    // peers discoverable while splitting their transport home — exactly how
    // alpha's two doorways share one bootstrap namespace.
    let inner = SweetLocalRendezvous::new_raw().await;
    let rendezvous_b: DynSweetRendezvous = Arc::new(ElohimRelayRendezvous {
        inner: inner.clone(),
        relay: relay_b.clone(),
    });
    let rendezvous_a: DynSweetRendezvous = Arc::new(ElohimRelayRendezvous {
        inner,
        relay: relay_a.clone(),
    });
    println!(
        "STAGE0b bootstrap_addr={} (shared, local, private space)",
        rendezvous_b.bootstrap_addr()
    );

    let config = SweetConductorConfig::rendezvous(true);
    let c_b = SweetConductor::from_config_rendezvous(config.clone(), rendezvous_b).await;
    let c_a = SweetConductor::from_config_rendezvous(config.clone(), rendezvous_a).await;

    for (label, c, expected) in [("B", &c_b, &relay_b), ("A", &c_a, &relay_a)] {
        let net = &c.raw_handle().config.network;
        println!("STAGE0b conductor{label} relay_url={}", net.relay_url);
        assert_eq!(
            net.relay_url.as_str().trim_end_matches('/'),
            expected.trim_end_matches('/'),
            "conductor {label} did not take its doorway's relay URL"
        );
    }

    let mut conductors = SweetConductorBatch::new(vec![c_b, c_a]);
    let apps = conductors.setup_app("stage0b", [&dna]).await.unwrap();
    let ((bob,), (alice,)) = apps.into_tuples();

    // Peer URLs must show BOTH relay hosts — proof the split is real and not
    // collapsed by some shared default.
    let mut hosts = std::collections::BTreeSet::new();
    for c in conductors.iter() {
        for info in c.raw_handle().get_agent_infos(None).await.unwrap() {
            if let Some(url) = info.url.as_ref() {
                let u = url.to_string();
                println!("STAGE0b-PEER-URL {u}");
                if let Some(rest) = u.strip_prefix("https://") {
                    hosts.insert(
                        rest.split('/')
                            .next()
                            .unwrap_or_default()
                            .trim_end_matches(":443")
                            // iroh's RelayUrl canonicalizes to an FQDN, so the
                            // host carries a trailing root-label dot.
                            .trim_end_matches('.')
                            .to_string(),
                    );
                }
            }
        }
    }
    println!("STAGE0b distinct relay hosts in peer store: {hosts:?}");
    assert!(
        hosts.len() >= 2,
        "expected peer URLs on BOTH relays, saw {hosts:?} — the cross-relay \
         condition never materialised, so a PASS here would prove nothing"
    );

    // The assertion the defect broke: ops cross the relay split.
    let alice_zome = alice.zome(SweetInlineZomes::COORDINATOR);
    let hash: ActionHash = conductors[1].call(&alice_zome, "create", ()).await;
    println!("STAGE0b alice (doorway A) created action={hash}");

    await_consistency_s(120u64, [&alice, &bob]).await.expect(
        "ops did not converge ACROSS the per-doorway relay split — this is \
             the own_url_for_preflight fail-closed seam if the logs carry \
             'Connection attempted before home relay URL is known' on a \
             conductor whose home relay was confirmed",
    );

    let bob_zome = bob.zome(SweetInlineZomes::COORDINATOR);
    let records: Vec<Option<Record>> = conductors[0].call(&bob_zome, "get", hash.clone()).await;
    assert!(
        records.iter().any(|r| r.is_some()),
        "bob (doorway B) could not get alice's (doorway A) record across the \
         relay split"
    );
    println!("STAGE0b PASS — ops crossed relay_a <-> relay_b");
}
