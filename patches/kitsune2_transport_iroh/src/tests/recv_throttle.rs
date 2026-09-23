//! Reader-level tests for the ELOHIM receive throttle (2026-09-13).
//!
//! These drive a real [`ConnectionContext`] reader over a scripted stream of
//! frames and assert the two properties the publish-storm cure depends on:
//!
//! 1. A module handler that refuses a frame (a full inbound queue) does not
//!    cost the connection — the reader keeps reading and no close is issued.
//! 2. After a refusal, further frames for that module are dropped *before*
//!    the handler is invoked, while frames for every other module continue
//!    to be delivered.
//!
//! The pure throttle logic (cooldown windows, log rate limiting, protobuf
//! peeking) is unit-tested in [`crate::recv_throttle`].

use super::support::CloseCalls;
use crate::close_code::CloseCode;
use crate::connection::{Connection, DynConnection};
use crate::connection_context::{ConnectionContext, ConnectionContextParams};
use crate::frame::{Frame, encode_frame};
use crate::recv_throttle::{PUBLISH_MOD_NAME, RecvThrottleConfig};
use crate::stream::{DynIrohRecvStream, DynIrohSendStream};
use crate::test_utils::MockTxHandler;
use crate::url::endpoint_from_url;
use bytes::Bytes;
use iroh::EndpointId;
use kitsune2_api::{
    BoxFut, DefaultTransport, DynTxModuleHandler, K2Error, K2Proto, K2Result,
    K2WireType, TransportStats, TxImp, TxImpHnd, Url,
};
use kitsune2_test_utils::retry_fn_until_timeout;
use kitsune2_test_utils::space::TEST_SPACE_ID;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

const MAX_FRAME_BYTES: usize = 64 * 1024;
/// A module that is never on the throttle allow-list.
const FETCH_MOD_NAME: &str = "Fetch";

/// A connection that serves a scripted list of streams and then parks.
///
/// Parking rather than failing keeps the reader alive for the duration of
/// the assertions, so `close_calls` reflects only what the reader decided to
/// do about the frames — not the teardown that follows a dead connection.
struct ScriptedConnection {
    streams: Mutex<Vec<Vec<u8>>>,
    park: Arc<tokio::sync::Notify>,
    remote_id: EndpointId,
    close_calls: CloseCalls,
}

impl Connection for ScriptedConnection {
    fn open_uni(&self) -> BoxFut<'_, K2Result<DynIrohSendStream>> {
        Box::pin(async { Err(K2Error::other("open_uni not used")) })
    }

    fn accept_uni(&self) -> BoxFut<'_, K2Result<DynIrohRecvStream>> {
        let next = self.streams.lock().unwrap().pop();
        let park = self.park.clone();
        Box::pin(async move {
            match next {
                Some(bytes) => {
                    let stream: DynIrohRecvStream = Arc::new(
                        crate::stream::mock::MockRecvStream::new(bytes),
                    );
                    Ok(stream)
                }
                None => {
                    // Never resolves; the test aborts the reader instead.
                    park.notified().await;
                    Err(K2Error::other("parked"))
                }
            }
        })
    }

    fn remote_id(&self) -> EndpointId {
        self.remote_id
    }

    fn close(&self, code: CloseCode, reason: &[u8]) {
        self.close_calls
            .lock()
            .unwrap()
            .push((code, reason.to_vec()));
    }

    fn is_direct(&self) -> bool {
        false
    }

    fn remote_close_reason(&self) -> Option<(CloseCode, Bytes)> {
        None
    }
}

#[derive(Debug)]
struct StubTxImp;

impl TxImp for StubTxImp {
    fn url(&self) -> Option<Url> {
        None
    }

    fn disconnect(
        &self,
        _peer: Url,
        _payload: Option<(String, Bytes)>,
    ) -> BoxFut<'_, ()> {
        Box::pin(async {})
    }

    fn send(&self, _peer: Url, _data: Bytes) -> BoxFut<'_, K2Result<()>> {
        Box::pin(async { Err(K2Error::other("send not used")) })
    }

    fn get_connected_peers(&self) -> BoxFut<'_, K2Result<Vec<Url>>> {
        Box::pin(async { Ok(Vec::new()) })
    }

    fn dump_network_stats(&self) -> BoxFut<'_, K2Result<TransportStats>> {
        Box::pin(async {
            Ok(TransportStats {
                backend: String::new(),
                peer_urls: Vec::new(),
                connections: Vec::new(),
            })
        })
    }
}

fn remote_url() -> Url {
    Url::from_str(
        "https://relay.example.com:443/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )
    .unwrap()
}

/// Count of `recv_module_msg` calls, per module.
type ModuleCalls = Arc<AtomicUsize>;

/// Build a module handler that counts its calls and returns `result`.
fn counting_module_handler(
    calls: ModuleCalls,
    refuse: bool,
) -> DynTxModuleHandler {
    Arc::new(MockTxHandler {
        recv_module_msg: Arc::new(move |_peer, _space, _module, _data| {
            calls.fetch_add(1, Ordering::SeqCst);
            if refuse {
                // What a saturated kitsune2 publish queue returns.
                Err(K2Error::other(
                    "could not insert incoming publish ops request into queue",
                ))
            } else {
                Ok(())
            }
        }),
        ..MockTxHandler::default()
    })
}

/// Encode a `K2Proto` module frame wrapped in an iroh data frame.
fn module_frame(module: &str, payload: &[u8]) -> Vec<u8> {
    let proto = K2Proto {
        ty: K2WireType::Module as i32,
        data: Bytes::copy_from_slice(payload),
        space_id: Some(TEST_SPACE_ID.into()),
        module_id: Some(module.to_string()),
    }
    .encode()
    .unwrap();
    encode_frame(Frame::Data(proto), MAX_FRAME_BYTES)
        .unwrap()
        .to_vec()
}

/// Encode the preflight frame the reader expects as the first frame on a
/// connection.
fn preflight_frame(url: &Url) -> Vec<u8> {
    let proto = K2Proto {
        ty: K2WireType::Preflight as i32,
        data: Bytes::from_static(b"preflight"),
        space_id: None,
        module_id: None,
    }
    .encode()
    .unwrap();
    encode_frame(Frame::Preflight((url.clone(), proto)), MAX_FRAME_BYTES)
        .unwrap()
        .to_vec()
}

struct Fixture {
    ctx: Arc<ConnectionContext>,
    publish_calls: ModuleCalls,
    fetch_calls: ModuleCalls,
    close_calls: CloseCalls,
    unresponsive_calls: Arc<AtomicUsize>,
}

/// Drive a reader over one stream containing `frames`, with the publish
/// module handler refusing every frame it is given.
fn spawn_reader(frames: Vec<Vec<u8>>, throttle: RecvThrottleConfig) -> Fixture {
    let url = remote_url();

    let unresponsive_calls = Arc::new(AtomicUsize::new(0));
    let base = {
        let unresponsive = unresponsive_calls.clone();
        Arc::new(MockTxHandler {
            set_unresponsive: Arc::new(move |_peer, _ts| {
                unresponsive.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }),
            ..MockTxHandler::default()
        })
    };
    let handler = TxImpHnd::new(base.clone());
    let transport = DefaultTransport::create(&handler, Arc::new(StubTxImp));
    transport.register_space_handler(TEST_SPACE_ID, base);

    let publish_calls: ModuleCalls = Arc::new(AtomicUsize::new(0));
    let fetch_calls: ModuleCalls = Arc::new(AtomicUsize::new(0));
    transport.register_module_handler(
        TEST_SPACE_ID,
        PUBLISH_MOD_NAME.to_string(),
        counting_module_handler(publish_calls.clone(), true),
    );
    transport.register_module_handler(
        TEST_SPACE_ID,
        FETCH_MOD_NAME.to_string(),
        counting_module_handler(fetch_calls.clone(), false),
    );

    // One stream carrying the preflight followed by every data frame.
    let mut stream = preflight_frame(&url);
    for frame in frames {
        stream.extend_from_slice(&frame);
    }

    let close_calls = Arc::new(Mutex::new(Vec::new()));
    let connection: DynConnection = Arc::new(ScriptedConnection {
        // `accept_uni` pops from the back.
        streams: Mutex::new(vec![stream]),
        park: Arc::new(tokio::sync::Notify::new()),
        remote_id: endpoint_from_url(&url).unwrap().id,
        close_calls: close_calls.clone(),
    });

    let connections = Arc::new(RwLock::new(HashMap::new()));
    let ctx = ConnectionContext::new(ConnectionContextParams {
        handler,
        connection,
        local_id: [0u8; 32],
        dialed_by_us: true,
        remote_url: Some(url.clone()),
        preflight_sent: true,
        opened_at_s: 0,
        connections: connections.clone(),
        local_url: Arc::new(RwLock::new(Some(url.clone()))),
        space_relays: Arc::new(RwLock::new(HashMap::new())),
        max_frame_bytes: MAX_FRAME_BYTES,
        recv_throttle: throttle,
    });
    connections.write().unwrap().insert(url, ctx.clone());

    Fixture {
        ctx,
        publish_calls,
        fetch_calls,
        close_calls,
        unresponsive_calls,
    }
}

/// A queue-full refusal must not close the connection, and must not stop the
/// reader: the frames that follow are still read, and a frame for a
/// different module is still delivered.
#[tokio::test(flavor = "multi_thread")]
async fn refusal_does_not_close_the_connection() {
    let frames = vec![
        module_frame(PUBLISH_MOD_NAME, b"ops-1"),
        module_frame(FETCH_MOD_NAME, b"fetch-1"),
    ];
    // Throttle disabled: this test is purely about the close behaviour.
    let fixture = spawn_reader(frames, RecvThrottleConfig::disabled());

    retry_fn_until_timeout(
        || async { fixture.fetch_calls.load(Ordering::SeqCst) == 1 },
        Some(5_000),
        Some(10),
    )
    .await
    .expect("the frame after a refusal must still be delivered");

    assert_eq!(
        fixture.publish_calls.load(Ordering::SeqCst),
        1,
        "the refused frame reached the handler once"
    );
    assert!(
        fixture.close_calls.lock().unwrap().is_empty(),
        "a module handler refusal is advisory back-pressure and must never \
         close the connection: {:?}",
        fixture.close_calls.lock().unwrap()
    );
    assert_eq!(
        fixture.unresponsive_calls.load(Ordering::SeqCst),
        0,
        "and must never mark the peer unresponsive"
    );

    fixture.ctx.abort_tasks();
}

/// After a refusal, further frames for that module are dropped before the
/// handler is invoked — while another module's frames keep flowing.
#[tokio::test(flavor = "multi_thread")]
async fn refusal_throttles_only_the_refusing_module() {
    let mut frames = Vec::new();
    for i in 0..64u32 {
        frames.push(module_frame(
            PUBLISH_MOD_NAME,
            format!("ops-{i}").as_bytes(),
        ));
    }
    // Delivered last, so reaching the handler proves the reader kept going
    // through all 64 publish frames.
    frames.push(module_frame(FETCH_MOD_NAME, b"fetch-after-storm"));

    let throttle = RecvThrottleConfig {
        // Long enough that the whole scripted stream lands inside one window.
        cooldown: Duration::from_secs(60),
        summary_interval: Duration::from_secs(60),
        modules: vec![PUBLISH_MOD_NAME.to_string()],
    };
    let fixture = spawn_reader(frames, throttle);

    retry_fn_until_timeout(
        || async { fixture.fetch_calls.load(Ordering::SeqCst) == 1 },
        Some(5_000),
        Some(10),
    )
    .await
    .expect("fetch frames are never throttled");

    assert_eq!(
        fixture.publish_calls.load(Ordering::SeqCst),
        1,
        "only the first publish frame may reach the saturated handler; the \
         other 63 must be dropped at the transport"
    );
    assert_eq!(
        fixture.ctx.get_recv_dropped_count(),
        63,
        "every dropped frame is counted"
    );
    assert_eq!(
        fixture.ctx.get_recv_message_count(),
        65,
        "dropped frames still count as received on the wire"
    );
    assert!(
        fixture.close_calls.lock().unwrap().is_empty(),
        "throttling never closes the connection"
    );

    fixture.ctx.abort_tasks();
}

/// With the throttle disabled every frame reaches the handler, which is the
/// pre-patch behaviour and the escape hatch `recvThrottleCooldownMs: 0`
/// restores.
#[tokio::test(flavor = "multi_thread")]
async fn disabled_throttle_delivers_every_frame() {
    let mut frames = Vec::new();
    for i in 0..8u32 {
        frames.push(module_frame(
            PUBLISH_MOD_NAME,
            format!("ops-{i}").as_bytes(),
        ));
    }
    frames.push(module_frame(FETCH_MOD_NAME, b"fetch-last"));

    let fixture = spawn_reader(frames, RecvThrottleConfig::disabled());

    retry_fn_until_timeout(
        || async { fixture.fetch_calls.load(Ordering::SeqCst) == 1 },
        Some(5_000),
        Some(10),
    )
    .await
    .expect("reader should drain the scripted stream");

    assert_eq!(fixture.publish_calls.load(Ordering::SeqCst), 8);
    assert_eq!(fixture.ctx.get_recv_dropped_count(), 0);

    fixture.ctx.abort_tasks();
}
