//! Per-remote, module-scoped receive throttle.
//!
//! ── ELOHIM PATCH (2026-09-13, publish-storm cure) ───────────────────────
//!
//! A kitsune2 module handler signals "my inbound queue is full" by returning
//! an error from [`kitsune2_api::TxModuleHandler::recv_module_msg`]. Upstream
//! treats that as a connection-fatal error (see the
//! `"Error in recv_module_msg, peer connection will be closed"` warning in
//! `kitsune2_api::transport`), and this transport already declines to close
//! the connection for it — a saturated queue is advisory back-pressure, not a
//! broken peer.
//!
//! Declining to close is necessary but not sufficient. With the connection
//! held open the remote keeps sending, and every refused frame is still fully
//! decoded by the module handler, still allocated, still discarded, and still
//! logged twice. On the alpha fleet that steady state was measured at
//! ~750 refusals/second against a single conductor (~5.4 M log lines/hour) —
//! pure burn, with no work done on the data.
//!
//! This module adds the missing half: when a module refuses a frame, that
//! *module* on that *connection* enters a short cooldown. Frames addressed to
//! it are dropped at the transport, before the handler is invoked at all, so
//! the decode, the allocation and both log lines are never paid. The drop is
//! counted and summarised at a rate limit rather than logged per frame.
//!
//! Three properties keep the blast radius small:
//!
//! - **Module-scoped.** Only modules on the configured allow-list are ever
//!   throttled (default: `Publish`). Gossip, fetch, preflight and notify
//!   frames are never dropped, so no gossip round and no op fetch is
//!   affected by a publish flood.
//! - **Per connection.** Each [`crate::connection_context::ConnectionContext`]
//!   owns its own throttle, so one flooding remote cannot silence another.
//! - **Short and self-clearing.** The cooldown expires on a timer; nothing
//!   has to un-stick it, and disabling it is a config change
//!   (`recvThrottleCooldownMs: 0`), not a rebuild.
//!
//! Dropping is safe by construction: the kitsune2 transport offers no
//! delivery guarantee, and these frames were already being dropped — by the
//! full queue, after the expensive part. This drops them earlier and cheaper.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Bucket key used for refusals that could not be attributed to a module
/// (a malformed frame, a preflight rejection, a notify handler error).
/// Refusals in this bucket are rate-limited for logging but never arm a
/// cooldown — there is no module to scope the drop to.
const UNSCOPED: &str = "<unscoped>";

/// Module that the receive throttle guards by default.
///
/// Matches `kitsune2_core::factories::core_publish::PUBLISH_MOD_NAME`. It is
/// duplicated as a literal rather than imported so this crate does not take a
/// non-test dependency on `kitsune2_core`.
pub(crate) const PUBLISH_MOD_NAME: &str = "Publish";

/// How long a module stays in cooldown after refusing a frame.
pub(crate) const DEFAULT_RECV_THROTTLE_COOLDOWN_MS: u64 = 250;

/// How often a throttle summary may be logged, per module per connection.
pub(crate) const DEFAULT_RECV_THROTTLE_SUMMARY_INTERVAL_S: u32 = 30;

/// Runtime configuration for [`RecvThrottle`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RecvThrottleConfig {
    /// Cooldown applied to a module after it refuses a frame. Zero disables
    /// the throttle entirely.
    pub cooldown: Duration,
    /// Minimum interval between throttle summary logs, per module.
    pub summary_interval: Duration,
    /// Modules eligible for throttling. Anything not listed here is always
    /// handed to the handler.
    pub modules: Vec<String>,
}

impl Default for RecvThrottleConfig {
    fn default() -> Self {
        Self {
            cooldown: Duration::from_millis(DEFAULT_RECV_THROTTLE_COOLDOWN_MS),
            summary_interval: Duration::from_secs(
                DEFAULT_RECV_THROTTLE_SUMMARY_INTERVAL_S as u64,
            ),
            modules: vec![PUBLISH_MOD_NAME.to_string()],
        }
    }
}

impl RecvThrottleConfig {
    /// A configuration that never drops a frame. Behaviour is then identical
    /// to the pre-patch reader, minus the per-frame error log.
    ///
    /// Test helper only — in production the same effect is a config change,
    /// `recvThrottleCooldownMs: 0`.
    #[cfg(test)]
    pub(crate) fn disabled() -> Self {
        Self {
            cooldown: Duration::ZERO,
            summary_interval: Duration::from_secs(
                DEFAULT_RECV_THROTTLE_SUMMARY_INTERVAL_S as u64,
            ),
            modules: Vec::new(),
        }
    }

    /// Whether this configuration can drop anything at all.
    pub(crate) fn is_enabled(&self) -> bool {
        !self.cooldown.is_zero() && !self.modules.is_empty()
    }

    /// Whether `module` is eligible for throttling.
    pub(crate) fn throttles(&self, module: &str) -> bool {
        self.is_enabled() && self.modules.iter().any(|m| m == module)
    }
}

/// A rate-limited summary of what the throttle absorbed for one module since
/// the previous summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ThrottleReport {
    /// Module the refusals were addressed to, or `<unscoped>`.
    pub module: String,
    /// Refusals seen since the previous report, including this one.
    pub refusals: u64,
    /// Frames dropped without invoking the handler since the previous report.
    pub dropped: u64,
}

#[derive(Debug, Default)]
struct ModuleState {
    cooldown_until: Option<Instant>,
    refusals: u64,
    dropped: u64,
    reported_at: Option<Instant>,
}

/// Per-connection receive throttle state.
///
/// Not internally synchronised; the connection reader holds it behind a
/// [`std::sync::Mutex`] and never awaits while holding it.
#[derive(Debug)]
pub(crate) struct RecvThrottle {
    config: RecvThrottleConfig,
    modules: HashMap<String, ModuleState>,
}

impl RecvThrottle {
    /// Create a throttle with the given configuration.
    pub(crate) fn new(config: RecvThrottleConfig) -> Self {
        Self {
            config,
            modules: HashMap::new(),
        }
    }

    /// Whether a frame addressed to `module` should be dropped without
    /// invoking the handler.
    ///
    /// Counts the drop so it can be reported in the next summary.
    pub(crate) fn should_drop(&mut self, module: &str, now: Instant) -> bool {
        if !self.config.throttles(module) {
            return false;
        }
        let state = self.modules.entry(module.to_string()).or_default();
        match state.cooldown_until {
            Some(until) if until > now => {
                state.dropped += 1;
                true
            }
            Some(_) => {
                // Cooldown elapsed: let the next frame through and find out
                // whether the handler has caught up.
                state.cooldown_until = None;
                false
            }
            None => false,
        }
    }

    /// Record that a handler refused a frame.
    ///
    /// Arms a cooldown when the module is eligible, and returns a summary
    /// when the log rate limit allows one. `None` means the caller should
    /// log at debug level (or not at all).
    pub(crate) fn on_refusal(
        &mut self,
        module: Option<&str>,
        now: Instant,
    ) -> Option<ThrottleReport> {
        let arm = module.map(|m| self.config.throttles(m)).unwrap_or(false);
        let cooldown = self.config.cooldown;
        let summary_interval = self.config.summary_interval;
        let key = module.unwrap_or(UNSCOPED);

        let state = self.modules.entry(key.to_string()).or_default();
        state.refusals += 1;
        if arm {
            state.cooldown_until = Some(now + cooldown);
        }

        let due = match state.reported_at {
            None => true,
            Some(at) => now.duration_since(at) >= summary_interval,
        };
        if !due {
            return None;
        }

        state.reported_at = Some(now);
        let report = ThrottleReport {
            module: key.to_string(),
            refusals: state.refusals,
            dropped: state.dropped,
        };
        state.refusals = 0;
        state.dropped = 0;
        Some(report)
    }
}

impl From<&crate::config::IrohTransportConfig> for RecvThrottleConfig {
    fn from(config: &crate::config::IrohTransportConfig) -> Self {
        Self {
            cooldown: Duration::from_millis(config.recv_throttle_cooldown_ms),
            summary_interval: Duration::from_secs(
                config.recv_throttle_summary_interval_s as u64,
            ),
            modules: config.recv_throttle_modules.clone(),
        }
    }
}

/// Protobuf field number of `K2Proto.ty`.
const FIELD_TY: u64 = 1;
/// Protobuf field number of `K2Proto.module_id`.
const FIELD_MODULE_ID: u64 = 4;
/// Discriminant of `kitsune2_api::K2WireType::Module`.
const WIRE_TYPE_MODULE: u64 = 3;

/// Read a base-128 varint, returning its value and the bytes consumed.
fn read_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let mut value: u64 = 0;
    let mut shift: u32 = 0;
    for (i, byte) in buf.iter().enumerate() {
        if shift >= 64 {
            return None;
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some((value, i + 1));
        }
        shift += 7;
    }
    None
}

/// Peek at the module a `K2Proto` frame is addressed to, without decoding it.
///
/// Walks the top-level protobuf fields and skips length-delimited payloads by
/// length, so the cost is proportional to the number of fields (four) and not
/// to the size of the message — and nothing is allocated or copied. Returns
/// `None` for any frame that is not a well-formed `TY_MODULE` message with a
/// UTF-8 `module_id`, which makes an unparseable frame fall through to the
/// handler exactly as before.
pub(crate) fn peek_module_id(frame: &[u8]) -> Option<&str> {
    let mut pos = 0usize;
    let mut is_module = false;
    let mut module_id: Option<&str> = None;

    while pos < frame.len() {
        let (key, read) = read_varint(&frame[pos..])?;
        pos += read;
        let field = key >> 3;
        match key & 0x7 {
            // varint
            0 => {
                let (value, read) = read_varint(frame.get(pos..)?)?;
                pos += read;
                if field == FIELD_TY {
                    is_module = value == WIRE_TYPE_MODULE;
                }
            }
            // 64-bit
            1 => pos = pos.checked_add(8)?,
            // length-delimited
            2 => {
                let (len, read) = read_varint(frame.get(pos..)?)?;
                pos += read;
                let len = usize::try_from(len).ok()?;
                let end = pos.checked_add(len)?;
                let bytes = frame.get(pos..end)?;
                if field == FIELD_MODULE_ID {
                    module_id = std::str::from_utf8(bytes).ok();
                }
                pos = end;
            }
            // 32-bit
            5 => pos = pos.checked_add(4)?,
            // groups (3, 4) and anything else are not used by K2Proto
            _ => return None,
        }
        if pos > frame.len() {
            return None;
        }
    }

    if is_module { module_id } else { None }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(cooldown_ms: u64, summary_s: u64) -> RecvThrottleConfig {
        RecvThrottleConfig {
            cooldown: Duration::from_millis(cooldown_ms),
            summary_interval: Duration::from_secs(summary_s),
            modules: vec![PUBLISH_MOD_NAME.to_string()],
        }
    }

    #[test]
    fn refusal_arms_cooldown_and_drops_following_frames() {
        let mut throttle = RecvThrottle::new(cfg(250, 30));
        let t0 = Instant::now();

        assert!(
            !throttle.should_drop(PUBLISH_MOD_NAME, t0),
            "nothing is dropped before a handler has refused anything"
        );

        throttle.on_refusal(Some(PUBLISH_MOD_NAME), t0);

        assert!(
            throttle
                .should_drop(PUBLISH_MOD_NAME, t0 + Duration::from_millis(1))
        );
        assert!(
            throttle
                .should_drop(PUBLISH_MOD_NAME, t0 + Duration::from_millis(249))
        );
    }

    #[test]
    fn cooldown_expires_and_lets_a_probe_frame_through() {
        let mut throttle = RecvThrottle::new(cfg(250, 30));
        let t0 = Instant::now();
        throttle.on_refusal(Some(PUBLISH_MOD_NAME), t0);

        assert!(
            !throttle
                .should_drop(PUBLISH_MOD_NAME, t0 + Duration::from_secs(1)),
            "after the cooldown the next frame must reach the handler so a \
             recovered queue is noticed"
        );
        assert!(
            !throttle
                .should_drop(PUBLISH_MOD_NAME, t0 + Duration::from_secs(1)),
            "and the throttle stays open until the handler refuses again"
        );
    }

    #[test]
    fn other_modules_are_never_throttled() {
        let mut throttle = RecvThrottle::new(cfg(250, 30));
        let t0 = Instant::now();

        // A publish flood is in cooldown ...
        throttle.on_refusal(Some(PUBLISH_MOD_NAME), t0);
        assert!(
            throttle
                .should_drop(PUBLISH_MOD_NAME, t0 + Duration::from_millis(1))
        );

        // ... but gossip and fetch frames from the same peer still flow.
        for module in ["K2Gossip", "Fetch", "Publishing"] {
            assert!(
                !throttle.should_drop(module, t0 + Duration::from_millis(1)),
                "{module} is not on the allow-list and must never be dropped"
            );
        }
    }

    #[test]
    fn gossip_refusal_does_not_arm_a_cooldown() {
        let mut throttle = RecvThrottle::new(cfg(250, 30));
        let t0 = Instant::now();
        throttle.on_refusal(Some("K2Gossip"), t0);
        assert!(
            !throttle.should_drop("K2Gossip", t0 + Duration::from_millis(1)),
            "a refusal from a non-allow-listed module must not silence it"
        );
    }

    #[test]
    fn disabled_config_never_drops() {
        let mut throttle = RecvThrottle::new(RecvThrottleConfig::disabled());
        let t0 = Instant::now();
        throttle.on_refusal(Some(PUBLISH_MOD_NAME), t0);
        assert!(
            !throttle
                .should_drop(PUBLISH_MOD_NAME, t0 + Duration::from_millis(1))
        );

        let mut zero_cooldown = RecvThrottle::new(cfg(0, 30));
        zero_cooldown.on_refusal(Some(PUBLISH_MOD_NAME), t0);
        assert!(
            !zero_cooldown
                .should_drop(PUBLISH_MOD_NAME, t0 + Duration::from_millis(1))
        );
    }

    #[test]
    fn summaries_are_rate_limited_and_carry_counts() {
        let mut throttle = RecvThrottle::new(cfg(250, 30));
        let t0 = Instant::now();

        let first = throttle
            .on_refusal(Some(PUBLISH_MOD_NAME), t0)
            .expect("the first refusal always reports");
        assert_eq!(first.module, PUBLISH_MOD_NAME);
        assert_eq!(first.refusals, 1);
        assert_eq!(first.dropped, 0);

        // A storm inside the summary window: many drops, one probe refusal
        // per cooldown, and not a single extra log line.
        let mut t = t0;
        for _ in 0..5 {
            for _ in 0..100 {
                t += Duration::from_millis(1);
                assert!(throttle.should_drop(PUBLISH_MOD_NAME, t));
            }
            t += Duration::from_millis(200);
            assert!(
                throttle.on_refusal(Some(PUBLISH_MOD_NAME), t).is_none(),
                "no summary may be emitted inside the rate-limit window"
            );
        }

        let later = throttle
            .on_refusal(Some(PUBLISH_MOD_NAME), t0 + Duration::from_secs(31))
            .expect("a summary is due once the window has elapsed");
        assert_eq!(later.refusals, 6, "5 in-window refusals plus this one");
        assert_eq!(later.dropped, 500);

        assert!(
            throttle
                .on_refusal(
                    Some(PUBLISH_MOD_NAME),
                    t0 + Duration::from_secs(31)
                )
                .is_none(),
            "counters reset after a summary, and the window restarts"
        );
    }

    #[test]
    fn unscoped_refusals_are_rate_limited_but_arm_nothing() {
        let mut throttle = RecvThrottle::new(cfg(250, 30));
        let t0 = Instant::now();

        let report = throttle.on_refusal(None, t0).expect("first reports");
        assert_eq!(report.module, UNSCOPED);
        assert!(throttle.on_refusal(None, t0).is_none());
        assert!(
            !throttle
                .should_drop(PUBLISH_MOD_NAME, t0 + Duration::from_millis(1)),
            "an unattributable refusal must not silence a real module"
        );
    }

    #[test]
    fn peek_reads_the_module_of_a_module_frame() {
        use kitsune2_api::{K2Proto, K2WireType};
        let frame = K2Proto {
            ty: K2WireType::Module as i32,
            data: bytes::Bytes::from_static(&[7u8; 4096]),
            space_id: Some(bytes::Bytes::from_static(b"space")),
            module_id: Some(PUBLISH_MOD_NAME.to_string()),
        }
        .encode()
        .unwrap();

        assert_eq!(peek_module_id(&frame), Some(PUBLISH_MOD_NAME));
    }

    #[test]
    fn peek_declines_non_module_and_malformed_frames() {
        use kitsune2_api::{K2Proto, K2WireType};

        let notify = K2Proto {
            ty: K2WireType::Notify as i32,
            data: bytes::Bytes::from_static(b"payload"),
            space_id: Some(bytes::Bytes::from_static(b"space")),
            module_id: None,
        }
        .encode()
        .unwrap();
        assert_eq!(
            peek_module_id(&notify),
            None,
            "a notify frame is not module-addressed"
        );

        let preflight = K2Proto {
            ty: K2WireType::Preflight as i32,
            data: bytes::Bytes::from_static(b"payload"),
            space_id: None,
            module_id: None,
        }
        .encode()
        .unwrap();
        assert_eq!(peek_module_id(&preflight), None);

        assert_eq!(peek_module_id(b""), None);
        assert_eq!(
            peek_module_id(b"this is not a protobuf message at all"),
            None
        );
        // Truncated mid-field: must not panic and must not claim a module.
        let truncated = &notify[..notify.len() - 2];
        assert_eq!(peek_module_id(truncated), None);
    }

    #[test]
    fn peek_matches_a_full_decode_for_every_wire_type() {
        use kitsune2_api::{K2Proto, K2WireType};
        for (ty, module) in [
            (K2WireType::Unspecified, None),
            (K2WireType::Preflight, None),
            (K2WireType::Notify, None),
            (K2WireType::Module, Some("Fetch")),
            (K2WireType::Module, Some(PUBLISH_MOD_NAME)),
            (K2WireType::Disconnect, None),
        ] {
            let encoded = K2Proto {
                ty: ty as i32,
                data: bytes::Bytes::from_static(b"some payload bytes"),
                space_id: Some(bytes::Bytes::from_static(b"space-id")),
                module_id: module.map(|m| m.to_string()),
            }
            .encode()
            .unwrap();

            let decoded = K2Proto::decode(&encoded).unwrap();
            let expected = if decoded.ty == K2WireType::Module as i32 {
                decoded.module_id.as_deref()
            } else {
                None
            };
            assert_eq!(peek_module_id(&encoded), expected, "ty={ty:?}");
        }
    }
}
