use super::DbKind;
use opentelemetry::{global::meter, metrics, KeyValue};

/// An OpenTelemetry f64 histogram pre-bound to a fixed set of attributes.
#[derive(Clone)]
pub struct Histogram {
    histogram: metrics::Histogram<f64>,
    attributes: Vec<KeyValue>,
}

impl Histogram {
    /// Record a value. The pre-bound attributes are used; `_attributes` is ignored.
    pub fn record(&self, value: f64, _attributes: &[KeyValue]) {
        self.histogram.record(value, &self.attributes);
    }
}

/// Metric for `hc.db.write_txn.duration`.
pub type WriteTxnDurationMetric = Histogram;

/// Create a [`WriteTxnDurationMetric`] bound to the given [`DbKind`].
pub fn create_write_txn_duration_metric(kind: DbKind) -> WriteTxnDurationMetric {
    let histogram = meter("hc.db")
        .f64_histogram("hc.db.write_txn.duration")
        .with_unit("s")
        .with_description("The time spent executing an exclusive write transaction")
        .build();
    let attributes = vec![
        KeyValue::new("kind", db_kind_name(kind.clone())),
        KeyValue::new("id", format!("{kind}")),
    ];
    Histogram {
        histogram,
        attributes,
    }
}

/// Metric for `hc.db.connections.use_time`.
pub type ConnectionUseTimeMetric = Histogram;

/// Create a [`ConnectionUseTimeMetric`] bound to the given [`DbKind`].
pub fn create_connection_use_time_metric(kind: DbKind) -> ConnectionUseTimeMetric {
    let histogram = meter("hc.db")
        .f64_histogram("hc.db.connections.use_time")
        .with_unit("s")
        .with_description("The time between borrowing a connection and returning it to the pool")
        .build();
    let attributes = vec![
        KeyValue::new("kind", db_kind_name(kind.clone())),
        KeyValue::new("id", format!("{kind}")),
    ];
    Histogram {
        histogram,
        attributes,
    }
}

fn db_kind_name(kind: DbKind) -> String {
    match kind {
        DbKind::Authored(_) => "authored",
        DbKind::Dht(_) => "dht",
        DbKind::Cache(_) => "cache",
        DbKind::Conductor => "conductor",
        DbKind::Wasm => "wasm",
        DbKind::PeerMetaStore(_) => "peer_meta_store",
        #[cfg(feature = "test_utils")]
        DbKind::Test(_) => "test",
    }
    .to_string()
}

/// An OpenTelemetry u64 counter pre-bound to a fixed set of attributes.
#[derive(Clone)]
pub struct Counter {
    counter: metrics::Counter<u64>,
    attributes: Vec<KeyValue>,
}

impl Counter {
    /// Add to the counter using the pre-bound attributes.
    pub fn add(&self, value: u64) {
        self.counter.add(value, &self.attributes);
    }
}

/// Metric for `hc.db.connections.read_saturation`.
pub type ReadSaturationMetric = Counter;

/// Create a [`ReadSaturationMetric`] bound to the given [`DbKind`].
///
/// Counts every attempt to check out a read connection while the read pool is oversubscribed. The
/// corresponding log line is rate limited, so this counter is the accurate measure of how hard the
/// read pool is being oversubscribed, and of which database.
pub fn create_read_saturation_metric(kind: DbKind) -> ReadSaturationMetric {
    let counter = meter("hc.db")
        .u64_counter("hc.db.connections.read_saturation")
        .with_description(
            "Read connection checkouts attempted while the read pool was oversubscribed.",
        )
        .build();
    let attributes = vec![
        KeyValue::new("kind", db_kind_name(kind.clone())),
        KeyValue::new("id", format!("{kind}")),
    ];
    Counter {
        counter,
        attributes,
    }
}
