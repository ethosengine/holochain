//! Prometheus text exposition for the conductor's OpenTelemetry instruments.
//!
//! ── ELOHIM ADDITION (2026-09-23) ──
//!
//! The conductor instruments about thirty OpenTelemetry meters
//! (`hc.conductor.workflow.*`, `hc.db.connections.use_time`,
//! `hc.holochain_p2p.request.duration`, `hc.ribosome.zome_call.duration`, …)
//! but this crate only knew how to ship them to InfluxDB. Nothing in the fleet
//! runs InfluxDB, so every one of those instruments was a no-op and the
//! conductor's own view of a CPU storm never reached Prometheus.
//!
//! `HOLOCHAIN_PROMETHEUS_LISTEN=host:port` serves them at `GET /metrics` in the
//! Prometheus text format, pull-based: a [`ManualReader`] is collected on each
//! scrape, so nothing is exported while nobody asks.
//!
//! Deliberately not `opentelemetry-prometheus`: that crate is discontinued
//! upstream and carries an unmaintained `protobuf` dependency. This is a small
//! renderer over the SDK's public data model and a one-route HTTP/1.1
//! responder — no framework, no new transitive dependencies.

use opentelemetry::KeyValue;
use opentelemetry_sdk::error::OTelSdkResult;
use opentelemetry_sdk::metrics::data::{AggregatedMetrics, Metric, MetricData, ResourceMetrics};
use opentelemetry_sdk::metrics::reader::MetricReader;
use opentelemetry_sdk::metrics::{
    InstrumentKind, ManualReader, Pipeline, SdkMeterProvider, Temporality,
};
use std::fmt::Write as _;
use std::sync::{Arc, Weak};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Largest request head we are willing to read before answering.
const MAX_REQUEST_HEAD_BYTES: usize = 8 * 1024;
/// How long a scraper may take to send its request head.
const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(5);
/// Content type for the text exposition format.
const TEXT_FORMAT: &str = "text/plain; version=0.0.4; charset=utf-8";

/// A [`ManualReader`] that can be handed to the SDK meter provider AND kept
/// by the exporter for collection. The SDK takes readers by value, so the
/// shared handle delegates every trait method to the one reader inside.
#[derive(Debug, Clone)]
struct SharedReader(Arc<ManualReader>);

impl MetricReader for SharedReader {
    fn register_pipeline(&self, pipeline: Weak<Pipeline>) {
        self.0.register_pipeline(pipeline)
    }

    fn collect(&self, rm: &mut ResourceMetrics) -> OTelSdkResult {
        self.0.collect(rm)
    }

    fn force_flush(&self) -> OTelSdkResult {
        self.0.force_flush()
    }

    fn shutdown_with_timeout(&self, timeout: Duration) -> OTelSdkResult {
        self.0.shutdown_with_timeout(timeout)
    }

    fn temporality(&self, kind: InstrumentKind) -> Temporality {
        self.0.temporality(kind)
    }
}

/// Collects the process's OpenTelemetry metrics on demand and renders them in
/// the Prometheus text exposition format.
#[derive(Debug)]
pub struct PrometheusExporter {
    reader: Arc<ManualReader>,
}

impl PrometheusExporter {
    /// Build an exporter and the meter provider that feeds it.
    ///
    /// The caller installs the provider globally (or uses it directly in a
    /// test); the exporter is what a scrape reads from. Cumulative temporality
    /// is what Prometheus expects for counters and histograms.
    pub fn install() -> (Self, SdkMeterProvider) {
        let reader = Arc::new(
            ManualReader::builder()
                .with_temporality(Temporality::Cumulative)
                .build(),
        );
        let provider = SdkMeterProvider::builder()
            .with_reader(SharedReader(Arc::clone(&reader)))
            .build();
        (Self { reader }, provider)
    }

    /// Collect every registered instrument and render the text exposition.
    pub fn render(&self) -> Result<String, String> {
        let mut rm = ResourceMetrics::default();
        self.reader
            .collect(&mut rm)
            .map_err(|err| format!("metrics collect failed: {err}"))?;
        Ok(render_text(&rm))
    }
}

/// Serve `GET /metrics` on an already-bound listener until the task is dropped.
///
/// One request per connection, `Connection: close`, no keep-alive, no TLS:
/// the listener is meant for a pod-local scrape endpoint behind the cluster's
/// network policy, exactly like elohim-storage's `/metrics`.
pub async fn serve(exporter: Arc<PrometheusExporter>, listener: TcpListener) {
    loop {
        let (mut stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(err) => {
                tracing::warn!(?err, "prometheus metrics: accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let exporter = Arc::clone(&exporter);
        tokio::spawn(async move {
            let head = read_request_head(&mut stream).await;
            let (status, content_type, body) = match head {
                Some(head) => answer(&exporter, &head),
                None => (
                    "408 Request Timeout",
                    "text/plain; charset=utf-8",
                    String::new(),
                ),
            };
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            if let Err(err) = stream.write_all(response.as_bytes()).await {
                tracing::debug!(?err, ?peer, "prometheus metrics: response write failed");
            }
            let _ = stream.shutdown().await;
        });
    }
}

/// Read up to the end of the request head (`\r\n\r\n`) or the size cap.
async fn read_request_head(stream: &mut tokio::net::TcpStream) -> Option<String> {
    let mut head = Vec::with_capacity(512);
    let mut chunk = [0u8; 1024];
    let read = tokio::time::timeout(REQUEST_READ_TIMEOUT, async {
        loop {
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                break;
            }
            head.extend_from_slice(&chunk[..n]);
            if head.windows(4).any(|w| w == b"\r\n\r\n") || head.len() >= MAX_REQUEST_HEAD_BYTES {
                break;
            }
        }
        Ok::<(), std::io::Error>(())
    })
    .await;
    match read {
        Ok(Ok(())) => Some(String::from_utf8_lossy(&head).into_owned()),
        _ => None,
    }
}

/// Route the one request we serve.
fn answer(exporter: &PrometheusExporter, head: &str) -> (&'static str, &'static str, String) {
    let mut request_line = head.lines().next().unwrap_or("").split_whitespace();
    let method = request_line.next().unwrap_or("");
    let target = request_line.next().unwrap_or("");
    let path = target.split('?').next().unwrap_or("");
    if method != "GET" {
        return (
            "405 Method Not Allowed",
            "text/plain; charset=utf-8",
            String::new(),
        );
    }
    if path != "/metrics" {
        return ("404 Not Found", "text/plain; charset=utf-8", String::new());
    }
    match exporter.render() {
        Ok(body) => ("200 OK", TEXT_FORMAT, body),
        Err(err) => (
            "500 Internal Server Error",
            "text/plain; charset=utf-8",
            err,
        ),
    }
}

/// Render every scope's metrics. Resource attributes are deliberately NOT
/// attached as labels: the scraper (a PodMonitor) already labels the series
/// with the pod, and repeating a `host` on every line only inflates the body.
fn render_text(rm: &ResourceMetrics) -> String {
    let mut out = String::new();
    for scope in rm.scope_metrics() {
        for metric in scope.metrics() {
            render_metric(&mut out, metric);
        }
    }
    out
}

fn render_metric(out: &mut String, metric: &Metric) {
    let name = sanitize_name(metric.name());
    let help = metric.description();
    match metric.data() {
        AggregatedMetrics::F64(data) => render_data(out, &name, help, data),
        AggregatedMetrics::U64(data) => render_data(out, &name, help, data),
        AggregatedMetrics::I64(data) => render_data(out, &name, help, data),
    }
}

fn render_data<T: Copy + Number>(out: &mut String, name: &str, help: &str, data: &MetricData<T>) {
    match data {
        MetricData::Gauge(gauge) => {
            write_header(out, name, help, "gauge");
            for point in gauge.data_points() {
                write_sample(out, name, point.attributes(), point.value().render());
            }
        }
        MetricData::Sum(sum) => {
            let (series_name, kind) = if sum.is_monotonic() {
                (format!("{name}_total"), "counter")
            } else {
                (name.to_owned(), "gauge")
            };
            write_header(out, &series_name, help, kind);
            for point in sum.data_points() {
                write_sample(
                    out,
                    &series_name,
                    point.attributes(),
                    point.value().render(),
                );
            }
        }
        MetricData::Histogram(histogram) => {
            write_header(out, name, help, "histogram");
            for point in histogram.data_points() {
                let attributes: Vec<&KeyValue> = point.attributes().collect();
                let bounds: Vec<f64> = point.bounds().collect();
                let mut cumulative = 0u64;
                for (index, count) in point.bucket_counts().enumerate() {
                    cumulative = cumulative.saturating_add(count);
                    let le = bounds
                        .get(index)
                        .map(|bound| bound.render())
                        .unwrap_or_else(|| "+Inf".to_owned());
                    let mut labels = attributes.clone();
                    let le_label = KeyValue::new("le", le);
                    labels.push(&le_label);
                    write_sample(
                        out,
                        &format!("{name}_bucket"),
                        labels.into_iter(),
                        cumulative.to_string(),
                    );
                }
                write_sample(
                    out,
                    &format!("{name}_sum"),
                    attributes.iter().copied(),
                    point.sum().render(),
                );
                write_sample(
                    out,
                    &format!("{name}_count"),
                    attributes.iter().copied(),
                    point.count().to_string(),
                );
            }
        }
        MetricData::ExponentialHistogram(histogram) => {
            // Bucket layout is base-2 exponential; Prometheus classic buckets
            // cannot carry it losslessly. Export the totals so the series is
            // at least visible and rate-able.
            write_header(out, name, help, "summary");
            for point in histogram.data_points() {
                let attributes: Vec<&KeyValue> = point.attributes().collect();
                write_sample(
                    out,
                    &format!("{name}_sum"),
                    attributes.iter().copied(),
                    point.sum().render(),
                );
                write_sample(
                    out,
                    &format!("{name}_count"),
                    attributes.iter().copied(),
                    point.count().to_string(),
                );
            }
        }
    }
}

fn write_header(out: &mut String, name: &str, help: &str, kind: &str) {
    if !help.is_empty() {
        let _ = writeln!(out, "# HELP {name} {}", escape_help(help));
    }
    let _ = writeln!(out, "# TYPE {name} {kind}");
}

fn write_sample<'a>(
    out: &mut String,
    name: &str,
    attributes: impl Iterator<Item = &'a KeyValue>,
    value: String,
) {
    let mut labels = String::new();
    for (index, kv) in attributes.enumerate() {
        if index > 0 {
            labels.push(',');
        }
        let _ = write!(
            labels,
            "{}=\"{}\"",
            sanitize_name(kv.key.as_str()),
            escape_label(&kv.value.to_string())
        );
    }
    if labels.is_empty() {
        let _ = writeln!(out, "{name} {value}");
    } else {
        let _ = writeln!(out, "{name}{{{labels}}} {value}");
    }
}

/// `hc.conductor.workflow.duration` → `hc_conductor_workflow_duration`.
/// Prometheus names admit `[a-zA-Z_:][a-zA-Z0-9_:]*`; labels do not admit `:`.
fn sanitize_name(raw: &str) -> String {
    let mut name: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if name.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        name.insert(0, '_');
    }
    name
}

fn escape_label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn escape_help(value: &str) -> String {
    value.replace('\\', "\\\\").replace('\n', "\\n")
}

/// Numeric rendering that matches what Prometheus parses: integers as-is,
/// floats in Rust's shortest round-trip form, non-finite values spelled the
/// Prometheus way.
trait Number {
    fn render(self) -> String;
}

impl Number for u64 {
    fn render(self) -> String {
        self.to_string()
    }
}

impl Number for i64 {
    fn render(self) -> String {
        self.to_string()
    }
}

impl Number for f64 {
    fn render(self) -> String {
        if self.is_nan() {
            "NaN".to_owned()
        } else if self == f64::INFINITY {
            "+Inf".to_owned()
        } else if self == f64::NEG_INFINITY {
            "-Inf".to_owned()
        } else {
            self.to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry::metrics::MeterProvider as _;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpStream;

    fn sample_provider() -> (Arc<PrometheusExporter>, SdkMeterProvider) {
        let (exporter, provider) = PrometheusExporter::install();
        let meter = provider.meter("hc.test");
        meter
            .u64_counter("hc.test.workflow.run")
            .with_description("runs started")
            .build()
            .add(3, &[KeyValue::new("workflow", "publish_dht_ops")]);
        meter
            .i64_up_down_counter("hc.test.workflow.in_flight")
            .build()
            .add(2, &[]);
        meter
            .f64_histogram("hc.test.workflow.duration")
            .with_unit("s")
            .build()
            .record(0.25, &[KeyValue::new("workflow", "publish_dht_ops")]);
        meter.u64_gauge("hc.test.uptime").build().record(42, &[]);
        (Arc::new(exporter), provider)
    }

    #[test]
    fn renders_counter_updown_histogram_and_gauge_in_text_format() {
        let (exporter, _provider) = sample_provider();
        let body = exporter.render().expect("render");
        assert!(body.contains("# HELP hc_test_workflow_run_total runs started\n"));
        assert!(body.contains("# TYPE hc_test_workflow_run_total counter\n"));
        assert!(body.contains("hc_test_workflow_run_total{workflow=\"publish_dht_ops\"} 3\n"));
        assert!(body.contains("# TYPE hc_test_workflow_in_flight gauge\n"));
        assert!(body.contains("hc_test_workflow_in_flight 2\n"));
        assert!(body.contains("# TYPE hc_test_workflow_duration histogram\n"));
        assert!(body.contains(
            "hc_test_workflow_duration_bucket{workflow=\"publish_dht_ops\",le=\"+Inf\"} 1\n"
        ));
        assert!(body.contains("hc_test_workflow_duration_sum{workflow=\"publish_dht_ops\"} 0.25\n"));
        assert!(body.contains("hc_test_workflow_duration_count{workflow=\"publish_dht_ops\"} 1\n"));
        assert!(body.contains("# TYPE hc_test_uptime gauge\nhc_test_uptime 42\n"));
        // Cumulative bucket counts are monotone across the bounds.
        let bucket_values: Vec<u64> = body
            .lines()
            .filter(|l| l.starts_with("hc_test_workflow_duration_bucket"))
            .map(|l| l.rsplit(' ').next().unwrap().parse().unwrap())
            .collect();
        assert!(bucket_values.windows(2).all(|w| w[0] <= w[1]));
        assert_eq!(bucket_values.last(), Some(&1));
    }

    #[test]
    fn names_and_labels_are_sanitized_and_escaped() {
        assert_eq!(
            sanitize_name("hc.conductor.workflow.duration"),
            "hc_conductor_workflow_duration"
        );
        assert_eq!(sanitize_name("9lives"), "_9lives");
        assert_eq!(sanitize_name("dna-hash"), "dna_hash");
        assert_eq!(escape_label("a\"b\\c\nd"), "a\\\"b\\\\c\\nd");
        assert_eq!(f64::NAN.render(), "NaN");
        assert_eq!(f64::INFINITY.render(), "+Inf");
        assert_eq!(1.5f64.render(), "1.5");
        assert_eq!(2.0f64.render(), "2");
    }

    async fn http_get(addr: std::net::SocketAddr, target: &str) -> String {
        let mut stream = TcpStream::connect(addr).await.expect("connect");
        stream
            .write_all(format!("GET {target} HTTP/1.1\r\nHost: metrics\r\n\r\n").as_bytes())
            .await
            .expect("write");
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.expect("read");
        String::from_utf8(response).expect("utf8")
    }

    #[tokio::test]
    async fn serves_metrics_over_http_and_refuses_other_routes() {
        let (exporter, _provider) = sample_provider();
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = tokio::spawn(serve(exporter, listener));

        let ok = http_get(addr, "/metrics").await;
        assert!(ok.starts_with("HTTP/1.1 200 OK\r\n"), "{ok}");
        assert!(ok.contains(&format!("Content-Type: {TEXT_FORMAT}\r\n")));
        assert!(ok.contains("hc_test_workflow_run_total{workflow=\"publish_dht_ops\"} 3\n"));

        let with_query = http_get(addr, "/metrics?format=text").await;
        assert!(with_query.starts_with("HTTP/1.1 200 OK\r\n"));

        let missing = http_get(addr, "/health").await;
        assert!(
            missing.starts_with("HTTP/1.1 404 Not Found\r\n"),
            "{missing}"
        );

        let mut stream = TcpStream::connect(addr).await.expect("connect");
        stream
            .write_all(b"POST /metrics HTTP/1.1\r\nHost: metrics\r\n\r\n")
            .await
            .expect("write");
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.expect("read");
        assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 405 "));

        server.abort();
    }
}
