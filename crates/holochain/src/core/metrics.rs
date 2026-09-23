use holo_hash::DnaHash;
use opentelemetry::{global::meter, metrics, KeyValue};
use std::sync::{Arc, OnceLock};

#[cfg(test)]
#[derive(Default)]
struct WorkflowRunTestCounts {
    started: std::sync::atomic::AtomicU64,
    finished: std::sync::atomic::AtomicU64,
    in_flight: std::sync::atomic::AtomicI64,
    complete: std::sync::atomic::AtomicU64,
    dropped: std::sync::atomic::AtomicU64,
    other: std::sync::atomic::AtomicU64,
}

pub(crate) struct WorkflowRunMetrics {
    duration: metrics::Histogram<f64>,
    runs: metrics::Counter<u64>,
    in_flight: metrics::UpDownCounter<i64>,
    attributes: Vec<KeyValue>,
    #[cfg(test)]
    test_counts: Arc<WorkflowRunTestCounts>,
}

impl WorkflowRunMetrics {
    pub fn started(&self, trigger: &'static str) -> WorkflowRunGuard<'_> {
        #[cfg(test)]
        {
            self.test_counts
                .started
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.test_counts
                .in_flight
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        let mut attributes = self.attributes.clone();
        attributes.push(KeyValue::new("trigger", trigger));
        self.runs.add(1, &attributes);
        self.in_flight.add(1, &self.attributes);
        WorkflowRunGuard {
            metrics: self,
            started: std::time::Instant::now(),
            outcome: "dropped",
        }
    }
}

pub(crate) struct WorkflowRunGuard<'a> {
    metrics: &'a WorkflowRunMetrics,
    started: std::time::Instant,
    outcome: &'static str,
}

impl WorkflowRunGuard<'_> {
    pub fn finish(mut self, outcome: &'static str) {
        self.outcome = outcome;
    }
}

impl Drop for WorkflowRunGuard<'_> {
    fn drop(&mut self) {
        #[cfg(test)]
        {
            self.metrics
                .test_counts
                .finished
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.metrics
                .test_counts
                .in_flight
                .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            match self.outcome {
                "complete" => &self.metrics.test_counts.complete,
                "dropped" => &self.metrics.test_counts.dropped,
                _ => &self.metrics.test_counts.other,
            }
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        let mut attributes = self.metrics.attributes.clone();
        attributes.push(KeyValue::new("outcome", self.outcome));
        self.metrics
            .duration
            .record(self.started.elapsed().as_secs_f64(), &attributes);
        self.metrics.in_flight.add(-1, &self.metrics.attributes);
    }
}

#[cfg(test)]
impl WorkflowRunMetrics {
    pub(crate) fn test_counts(&self) -> (u64, u64, i64, u64, u64) {
        use std::sync::atomic::Ordering::SeqCst;
        (
            self.test_counts.started.load(SeqCst),
            self.test_counts.finished.load(SeqCst),
            self.test_counts.in_flight.load(SeqCst),
            self.test_counts.complete.load(SeqCst),
            self.test_counts.dropped.load(SeqCst),
        )
    }
}

pub(crate) fn create_workflow_run_metrics(
    workflow_name: String,
    dna_hash: Arc<DnaHash>,
) -> WorkflowRunMetrics {
    let attributes = vec![
        KeyValue::new("workflow", workflow_name),
        KeyValue::new("dna_hash", dna_hash.to_string()),
    ];
    let meter = meter("hc.conductor");
    WorkflowRunMetrics {
        duration: meter
            .f64_histogram("hc.conductor.workflow.duration")
            .with_unit("s")
            .with_description("Duration of a workflow run, including its terminal outcome")
            .build(),
        runs: meter
            .u64_counter("hc.conductor.workflow.run")
            .with_description("Workflow runs started, classified by their wake source")
            .build(),
        in_flight: meter
            .i64_up_down_counter("hc.conductor.workflow.in_flight")
            .with_description("Workflow runs currently in flight")
            .build(),
        attributes,
        #[cfg(test)]
        test_counts: Arc::default(),
    }
}

pub(crate) type IntegratedOpMetric = metrics::Counter<u64>;

static INTEGRATED_OP_METRIC: OnceLock<IntegratedOpMetric> = OnceLock::new();

pub(crate) fn workflow_integrated_op_metric() -> &'static IntegratedOpMetric {
    INTEGRATED_OP_METRIC.get_or_init(|| {
        meter("hc.conductor")
            .u64_counter("hc.conductor.workflow.integrated_ops")
            .with_description("The number of integrated operations.")
            .build()
    })
}

pub(crate) type OpIntegrationDelayMetric = metrics::Histogram<f64>;

static OP_INTEGRATION_DELAY_METRIC: OnceLock<OpIntegrationDelayMetric> = OnceLock::new();

pub(crate) fn op_integration_delay_metric() -> &'static OpIntegrationDelayMetric {
    OP_INTEGRATION_DELAY_METRIC.get_or_init(|| {
        meter("hc.conductor")
            .f64_histogram("hc.conductor.workflow.integration_delay")
            .with_unit("s")
            .with_description("Time between an op being stored and it being integrated.")
            .build()
    })
}

pub(crate) type OpValidationAttemptsMetric = metrics::Histogram<u64>;

static OP_VALIDATION_ATTEMPTS_METRIC: OnceLock<OpValidationAttemptsMetric> = OnceLock::new();

pub(crate) fn op_validation_attempts_metric() -> &'static OpValidationAttemptsMetric {
    OP_VALIDATION_ATTEMPTS_METRIC.get_or_init(|| {
        meter("hc.conductor")
            .u64_histogram("hc.conductor.workflow.validation_attempts")
            .with_description("Number of validation attempts required to integrate an op.")
            .build()
    })
}

/// Record integration metrics once per source-chain flush that integrated
/// locally-authored ops.
///
/// Locally-authored ops are integrated immediately at source
/// chain flush, bypassing the integration workflow's `summaries` path that
/// records [`op_integration_delay_metric`] / [`op_validation_attempts_metric`]
/// for network-received ops. Authored ops have no integration delay and need no
/// validation retries, so both samples are always zero — a single zeroed sample
/// per flush is therefore enough to keep these histograms exporting for
/// authored data, without recomputing the per-op count here. Per-op emission is
/// left to the future shared inline-integration helper that will own the
/// integrate/publish/metrics step for authored data.
pub(crate) fn record_authored_op_integration(dna_hash: &DnaHash) {
    let attributes = [KeyValue::new("dna_hash", dna_hash.to_string())];
    op_integration_delay_metric().record(0.0, &attributes);
    op_validation_attempts_metric().record(0, &attributes);
}

#[cfg(any(feature = "wasmer-sys-cranelift", feature = "wasmer-sys-llvm"))]
pub(crate) type WasmUsageMetric = metrics::Counter<u64>;

#[cfg(any(feature = "wasmer-sys-cranelift", feature = "wasmer-sys-llvm"))]
static WASM_USAGE_METRIC: OnceLock<WasmUsageMetric> = OnceLock::new();

#[cfg(any(feature = "wasmer-sys-cranelift", feature = "wasmer-sys-llvm"))]
pub(crate) fn ribosome_wasm_usage_metric() -> &'static WasmUsageMetric {
    WASM_USAGE_METRIC.get_or_init(|| {
        meter("hc.ribosome.wasm")
            .u64_counter("hc.ribosome.wasm.usage")
            .with_description("The metered usage of a wasm ribosome.")
            .build()
    })
}

pub(crate) type WasmCallDurationMetric = metrics::Histogram<f64>;

static WASM_CALL_DURATION_METRIC: OnceLock<WasmCallDurationMetric> = OnceLock::new();

pub(crate) fn ribosome_wasm_call_duration_metric() -> &'static WasmCallDurationMetric {
    WASM_CALL_DURATION_METRIC.get_or_init(|| {
        meter("hc.ribosome.wasm")
            .f64_histogram("hc.ribosome.wasm_call.duration")
            .with_unit("s")
            .with_description("The time spent running a wasm call.")
            .build()
    })
}

pub(crate) type ZomeCallDurationMetric = metrics::Histogram<f64>;

static ZOME_CALL_DURATION_METRIC: OnceLock<ZomeCallDurationMetric> = OnceLock::new();

pub(crate) fn ribosome_zome_call_duration_metric() -> &'static ZomeCallDurationMetric {
    ZOME_CALL_DURATION_METRIC.get_or_init(|| {
        meter("hc.ribosome.wasm")
            .f64_histogram("hc.ribosome.zome_call.duration")
            .with_unit("s")
            .with_description("The time spent running a zome call.")
            .build()
    })
}

pub(crate) type HostFnCallDurationMetric = metrics::Histogram<f64>;

static HOST_FN_CALL_DURATION_METRIC: OnceLock<HostFnCallDurationMetric> = OnceLock::new();

pub(crate) fn host_fn_call_duration_metric() -> &'static HostFnCallDurationMetric {
    HOST_FN_CALL_DURATION_METRIC.get_or_init(|| {
        meter("hc.ribosome")
            .f64_histogram("hc.ribosome.host_fn_call.duration")
            .with_unit("s")
            .with_description("The time spent executing a host function call.")
            .build()
    })
}

pub(crate) type EmitSignalMetric = metrics::Counter<u64>;

static EMIT_SIGNAL_METRIC: OnceLock<EmitSignalMetric> = OnceLock::new();

pub(crate) fn emit_signal_metric() -> &'static EmitSignalMetric {
    EMIT_SIGNAL_METRIC.get_or_init(|| {
        meter("hc.ribosome")
            .u64_counter("hc.ribosome.host_fn.emit_signal.count")
            .with_description("The number of local signals emitted.")
            .build()
    })
}

pub(crate) type SendRemoteSignalMetric = metrics::Counter<u64>;

static SEND_REMOTE_SIGNAL_METRIC: OnceLock<SendRemoteSignalMetric> = OnceLock::new();

pub(crate) fn send_remote_signal_metric() -> &'static SendRemoteSignalMetric {
    SEND_REMOTE_SIGNAL_METRIC.get_or_init(|| {
        meter("hc.ribosome")
            .u64_counter("hc.ribosome.host_fn.send_remote_signal")
            .with_description("The number of remote signals sent.")
            .build()
    })
}

pub(crate) type SysValidationMissingDepsMetric = metrics::Gauge<u64>;

static SYS_VALIDATION_MISSING_DEPS_METRIC: OnceLock<SysValidationMissingDepsMetric> =
    OnceLock::new();

/// The number of dependencies sys validation is currently waiting to find.
///
/// This is the number that has to reach zero for the ops in `AwaitingSysDeps` to drain. A value
/// that never falls is the signature of ops referencing data that no peer holds.
pub(crate) fn sys_validation_missing_deps_metric() -> &'static SysValidationMissingDepsMetric {
    SYS_VALIDATION_MISSING_DEPS_METRIC.get_or_init(|| {
        meter("hc.conductor")
            .u64_gauge("hc.conductor.sys_validation.missing_dependencies")
            .with_description("Dependencies sys validation is waiting to find.")
            .build()
    })
}

pub(crate) type SysValidationUnfetchableDepsMetric = metrics::Gauge<u64>;

static SYS_VALIDATION_UNFETCHABLE_DEPS_METRIC: OnceLock<SysValidationUnfetchableDepsMetric> =
    OnceLock::new();

/// The subset of missing dependencies that have failed often enough to be moved to a slow sweep.
///
/// These are neither dropped nor treated as valid. A rising value means the node is holding ops
/// whose dependencies are not obtainable from the current network.
pub(crate) fn sys_validation_unfetchable_deps_metric() -> &'static SysValidationUnfetchableDepsMetric
{
    SYS_VALIDATION_UNFETCHABLE_DEPS_METRIC.get_or_init(|| {
        meter("hc.conductor")
            .u64_gauge("hc.conductor.sys_validation.unfetchable_dependencies")
            .with_description(
                "Missing sys validation dependencies that repeatedly could not be found.",
            )
            .build()
    })
}
