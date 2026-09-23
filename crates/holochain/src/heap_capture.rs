//! Bounded admission for sampled heap profiles in an isolated disposable conductor.
//!
//! The native jemalloc traversal is not cancellable. This module bounds admission, arms a
//! process-terminal per-dump timer, and routes the dump to supervisor-owned FIFOs. The external
//! supervisor separately enforces the whole-process deadline, byte cap, EOF, and parser
//! validation. Jemalloc treats a positive short write as success, so even native return + EOF +
//! parse is not described here as a universally complete retained-heap profile. Profiling
//! activates only with the admitted `Before` request, so the pair covers sampled retained
//! allocations since that activation; allocations retained from process startup are outside its
//! evidence boundary.

#[cfg(all(target_os = "linux", feature = "jemalloc-prof"))]
use holochain_conductor_api::DiagnosticNativeProcess;
use holochain_conductor_api::{
    HeapCaptureFailure, HeapCaptureReceipt, HeapCaptureRefusal, HeapCaptureRequest,
};
#[cfg(any(test, all(target_os = "linux", feature = "jemalloc-prof")))]
use holochain_conductor_api::{HeapCapturePhase, DIAGNOSTIC_CAPTURE_SCHEMA_VERSION};
use std::sync::OnceLock;
use std::time::Duration;
#[cfg(any(test, all(target_os = "linux", feature = "jemalloc-prof")))]
use std::time::Instant;

const CANARY_DIR_ENV: &str = "HOLOCHAIN_HEAP_CANARY_DIR";
const CANARY_WINDOW_ENV: &str = "HOLOCHAIN_HEAP_CANARY_WINDOW_SECONDS";
const CANARY_DUMP_TIMEOUT_ENV: &str = "HOLOCHAIN_HEAP_CANARY_DUMP_TIMEOUT_SECONDS";
const MAX_WINDOW_SECONDS: u64 = 900;
const MAX_DUMP_TIMEOUT_SECONDS: u64 = 30;
#[cfg(any(test, all(target_os = "linux", feature = "jemalloc-prof")))]
const MAX_NONCE_BYTES: usize = 64;
#[cfg(all(target_os = "linux", feature = "jemalloc-prof"))]
const BEFORE_BASENAME: &str = "before.heap.fifo";
#[cfg(all(target_os = "linux", feature = "jemalloc-prof"))]
const AFTER_BASENAME: &str = "after.heap.fifo";

static SERVICE: OnceLock<Service> = OnceLock::new();

/// Result of applying the process-start heap-capture authorization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeapCaptureStartup {
    /// No heap-capture environment was present.
    Disabled,
    /// The isolated canary was authorized for one pair.
    Enabled,
}

enum Service {
    Disabled,
    #[cfg(all(target_os = "linux", feature = "jemalloc-prof"))]
    Enabled(std::sync::Arc<native::EnabledCapture>),
}

/// Apply heap-capture authorization exactly once, before the async runtime starts.
pub fn initialize_from_env() -> Result<HeapCaptureStartup, HeapCaptureFailure> {
    if SERVICE.get().is_some() {
        return Err(failure(
            HeapCaptureRefusal::InvalidRequest,
            "heap capture startup was initialized more than once",
        ));
    }

    let authorization = parse_startup_authorization(
        std::env::var_os(CANARY_DIR_ENV),
        std::env::var_os(CANARY_WINDOW_ENV),
        std::env::var_os(CANARY_DUMP_TIMEOUT_ENV),
    )?;
    let Some((directory, window, dump_timeout)) = authorization else {
        SERVICE.set(Service::Disabled).map_err(|_| {
            failure(
                HeapCaptureRefusal::InvalidRequest,
                "heap capture startup was initialized more than once",
            )
        })?;
        return Ok(HeapCaptureStartup::Disabled);
    };

    #[cfg(all(target_os = "linux", feature = "jemalloc-prof"))]
    {
        let enabled = std::sync::Arc::new(native::EnabledCapture::new(
            directory,
            window,
            dump_timeout,
        )?);
        SERVICE
            .set(Service::Enabled(enabled.clone()))
            .map_err(|_| {
                failure(
                    HeapCaptureRefusal::InvalidRequest,
                    "heap capture startup was initialized more than once",
                )
            })?;
        enabled.start_expiry_worker()?;
        Ok(HeapCaptureStartup::Enabled)
    }
    #[cfg(not(all(target_os = "linux", feature = "jemalloc-prof")))]
    {
        let _ = (directory, window, dump_timeout);
        Err(failure(
            HeapCaptureRefusal::Unsupported,
            "heap capture requires a Linux jemalloc profiling build",
        ))
    }
}

fn parse_startup_authorization(
    directory: Option<std::ffi::OsString>,
    window: Option<std::ffi::OsString>,
    dump_timeout: Option<std::ffi::OsString>,
) -> Result<Option<(std::ffi::OsString, Duration, Duration)>, HeapCaptureFailure> {
    let (directory, window, dump_timeout) = match (directory, window, dump_timeout) {
        (None, None, None) => return Ok(None),
        (Some(directory), Some(window), Some(dump_timeout)) => (directory, window, dump_timeout),
        _ => {
            return Err(failure(
                HeapCaptureRefusal::InvalidRequest,
                "heap capture startup authorization is incomplete",
            ));
        }
    };
    let window = bounded_startup_seconds(
        &window,
        MAX_WINDOW_SECONDS,
        "heap capture startup window is invalid",
    )?;
    let dump_timeout = bounded_startup_seconds(
        &dump_timeout,
        MAX_DUMP_TIMEOUT_SECONDS,
        "heap capture dump timeout is invalid",
    )?;
    Ok(Some((directory, window, dump_timeout)))
}

fn bounded_startup_seconds(
    value: &std::ffi::OsStr,
    maximum: u64,
    message: &'static str,
) -> Result<Duration, HeapCaptureFailure> {
    value
        .to_str()
        .filter(|value| {
            matches!(value.as_bytes().first(), Some(b'1'..=b'9'))
                && value.as_bytes()[1..].iter().all(u8::is_ascii_digit)
        })
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|seconds| (1..=maximum).contains(seconds))
        .map(Duration::from_secs)
        .ok_or_else(|| failure(HeapCaptureRefusal::InvalidRequest, message))
}

/// Execute one heap-capture phase on a blocking worker.
///
/// A successful receipt means only that jemalloc returned success. The supervisor must
/// independently prove FIFO EOF, byte bound, and parser validity.
pub async fn capture(
    request: HeapCaptureRequest,
) -> Result<HeapCaptureReceipt, HeapCaptureFailure> {
    #[cfg(not(all(target_os = "linux", feature = "jemalloc-prof")))]
    let _ = request;
    let service = SERVICE.get().ok_or_else(|| {
        failure(
            HeapCaptureRefusal::Disabled,
            "heap capture was not authorized at process startup",
        )
    })?;
    match service {
        Service::Disabled => Err(failure(
            HeapCaptureRefusal::Disabled,
            "heap capture was not authorized at process startup",
        )),
        #[cfg(all(target_os = "linux", feature = "jemalloc-prof"))]
        Service::Enabled(enabled) => {
            let enabled = enabled.clone();
            let permit = enabled.admit(request)?;
            let deadline = match enabled.arm_dump_deadline() {
                Ok(deadline) => deadline,
                Err(error) => {
                    enabled.mark_incomplete();
                    return Err(error);
                }
            };
            let worker = enabled.clone();
            match tokio::task::spawn_blocking(move || worker.capture_blocking(permit, deadline))
                .await
            {
                Ok(result) => result,
                Err(_) => {
                    let cleaner = enabled.clone();
                    let _ = tokio::task::spawn_blocking(move || cleaner.mark_incomplete()).await;
                    Err(failure(
                        HeapCaptureRefusal::Incomplete,
                        "heap capture blocking worker did not complete",
                    ))
                }
            }
        }
    }
}

fn failure(refusal: HeapCaptureRefusal, message: &'static str) -> HeapCaptureFailure {
    HeapCaptureFailure {
        refusal,
        message: message.to_owned(),
    }
}

#[cfg(any(test, all(target_os = "linux", feature = "jemalloc-prof")))]
#[derive(Debug, PartialEq, Eq)]
enum CaptureState {
    Idle,
    Busy {
        nonce: String,
        phase: HeapCapturePhase,
        expired: bool,
    },
    BeforeCaptured {
        nonce: String,
    },
    Complete {
        nonce: String,
    },
    Failed {
        nonce: Option<String>,
    },
}

#[cfg(any(test, all(target_os = "linux", feature = "jemalloc-prof")))]
#[derive(Debug)]
struct CapturePermit {
    nonce: String,
    phase: HeapCapturePhase,
}

/// One-pair process-local admission machine.
#[cfg(any(test, all(target_os = "linux", feature = "jemalloc-prof")))]
#[derive(Debug)]
struct CaptureMachine {
    state: CaptureState,
}

#[cfg(any(test, all(target_os = "linux", feature = "jemalloc-prof")))]
impl CaptureMachine {
    fn new() -> Self {
        Self {
            state: CaptureState::Idle,
        }
    }

    fn admit(
        &mut self,
        request: &HeapCaptureRequest,
        now: Instant,
        deadline: Instant,
    ) -> Result<CapturePermit, HeapCaptureRefusal> {
        if matches!(self.state, CaptureState::Busy { .. }) {
            return Err(HeapCaptureRefusal::Busy);
        }
        if request.schema_version != DIAGNOSTIC_CAPTURE_SCHEMA_VERSION
            || !valid_nonce(&request.nonce)
        {
            self.state = CaptureState::Failed { nonce: None };
            return Err(HeapCaptureRefusal::InvalidRequest);
        }
        if now >= deadline {
            self.state = CaptureState::Failed {
                nonce: Some(request.nonce.clone()),
            };
            return Err(HeapCaptureRefusal::Deadline);
        }

        match &self.state {
            CaptureState::Busy { .. } => unreachable!("busy state was handled before validation"),
            CaptureState::Idle if request.phase != HeapCapturePhase::Before => {
                self.state = CaptureState::Failed {
                    nonce: Some(request.nonce.clone()),
                };
                return Err(HeapCaptureRefusal::InvalidSequence);
            }
            CaptureState::Idle => {}
            CaptureState::BeforeCaptured { nonce }
                if nonce == &request.nonce && request.phase == HeapCapturePhase::After => {}
            CaptureState::BeforeCaptured { nonce } => {
                let nonce = nonce.clone();
                self.state = CaptureState::Failed { nonce: Some(nonce) };
                return Err(HeapCaptureRefusal::DuplicateNonce);
            }
            CaptureState::Complete { nonce } | CaptureState::Failed { nonce: Some(nonce) }
                if nonce == &request.nonce =>
            {
                return Err(HeapCaptureRefusal::DuplicateNonce);
            }
            CaptureState::Complete { .. } | CaptureState::Failed { .. } => {
                return Err(HeapCaptureRefusal::GenerationBudget);
            }
        }

        let permit = CapturePermit {
            nonce: request.nonce.clone(),
            phase: request.phase,
        };
        self.state = CaptureState::Busy {
            nonce: permit.nonce.clone(),
            phase: permit.phase,
            expired: false,
        };
        Ok(permit)
    }

    fn finish(&mut self, permit: &CapturePermit, now: Instant, deadline: Instant) -> bool {
        let valid_busy = matches!(
            &self.state,
            CaptureState::Busy {
                nonce,
                phase,
                expired: false,
            } if nonce == &permit.nonce && phase == &permit.phase
        );
        if !valid_busy || now >= deadline {
            self.state = CaptureState::Failed {
                nonce: Some(permit.nonce.clone()),
            };
            return false;
        }
        self.state = match permit.phase {
            HeapCapturePhase::Before => CaptureState::BeforeCaptured {
                nonce: permit.nonce.clone(),
            },
            HeapCapturePhase::After => CaptureState::Complete {
                nonce: permit.nonce.clone(),
            },
        };
        true
    }

    fn fail(&mut self, permit: &CapturePermit) {
        self.state = CaptureState::Failed {
            nonce: Some(permit.nonce.clone()),
        };
    }

    fn expire(&mut self) -> bool {
        match &mut self.state {
            CaptureState::Busy { expired, .. } => {
                *expired = true;
                false
            }
            CaptureState::BeforeCaptured { nonce } => {
                let nonce = nonce.clone();
                self.state = CaptureState::Failed { nonce: Some(nonce) };
                true
            }
            CaptureState::Idle => {
                self.state = CaptureState::Failed { nonce: None };
                false
            }
            CaptureState::Complete { .. } | CaptureState::Failed { .. } => false,
        }
    }
}

#[cfg(any(test, all(target_os = "linux", feature = "jemalloc-prof")))]
fn valid_nonce(nonce: &str) -> bool {
    !nonce.is_empty()
        && nonce.len() <= MAX_NONCE_BYTES
        && nonce.bytes().all(|byte| byte.is_ascii_graphic())
}

#[cfg(all(target_os = "linux", feature = "jemalloc-prof"))]
mod native {
    use super::*;
    use holochain_trace::diagnostic_identity::DiagnosticProcessIdentity;
    use parking_lot::Mutex;
    use std::ffi::{CStr, CString, OsString};
    use std::io;
    use std::mem::{size_of, MaybeUninit};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::path::PathBuf;
    use std::ptr;
    use std::sync::Arc;

    pub(super) struct EnabledCapture {
        machine: Mutex<CaptureMachine>,
        deadline: Instant,
        dump_timeout: Duration,
        identity: DiagnosticProcessIdentity,
        producer_id: String,
        directory: OwnedFd,
        before: PinnedFifo,
        after: PinnedFifo,
    }

    struct PinnedFifo {
        descriptor: OwnedFd,
        basename: &'static str,
    }

    /// One fresh process-directed timer for one admitted native traversal.
    pub(super) struct DumpDeadline {
        timer: Option<libc::timer_t>,
        deadline: libc::timespec,
        started_monotonic_ms: u64,
        deadline_monotonic_ms: u64,
        dump_timeout_ms: u64,
    }

    // SAFETY: Linux `timer_t` is an opaque process-local timer identifier. Moving the identifier
    // does not dereference its pointer representation, and POSIX timer operations are process-wide
    // and may be called from a thread other than the one which created the timer.
    unsafe impl Send for DumpDeadline {}

    impl EnabledCapture {
        pub(super) fn new(
            directory: OsString,
            window: Duration,
            dump_timeout: Duration,
        ) -> Result<Self, HeapCaptureFailure> {
            verify_profiler_startup()?;
            let directory = pin_private_directory(directory)?;
            let before = pin_fifo(&directory, BEFORE_BASENAME)?;
            let after = pin_fifo(&directory, AFTER_BASENAME)?;
            ensure_distinct(&before.descriptor, &after.descriptor)?;
            let identity = DiagnosticProcessIdentity::capture().map_err(|_| {
                failure(
                    HeapCaptureRefusal::Io,
                    "heap capture process identity is unavailable",
                )
            })?;
            Ok(Self {
                machine: Mutex::new(CaptureMachine::new()),
                deadline: Instant::now() + window,
                dump_timeout,
                identity,
                producer_id: uuid::Uuid::new_v4().to_string(),
                directory,
                before,
                after,
            })
        }

        pub(super) fn start_expiry_worker(self: &Arc<Self>) -> Result<(), HeapCaptureFailure> {
            let capture = self.clone();
            std::thread::Builder::new()
                .name("heap-capture-expiry".to_owned())
                .spawn(move || {
                    std::thread::sleep(capture.deadline.saturating_duration_since(Instant::now()));
                    if capture.machine.lock().expire() {
                        let _ = set_prof_active(false);
                    }
                })
                .map(|_| ())
                .map_err(|_| {
                    failure(
                        HeapCaptureRefusal::Io,
                        "heap capture expiry worker could not start",
                    )
                })
        }

        pub(super) fn admit(
            &self,
            request: HeapCaptureRequest,
        ) -> Result<CapturePermit, HeapCaptureFailure> {
            let mut machine = self
                .machine
                .try_lock()
                .ok_or_else(|| failure_for_refusal(HeapCaptureRefusal::Busy))?;
            machine
                .admit(&request, Instant::now(), self.deadline)
                .map_err(failure_for_refusal)
        }

        pub(super) fn arm_dump_deadline(&self) -> Result<DumpDeadline, HeapCaptureFailure> {
            DumpDeadline::arm(self.dump_timeout)
        }

        pub(super) fn capture_blocking(
            &self,
            permit: CapturePermit,
            deadline: DumpDeadline,
        ) -> Result<HeapCaptureReceipt, HeapCaptureFailure> {
            let fifo = match permit.phase {
                HeapCapturePhase::Before => &self.before,
                HeapCapturePhase::After => &self.after,
            };
            let started_monotonic_ms = deadline.started_monotonic_ms;
            let deadline_timespec = deadline.deadline;
            let deadline_monotonic_ms = deadline.deadline_monotonic_ms;
            let dump_timeout_ms = deadline.dump_timeout_ms;

            let native_result = match permit.phase {
                HeapCapturePhase::Before => set_prof_active(true)
                    .and_then(|()| dump_to_pinned_fifo(&self.directory, &fifo.descriptor)),
                HeapCapturePhase::After => dump_to_pinned_fifo(&self.directory, &fifo.descriptor),
            };
            let deactivate_result = match permit.phase {
                HeapCapturePhase::Before if native_result.is_ok() => Ok(()),
                HeapCapturePhase::Before | HeapCapturePhase::After => set_prof_active(false),
            };
            let native_result = native_result.and(deactivate_result);
            let finished_result = if native_result.is_ok() {
                monotonic_timespec().and_then(|finished| {
                    if timespec_after(finished, deadline_timespec) {
                        Err(failure_for_refusal(HeapCaptureRefusal::Deadline))
                    } else {
                        timespec_millis(finished)
                    }
                })
            } else {
                Err(failure(
                    HeapCaptureRefusal::Incomplete,
                    "jemalloc heap traversal did not complete",
                ))
            };
            let deadline_cleanup = deadline.disarm_and_delete();
            if let Err(native_failure) = native_result {
                self.machine.lock().fail(&permit);
                let _ = set_prof_active(false);
                return Err(native_failure);
            }
            if let Err(cleanup_failure) = deadline_cleanup {
                self.machine.lock().fail(&permit);
                let _ = set_prof_active(false);
                return Err(cleanup_failure);
            }
            let finished_monotonic_ms = match finished_result {
                Ok(value) => value,
                Err(error) => {
                    self.machine.lock().fail(&permit);
                    let _ = set_prof_active(false);
                    return Err(error);
                }
            };
            if !self
                .machine
                .lock()
                .finish(&permit, Instant::now(), self.deadline)
            {
                let _ = set_prof_active(false);
                return Err(failure_for_refusal(HeapCaptureRefusal::Deadline));
            }
            Ok(HeapCaptureReceipt {
                schema_version: DIAGNOSTIC_CAPTURE_SCHEMA_VERSION,
                nonce: permit.nonce,
                phase: permit.phase,
                producer_id: self.producer_id.clone(),
                generation: 1,
                artifact_basename: fifo.basename.to_owned(),
                native_process: DiagnosticNativeProcess {
                    schema: 1,
                    process_id: self.identity.process_id,
                    process_start_ticks: self.identity.process_start_ticks,
                    boot_id: self.identity.boot_id.clone(),
                    executable: self.identity.executable.clone(),
                    clock: "CLOCK_MONOTONIC".to_owned(),
                },
                started_monotonic_ms,
                finished_monotonic_ms,
                dump_timeout_ms,
                deadline_monotonic_ms,
                native_completed: true,
            })
        }

        pub(super) fn mark_incomplete(&self) {
            let mut machine = self.machine.lock();
            machine.state = match &machine.state {
                CaptureState::Idle => CaptureState::Failed { nonce: None },
                CaptureState::Busy { nonce, .. }
                | CaptureState::BeforeCaptured { nonce }
                | CaptureState::Complete { nonce } => CaptureState::Failed {
                    nonce: Some(nonce.clone()),
                },
                CaptureState::Failed { nonce } => CaptureState::Failed {
                    nonce: nonce.clone(),
                },
            };
            drop(machine);
            let _ = set_prof_active(false);
        }
    }

    impl DumpDeadline {
        pub(super) fn arm(timeout: Duration) -> Result<Self, HeapCaptureFailure> {
            let mut event = MaybeUninit::<libc::sigevent>::zeroed();
            // SAFETY: zero is a valid baseline for `sigevent`; these public fields select
            // process-directed signal delivery and SIGKILL cannot be caught or ignored.
            let event = unsafe {
                let event = event.assume_init_mut();
                event.sigev_notify = libc::SIGEV_SIGNAL;
                event.sigev_signo = libc::SIGKILL;
                event
            };
            let mut timer = MaybeUninit::<libc::timer_t>::uninit();
            // SAFETY: `event` remains live and `timer` is writable output storage.
            if unsafe { libc::timer_create(libc::CLOCK_MONOTONIC, event, timer.as_mut_ptr()) } != 0
            {
                return Err(timer_failure("heap capture deadline timer is unavailable"));
            }
            // SAFETY: successful timer_create initialized the opaque timer identifier.
            let timer = unsafe { timer.assume_init() };
            let mut guard = Self {
                timer: Some(timer),
                deadline: libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                },
                started_monotonic_ms: 0,
                deadline_monotonic_ms: 0,
                dump_timeout_ms: u64::try_from(timeout.as_millis()).map_err(|_| {
                    timer_failure("heap capture dump timeout cannot be represented")
                })?,
            };
            let now = monotonic_timespec()?;
            let timeout_seconds = libc::time_t::try_from(timeout.as_secs())
                .map_err(|_| timer_failure("heap capture dump timeout cannot be represented"))?;
            let timeout_nanos = libc::c_long::try_from(timeout.subsec_nanos())
                .map_err(|_| timer_failure("heap capture dump timeout cannot be represented"))?;
            let combined_nanos = now
                .tv_nsec
                .checked_add(timeout_nanos)
                .ok_or_else(|| timer_failure("heap capture deadline cannot be represented"))?;
            let carry_seconds = combined_nanos / 1_000_000_000;
            let deadline = libc::timespec {
                tv_sec: now
                    .tv_sec
                    .checked_add(timeout_seconds)
                    .and_then(|value| value.checked_add(carry_seconds))
                    .ok_or_else(|| timer_failure("heap capture deadline cannot be represented"))?,
                tv_nsec: combined_nanos % 1_000_000_000,
            };
            guard.deadline = deadline;
            guard.started_monotonic_ms = timespec_millis(now)?;
            guard.deadline_monotonic_ms = timespec_millis(deadline)?;
            let setting = libc::itimerspec {
                it_interval: libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                },
                it_value: deadline,
            };
            // SAFETY: the timer is live and `setting` is a valid one-shot absolute deadline.
            if unsafe { libc::timer_settime(timer, libc::TIMER_ABSTIME, &setting, ptr::null_mut()) }
                != 0
            {
                return Err(timer_failure(
                    "heap capture deadline timer could not be armed",
                ));
            }
            Ok(guard)
        }

        pub(super) fn disarm_and_delete(mut self) -> Result<(), HeapCaptureFailure> {
            let timer = self
                .timer
                .expect("live dump deadline must contain its timer identifier");
            let disarmed = libc::itimerspec {
                it_interval: libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                },
                it_value: libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                },
            };
            // SAFETY: the timer is live and a zero value disarms it.
            let disarm_result =
                unsafe { libc::timer_settime(timer, 0, &disarmed, ptr::null_mut()) };
            // SAFETY: the timer is still owned by this guard. A successful delete consumes it.
            let delete_result = unsafe { libc::timer_delete(timer) };
            if delete_result == 0 {
                self.timer = None;
            }
            if disarm_result != 0 || delete_result != 0 {
                return Err(timer_failure(
                    "heap capture deadline timer cleanup did not complete",
                ));
            }
            Ok(())
        }
    }

    impl Drop for DumpDeadline {
        fn drop(&mut self) {
            let Some(timer) = self.timer.take() else {
                return;
            };
            let disarmed = libc::itimerspec {
                it_interval: libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                },
                it_value: libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                },
            };
            // SAFETY: best-effort unwind cleanup uses this guard's still-owned timer.
            let _ = unsafe { libc::timer_settime(timer, 0, &disarmed, ptr::null_mut()) };
            // SAFETY: this is the guard's last use of its still-owned timer identifier.
            let _ = unsafe { libc::timer_delete(timer) };
        }
    }

    fn monotonic_timespec() -> Result<libc::timespec, HeapCaptureFailure> {
        let mut now = MaybeUninit::<libc::timespec>::uninit();
        // SAFETY: `now` is writable storage initialized by a successful clock_gettime call.
        if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, now.as_mut_ptr()) } != 0 {
            return Err(timer_failure("heap capture deadline clock is unavailable"));
        }
        // SAFETY: successful clock_gettime initialized the complete timespec.
        let now = unsafe { now.assume_init() };
        if now.tv_sec < 0 || !(0..1_000_000_000).contains(&now.tv_nsec) {
            return Err(timer_failure("heap capture deadline clock is invalid"));
        }
        Ok(now)
    }

    fn timespec_millis(value: libc::timespec) -> Result<u64, HeapCaptureFailure> {
        let seconds = u64::try_from(value.tv_sec)
            .map_err(|_| timer_failure("heap capture deadline cannot be represented"))?;
        let nanos = u64::try_from(value.tv_nsec)
            .map_err(|_| timer_failure("heap capture deadline cannot be represented"))?;
        seconds
            .checked_mul(1_000)
            .and_then(|value| value.checked_add(nanos / 1_000_000))
            .ok_or_else(|| timer_failure("heap capture deadline cannot be represented"))
    }

    fn timespec_after(left: libc::timespec, right: libc::timespec) -> bool {
        left.tv_sec > right.tv_sec || (left.tv_sec == right.tv_sec && left.tv_nsec > right.tv_nsec)
    }

    fn timer_failure(message: &'static str) -> HeapCaptureFailure {
        failure(HeapCaptureRefusal::Io, message)
    }

    fn failure_for_refusal(refusal: HeapCaptureRefusal) -> HeapCaptureFailure {
        let message = match refusal {
            HeapCaptureRefusal::Disabled => "heap capture is disabled",
            HeapCaptureRefusal::Busy => "heap capture is busy",
            HeapCaptureRefusal::DuplicateNonce => "heap capture nonce was already consumed",
            HeapCaptureRefusal::GenerationBudget => "heap capture pair budget is exhausted",
            HeapCaptureRefusal::InvalidRequest => "heap capture request is invalid",
            HeapCaptureRefusal::Unsupported => "heap capture is unsupported",
            HeapCaptureRefusal::ProfilerUnavailable => "jemalloc profiling is unavailable",
            HeapCaptureRefusal::InvalidSequence => "heap capture phase sequence is invalid",
            HeapCaptureRefusal::Deadline => "heap capture authorization has expired",
            HeapCaptureRefusal::ByteLimit => "heap capture collector byte limit was exceeded",
            HeapCaptureRefusal::Io => "heap capture private I/O failed",
            HeapCaptureRefusal::Incomplete => "heap capture native completion is incomplete",
        };
        failure(refusal, message)
    }

    fn pin_private_directory(directory: OsString) -> Result<OwnedFd, HeapCaptureFailure> {
        let requested = PathBuf::from(directory);
        if !requested.is_absolute() {
            return Err(failure(
                HeapCaptureRefusal::InvalidRequest,
                "heap capture private directory must be absolute",
            ));
        }
        let canonical = std::fs::canonicalize(&requested).map_err(|_| {
            failure(
                HeapCaptureRefusal::Io,
                "heap capture private directory is unavailable",
            )
        })?;
        if requested.as_os_str().as_bytes() != canonical.as_os_str().as_bytes() {
            return Err(failure(
                HeapCaptureRefusal::InvalidRequest,
                "heap capture private directory must be canonical",
            ));
        }
        let path = CString::new(canonical.as_os_str().as_bytes()).map_err(|_| {
            failure(
                HeapCaptureRefusal::InvalidRequest,
                "heap capture private directory is invalid",
            )
        })?;
        // SAFETY: `path` is NUL-terminated and remains live for this synchronous syscall.
        let fd = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        let directory = owned_fd(fd).map_err(|_| {
            failure(
                HeapCaptureRefusal::Io,
                "heap capture private directory could not be pinned",
            )
        })?;
        let stat = descriptor_stat(&directory)?;
        if stat.st_mode & libc::S_IFMT != libc::S_IFDIR
            || stat.st_mode & 0o7777 != 0o700
            // SAFETY: `geteuid` has no preconditions.
            || stat.st_uid != unsafe { libc::geteuid() }
        {
            return Err(failure(
                HeapCaptureRefusal::InvalidRequest,
                "heap capture private directory permissions are invalid",
            ));
        }
        Ok(directory)
    }

    fn pin_fifo(
        directory: &OwnedFd,
        basename: &'static str,
    ) -> Result<PinnedFifo, HeapCaptureFailure> {
        let name = CString::new(basename).expect("fixed FIFO basename contains no NUL");
        // SAFETY: the directory descriptor and fixed NUL-terminated basename remain live.
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        let descriptor = owned_fd(fd).map_err(|_| {
            failure(
                HeapCaptureRefusal::Io,
                "heap capture FIFO could not be pinned",
            )
        })?;
        let stat = descriptor_stat(&descriptor)?;
        if stat.st_mode & libc::S_IFMT != libc::S_IFIFO
            || stat.st_mode & 0o077 != 0
            || stat.st_nlink != 1
            // SAFETY: `geteuid` has no preconditions.
            || stat.st_uid != unsafe { libc::geteuid() }
        {
            return Err(failure(
                HeapCaptureRefusal::InvalidRequest,
                "heap capture FIFO identity or permissions are invalid",
            ));
        }
        Ok(PinnedFifo {
            descriptor,
            basename,
        })
    }

    fn ensure_distinct(before: &OwnedFd, after: &OwnedFd) -> Result<(), HeapCaptureFailure> {
        let before = descriptor_stat(before)?;
        let after = descriptor_stat(after)?;
        if before.st_dev == after.st_dev && before.st_ino == after.st_ino {
            return Err(failure(
                HeapCaptureRefusal::InvalidRequest,
                "heap capture phase FIFOs must be distinct",
            ));
        }
        Ok(())
    }

    fn descriptor_stat(descriptor: &OwnedFd) -> Result<libc::stat, HeapCaptureFailure> {
        let mut stat = MaybeUninit::<libc::stat>::uninit();
        // SAFETY: `stat` points to writable, correctly aligned storage and the descriptor is live.
        if unsafe { libc::fstat(descriptor.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
            return Err(failure(
                HeapCaptureRefusal::Io,
                "heap capture descriptor identity is unavailable",
            ));
        }
        // SAFETY: successful `fstat` initialized the complete structure.
        Ok(unsafe { stat.assume_init() })
    }

    fn owned_fd(fd: libc::c_int) -> io::Result<OwnedFd> {
        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            // SAFETY: a nonnegative successful open result is a newly owned descriptor.
            Ok(unsafe { OwnedFd::from_raw_fd(fd) })
        }
    }

    fn verify_profiler_startup() -> Result<(), HeapCaptureFailure> {
        if !mallctl_read::<bool>(c"config.prof")?
            || !mallctl_read::<bool>(c"opt.prof")?
            || mallctl_read::<bool>(c"prof.active")?
            || mallctl_read::<bool>(c"opt.prof_gdump")?
            || mallctl_read::<bool>(c"opt.prof_final")?
            || mallctl_read::<libc::ssize_t>(c"opt.lg_prof_interval")? != -1
        {
            return Err(failure(
                HeapCaptureRefusal::ProfilerUnavailable,
                "jemalloc profiler startup controls are unsafe",
            ));
        }
        mallctl_write(c"prof.gdump", false)?;
        mallctl_write(c"prof.active", false)?;
        if mallctl_read::<bool>(c"prof.gdump")? || mallctl_read::<bool>(c"prof.active")? {
            return Err(failure(
                HeapCaptureRefusal::ProfilerUnavailable,
                "jemalloc automatic profiling could not be disabled",
            ));
        }
        Ok(())
    }

    fn set_prof_active(active: bool) -> Result<(), HeapCaptureFailure> {
        mallctl_write(c"prof.active", active)?;
        if mallctl_read::<bool>(c"prof.active")? != active {
            return Err(failure(
                HeapCaptureRefusal::ProfilerUnavailable,
                "jemalloc profiler state could not be verified",
            ));
        }
        Ok(())
    }

    fn mallctl_read<T: Copy>(name: &CStr) -> Result<T, HeapCaptureFailure> {
        // ABI verified against the exact Cargo.lock resolution:
        // tikv-jemalloc-sys 0.6.1+5.3.0-1-ge13ca993e8ccb9ba9847cc330696e02839f328f7.
        let mut value = MaybeUninit::<T>::uninit();
        let mut length = size_of::<T>();
        // SAFETY: jemalloc writes at most `length` bytes to correctly aligned `value`; both
        // pointers remain live for the call and the control name is NUL-terminated.
        let result = unsafe {
            tikv_jemalloc_sys::mallctl(
                name.as_ptr(),
                value.as_mut_ptr().cast(),
                &mut length,
                ptr::null_mut(),
                0,
            )
        };
        if result != 0 || length != size_of::<T>() {
            return Err(failure(
                HeapCaptureRefusal::ProfilerUnavailable,
                "jemalloc profiler control is unavailable",
            ));
        }
        // SAFETY: successful mallctl initialized exactly `size_of::<T>()` bytes.
        Ok(unsafe { value.assume_init() })
    }

    fn mallctl_write<T>(name: &CStr, mut value: T) -> Result<(), HeapCaptureFailure> {
        // SAFETY: jemalloc reads exactly `size_of::<T>()` bytes from a live, aligned value and
        // the control name is NUL-terminated.
        let result = unsafe {
            tikv_jemalloc_sys::mallctl(
                name.as_ptr(),
                ptr::null_mut(),
                ptr::null_mut(),
                (&mut value as *mut T).cast(),
                size_of::<T>(),
            )
        };
        if result != 0 {
            return Err(failure(
                HeapCaptureRefusal::ProfilerUnavailable,
                "jemalloc profiler control update failed",
            ));
        }
        Ok(())
    }

    fn dump_to_pinned_fifo(
        directory: &OwnedFd,
        descriptor: &OwnedFd,
    ) -> Result<(), HeapCaptureFailure> {
        let directory_stat = descriptor_stat(directory)?;
        if directory_stat.st_mode & libc::S_IFMT != libc::S_IFDIR
            || directory_stat.st_mode & 0o7777 != 0o700
            // SAFETY: `geteuid` has no preconditions.
            || directory_stat.st_uid != unsafe { libc::geteuid() }
        {
            return Err(failure(
                HeapCaptureRefusal::InvalidRequest,
                "heap capture pinned directory is no longer private",
            ));
        }
        let stat = descriptor_stat(descriptor)?;
        if stat.st_mode & libc::S_IFMT != libc::S_IFIFO
            || stat.st_mode & 0o077 != 0
            || stat.st_nlink != 1
            // SAFETY: `geteuid` has no preconditions.
            || stat.st_uid != unsafe { libc::geteuid() }
        {
            return Err(failure(
                HeapCaptureRefusal::InvalidRequest,
                "heap capture pinned FIFO is no longer private",
            ));
        }
        let path = CString::new(format!("/proc/self/fd/{}", descriptor.as_raw_fd()))
            .expect("numeric proc descriptor path contains no NUL");
        let mut path_pointer = path.as_ptr();
        with_async_signals_blocked(|| {
            // SAFETY: `path_pointer` points to the live NUL-terminated procfd path for the
            // startup-pinned FIFO. The pointer-to-pointer ABI is jemalloc's `prof.dump` contract.
            let result = unsafe {
                tikv_jemalloc_sys::mallctl(
                    c"prof.dump".as_ptr(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    (&mut path_pointer as *mut *const libc::c_char).cast(),
                    size_of::<*const libc::c_char>(),
                )
            };
            if result == 0 {
                Ok(())
            } else {
                Err(failure(
                    HeapCaptureRefusal::Incomplete,
                    "jemalloc heap traversal did not complete",
                ))
            }
        })
    }

    pub(super) fn with_async_signals_blocked<T>(
        operation: impl FnOnce() -> Result<T, HeapCaptureFailure>,
    ) -> Result<T, HeapCaptureFailure> {
        let mut blocked = MaybeUninit::<libc::sigset_t>::uninit();
        // SAFETY: `blocked` is writable and initialized by `sigfillset`. The synchronous fault
        // signals are removed below; blocking the remaining maskable asynchronous signals on
        // this worker prevents EINTR-induced short writes. SIGKILL stays available to the
        // external hard-deadline supervisor.
        if unsafe { libc::sigfillset(blocked.as_mut_ptr()) } != 0 {
            return Err(failure(
                HeapCaptureRefusal::Io,
                "heap capture signal mask setup failed",
            ));
        }
        // SAFETY: `sigfillset` initialized `blocked` above.
        let mut blocked = unsafe { blocked.assume_init() };
        for signal in [
            libc::SIGKILL,
            libc::SIGSTOP,
            libc::SIGILL,
            libc::SIGTRAP,
            libc::SIGABRT,
            libc::SIGBUS,
            libc::SIGFPE,
            libc::SIGSEGV,
            libc::SIGSYS,
        ] {
            // SAFETY: `blocked` is initialized and writable; every listed signal is valid.
            if unsafe { libc::sigdelset(&mut blocked, signal) } != 0 {
                return Err(failure(
                    HeapCaptureRefusal::Io,
                    "heap capture signal mask setup failed",
                ));
            }
        }
        let mut sigpipe = MaybeUninit::<libc::sigset_t>::uninit();
        // SAFETY: `sigpipe` is writable and then initialized by sigemptyset/sigaddset.
        if unsafe { libc::sigemptyset(sigpipe.as_mut_ptr()) } != 0 {
            return Err(failure(
                HeapCaptureRefusal::Io,
                "heap capture signal mask setup failed",
            ));
        }
        // SAFETY: sigemptyset initialized the signal set.
        let mut sigpipe = unsafe { sigpipe.assume_init() };
        // SAFETY: `sigpipe` is initialized and writable; SIGPIPE is valid.
        if unsafe { libc::sigaddset(&mut sigpipe, libc::SIGPIPE) } != 0 {
            return Err(failure(
                HeapCaptureRefusal::Io,
                "heap capture signal mask setup failed",
            ));
        }
        let mut old = MaybeUninit::<libc::sigset_t>::uninit();
        // SAFETY: both sets are live; pthread_sigmask initializes `old` on success and changes
        // only the calling blocking worker's mask.
        let mask_result =
            unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &blocked, old.as_mut_ptr()) };
        if mask_result != 0 {
            return Err(failure(
                HeapCaptureRefusal::Io,
                "heap capture signal mask could not be applied",
            ));
        }
        // SAFETY: successful pthread_sigmask initialized `old`.
        let old = unsafe { old.assume_init() };
        let mut guard = SignalMaskGuard {
            old,
            restored: false,
        };
        let pending_before = sigpipe_pending()?;
        let operation_result = operation();
        let drain_result = if pending_before {
            Ok(())
        } else {
            drain_sigpipe(&sigpipe)
        };
        guard.restore()?;
        // Preserve the native operation result when signal cleanup succeeds. If both fail, the
        // operation refusal is the primary capture outcome; the bounded cleanup cannot recover it.
        match (operation_result, drain_result) {
            (Err(operation_error), _) => Err(operation_error),
            (Ok(_), Err(drain_error)) => Err(drain_error),
            (Ok(value), Ok(())) => Ok(value),
        }
    }

    struct SignalMaskGuard {
        old: libc::sigset_t,
        restored: bool,
    }

    impl SignalMaskGuard {
        fn restore(&mut self) -> Result<(), HeapCaptureFailure> {
            // SAFETY: `old` is the mask returned for this thread by pthread_sigmask.
            let result =
                unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &self.old, ptr::null_mut()) };
            if result != 0 {
                return Err(failure(
                    HeapCaptureRefusal::Io,
                    "heap capture signal mask could not be restored",
                ));
            }
            self.restored = true;
            Ok(())
        }
    }

    impl Drop for SignalMaskGuard {
        fn drop(&mut self) {
            if !self.restored {
                // SAFETY: best-effort unwind restoration uses the mask captured on this thread.
                let _ =
                    unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &self.old, ptr::null_mut()) };
            }
        }
    }

    pub(super) fn sigpipe_pending() -> Result<bool, HeapCaptureFailure> {
        let mut pending = MaybeUninit::<libc::sigset_t>::uninit();
        // SAFETY: `pending` is writable and initialized by sigpending on success.
        if unsafe { libc::sigpending(pending.as_mut_ptr()) } != 0 {
            return Err(failure(
                HeapCaptureRefusal::Io,
                "heap capture pending signal state is unavailable",
            ));
        }
        // SAFETY: successful sigpending initialized `pending`.
        let pending = unsafe { pending.assume_init() };
        // SAFETY: `pending` is initialized; SIGPIPE is a valid signal number.
        Ok(unsafe { libc::sigismember(&pending, libc::SIGPIPE) } == 1)
    }

    fn drain_sigpipe(set: &libc::sigset_t) -> Result<(), HeapCaptureFailure> {
        let timeout = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        loop {
            // SAFETY: SIGPIPE remains blocked on this thread, and both input pointers are live.
            let result = unsafe { libc::sigtimedwait(set, ptr::null_mut(), &timeout) };
            if result == libc::SIGPIPE {
                continue;
            }
            if result == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::EAGAIN) {
                return Ok(());
            }
            return Err(failure(
                HeapCaptureRefusal::Io,
                "heap capture pending signal could not be drained",
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(nonce: &str, phase: HeapCapturePhase) -> HeapCaptureRequest {
        HeapCaptureRequest {
            schema_version: DIAGNOSTIC_CAPTURE_SCHEMA_VERSION,
            nonce: nonce.to_owned(),
            phase,
        }
    }

    #[test]
    fn startup_authorization_requires_bounded_complete_timer_configuration() {
        assert!(parse_startup_authorization(None, None, None)
            .unwrap()
            .is_none());
        for values in [
            (Some("/private"), Some("900"), None),
            (Some("/private"), None, Some("30")),
            (None, Some("900"), Some("30")),
        ] {
            assert_eq!(
                parse_startup_authorization(
                    values.0.map(Into::into),
                    values.1.map(Into::into),
                    values.2.map(Into::into),
                )
                .unwrap_err()
                .refusal,
                HeapCaptureRefusal::InvalidRequest
            );
        }
        for timeout in ["0", "01", "+1", " 1", "31", "1.5", "not-a-number"] {
            assert_eq!(
                parse_startup_authorization(
                    Some("/private".into()),
                    Some("900".into()),
                    Some(timeout.into()),
                )
                .unwrap_err()
                .refusal,
                HeapCaptureRefusal::InvalidRequest
            );
        }
        let (_, window, timeout) = parse_startup_authorization(
            Some("/private".into()),
            Some("900".into()),
            Some("30".into()),
        )
        .unwrap()
        .unwrap();
        assert_eq!(window, Duration::from_secs(900));
        assert_eq!(timeout, Duration::from_secs(30));
    }

    #[test]
    fn capture_machine_allows_exactly_one_ordered_pair() {
        let now = Instant::now();
        let deadline = now + Duration::from_secs(10);
        let mut machine = CaptureMachine::new();
        let before = machine
            .admit(
                &request("opaque-1", HeapCapturePhase::Before),
                now,
                deadline,
            )
            .unwrap();
        assert_eq!(
            machine
                .admit(&request("opaque-1", HeapCapturePhase::After), now, deadline)
                .unwrap_err(),
            HeapCaptureRefusal::Busy
        );
        assert!(machine.finish(&before, now, deadline));
        let after = machine
            .admit(&request("opaque-1", HeapCapturePhase::After), now, deadline)
            .unwrap();
        assert!(machine.finish(&after, now, deadline));
        assert_eq!(
            machine
                .admit(&request("opaque-1", HeapCapturePhase::After), now, deadline)
                .unwrap_err(),
            HeapCaptureRefusal::DuplicateNonce
        );
        assert_eq!(
            machine
                .admit(
                    &request("opaque-2", HeapCapturePhase::Before),
                    now,
                    deadline
                )
                .unwrap_err(),
            HeapCaptureRefusal::GenerationBudget
        );
    }

    #[test]
    fn capture_machine_makes_invalid_sequence_and_expiry_terminal() {
        let now = Instant::now();
        let deadline = now + Duration::from_secs(10);
        let mut inverted = CaptureMachine::new();
        assert_eq!(
            inverted
                .admit(&request("opaque", HeapCapturePhase::After), now, deadline)
                .unwrap_err(),
            HeapCaptureRefusal::InvalidSequence
        );
        assert_eq!(
            inverted
                .admit(&request("new", HeapCapturePhase::Before), now, deadline)
                .unwrap_err(),
            HeapCaptureRefusal::GenerationBudget
        );

        let mut expired = CaptureMachine::new();
        assert_eq!(
            expired
                .admit(
                    &request("opaque", HeapCapturePhase::Before),
                    deadline,
                    deadline
                )
                .unwrap_err(),
            HeapCaptureRefusal::Deadline
        );
        assert_eq!(
            expired
                .admit(&request("new", HeapCapturePhase::Before), now, deadline)
                .unwrap_err(),
            HeapCaptureRefusal::GenerationBudget
        );

        let mut during_native = CaptureMachine::new();
        let permit = during_native
            .admit(&request("opaque", HeapCapturePhase::Before), now, deadline)
            .unwrap();
        assert!(!during_native.expire());
        assert!(!during_native.finish(&permit, now, deadline));
        assert_eq!(
            during_native
                .admit(&request("new", HeapCapturePhase::Before), now, deadline)
                .unwrap_err(),
            HeapCaptureRefusal::GenerationBudget
        );

        let mut native_failure = CaptureMachine::new();
        let permit = native_failure
            .admit(&request("opaque", HeapCapturePhase::Before), now, deadline)
            .unwrap();
        native_failure.fail(&permit);
        assert_eq!(
            native_failure
                .admit(&request("opaque", HeapCapturePhase::Before), now, deadline)
                .unwrap_err(),
            HeapCaptureRefusal::DuplicateNonce
        );

        let mut duplicate_phase = CaptureMachine::new();
        let permit = duplicate_phase
            .admit(&request("opaque", HeapCapturePhase::Before), now, deadline)
            .unwrap();
        assert!(duplicate_phase.finish(&permit, now, deadline));
        assert_eq!(
            duplicate_phase
                .admit(&request("opaque", HeapCapturePhase::Before), now, deadline)
                .unwrap_err(),
            HeapCaptureRefusal::DuplicateNonce
        );
        assert_eq!(
            duplicate_phase
                .admit(&request("opaque", HeapCapturePhase::After), now, deadline)
                .unwrap_err(),
            HeapCaptureRefusal::DuplicateNonce
        );
    }

    #[test]
    fn capture_machine_rejects_unbounded_or_non_ascii_nonce() {
        let now = Instant::now();
        let deadline = now + Duration::from_secs(10);
        let too_long = "x".repeat(MAX_NONCE_BYTES + 1);
        for nonce in ["", "\n", "é", too_long.as_str()] {
            let mut machine = CaptureMachine::new();
            assert_eq!(
                machine
                    .admit(&request(nonce, HeapCapturePhase::Before), now, deadline)
                    .unwrap_err(),
                HeapCaptureRefusal::InvalidRequest
            );
            assert_eq!(machine.state, CaptureState::Failed { nonce: None });
        }
    }

    #[cfg(all(target_os = "linux", feature = "jemalloc-prof"))]
    #[test]
    fn procfd_creat_targets_pinned_fifo_after_path_replacement() {
        use std::ffi::CString;
        use std::io::{Read, Write};
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        use std::os::unix::ffi::OsStrExt;

        let scratch = tempfile::tempdir().unwrap();
        let fifo_path = scratch.path().join(BEFORE_BASENAME);
        let fifo = CString::new(fifo_path.as_os_str().as_bytes()).unwrap();
        // SAFETY: `fifo` is a live NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        // SAFETY: `fifo` is live; the successful result is immediately owned below.
        let pinned = unsafe { libc::open(fifo.as_ptr(), libc::O_PATH | libc::O_NOFOLLOW) };
        assert!(pinned >= 0);
        // SAFETY: `pinned` is a newly opened descriptor.
        let pinned = unsafe { OwnedFd::from_raw_fd(pinned) };
        // SAFETY: a nonblocking reader plus anchor avoids blocking either side.
        let reader = unsafe { libc::open(fifo.as_ptr(), libc::O_RDONLY | libc::O_NONBLOCK) };
        assert!(reader >= 0);
        // SAFETY: `reader` is newly opened.
        let mut reader = unsafe { std::fs::File::from_raw_fd(reader) };
        // SAFETY: the reader is open, so the nonblocking anchor can open.
        let anchor = unsafe { libc::open(fifo.as_ptr(), libc::O_WRONLY | libc::O_NONBLOCK) };
        assert!(anchor >= 0);
        // SAFETY: `anchor` is newly opened.
        let _anchor = unsafe { OwnedFd::from_raw_fd(anchor) };

        std::fs::remove_file(&fifo_path).unwrap();
        std::fs::File::create(&fifo_path).unwrap();
        let procfd = CString::new(format!("/proc/self/fd/{}", pinned.as_raw_fd())).unwrap();
        // SAFETY: procfd is live and resolves to the pinned FIFO inode.
        let writer = unsafe { libc::creat(procfd.as_ptr(), 0o600) };
        assert!(writer >= 0);
        // SAFETY: `writer` is newly opened.
        let mut writer = unsafe { std::fs::File::from_raw_fd(writer) };
        writer.write_all(b"pinned").unwrap();
        let mut observed = [0_u8; 6];
        reader.read_exact(&mut observed).unwrap();
        assert_eq!(&observed, b"pinned");
        assert_eq!(std::fs::metadata(&fifo_path).unwrap().len(), 0);
    }

    #[cfg(all(target_os = "linux", feature = "jemalloc-prof"))]
    #[test]
    fn sigpipe_mask_is_thread_local_restored_and_drained() {
        use std::mem::MaybeUninit;
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

        let mut descriptors = [0; 2];
        // SAFETY: `descriptors` is writable storage for two pipe descriptors.
        assert_eq!(unsafe { libc::pipe(descriptors.as_mut_ptr()) }, 0);
        // SAFETY: successful pipe returned two newly owned descriptors.
        let read_end = unsafe { OwnedFd::from_raw_fd(descriptors[0]) };
        // SAFETY: successful pipe returned two newly owned descriptors.
        let write_end = unsafe { OwnedFd::from_raw_fd(descriptors[1]) };
        drop(read_end);

        let mut before = MaybeUninit::<libc::sigset_t>::uninit();
        // SAFETY: a null set reads the current mask into writable `before`.
        assert_eq!(
            unsafe {
                libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), before.as_mut_ptr())
            },
            0
        );
        // SAFETY: pthread_sigmask initialized `before`.
        let before = unsafe { before.assume_init() };
        let result = native::with_async_signals_blocked(|| {
            // SAFETY: the descriptor is live; the read end is deliberately closed.
            let result = unsafe { libc::write(write_end.as_raw_fd(), b"x".as_ptr().cast(), 1) };
            assert_eq!(result, -1);
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EPIPE)
            );
            Ok(())
        });
        assert!(result.is_ok());
        assert!(!native::sigpipe_pending().unwrap());

        let mut after = MaybeUninit::<libc::sigset_t>::uninit();
        // SAFETY: a null set reads the current mask into writable `after`.
        assert_eq!(
            unsafe {
                libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), after.as_mut_ptr())
            },
            0
        );
        // SAFETY: pthread_sigmask initialized `after`.
        let after = unsafe { after.assume_init() };
        // SAFETY: both signal sets are initialized.
        assert_eq!(
            unsafe { libc::sigismember(&before, libc::SIGPIPE) },
            unsafe { libc::sigismember(&after, libc::SIGPIPE) }
        );
    }

    #[cfg(all(target_os = "linux", feature = "jemalloc-prof"))]
    #[test]
    fn posix_deadline_subprocess_helper() {
        match std::env::var("HOLOCHAIN_HEAP_TIMER_TEST_HELPER").as_deref() {
            Ok("kill") => {
                let _deadline = native::DumpDeadline::arm(Duration::from_millis(100)).unwrap();
                loop {
                    std::thread::sleep(Duration::from_secs(1));
                }
            }
            Ok("disarm") => {
                native::DumpDeadline::arm(Duration::from_millis(100))
                    .unwrap()
                    .disarm_and_delete()
                    .unwrap();
                std::thread::sleep(Duration::from_millis(250));
            }
            _ => {}
        }
    }

    #[cfg(all(target_os = "linux", feature = "jemalloc-prof"))]
    #[test]
    fn posix_deadline_kills_without_handler_and_disarm_survives() {
        use std::os::unix::process::ExitStatusExt;
        use std::process::{Command, Stdio};

        fn run_helper(mode: &str) -> std::process::ExitStatus {
            let mut child = Command::new(std::env::current_exe().unwrap())
                .arg("--exact")
                .arg("heap_capture::tests::posix_deadline_subprocess_helper")
                .arg("--nocapture")
                .env("HOLOCHAIN_HEAP_TIMER_TEST_HELPER", mode)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let expires = Instant::now() + Duration::from_secs(5);
            loop {
                if let Some(status) = child.try_wait().unwrap() {
                    return status;
                }
                if Instant::now() >= expires {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("POSIX deadline helper exceeded its bounded parent watchdog");
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }

        assert_eq!(run_helper("kill").signal(), Some(libc::SIGKILL));
        assert!(run_helper("disarm").success());
    }
}
