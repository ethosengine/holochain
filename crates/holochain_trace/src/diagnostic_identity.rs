//! Kernel-derived witnesses for local, ephemeral diagnostic artifacts.
//!
//! These are operational observations, not agent identities or protocol records.
//! They are gathered only when an explicit diagnostic window requests them. A new
//! capture reconstructs them; unavailable observations must never become zeroes.

use std::io;

/// Identity of the native process which produces a diagnostic window.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiagnosticProcessIdentity {
    /// PID in the producer's Linux process namespace.
    pub process_id: u32,
    /// Kernel start ticks from field 22 of `/proc/self/stat`.
    pub process_start_ticks: u64,
    /// Kernel boot identifier, used to reject observations from another boot.
    pub boot_id: String,
    /// Kernel-observed executable path; private capture metadata, not public output.
    pub executable: String,
}

impl DiagnosticProcessIdentity {
    /// Read the current process's kernel identity, or explicitly refuse.
    pub fn capture() -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            let process_id = std::process::id();
            let stat = bounded_text("/proc/self/stat")?;
            let process_start_ticks = start_ticks(&stat, process_id)?;
            let boot_id = bounded_text("/proc/sys/kernel/random/boot_id")?;
            let boot_id = boot_id.trim();
            if boot_id.len() != 36
                || boot_id.chars().enumerate().any(|(i, c)| {
                    if [8, 13, 18, 23].contains(&i) {
                        c != '-'
                    } else {
                        !c.is_ascii_hexdigit()
                    }
                })
            {
                return Err(invalid("invalid kernel boot identity"));
            }
            let executable = std::fs::read_link("/proc/self/exe")?;
            let executable = executable
                .to_str()
                .filter(|value| {
                    value.starts_with('/')
                        && value.len() <= 4096
                        && !value.chars().any(char::is_control)
                })
                .ok_or_else(|| invalid("unrepresentable kernel executable identity"))?;
            Ok(Self {
                process_id,
                process_start_ticks,
                boot_id: boot_id.to_owned(),
                executable: executable.to_owned(),
            })
        }
        #[cfg(not(target_os = "linux"))]
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "native diagnostic identity requires Linux procfs",
        ))
    }

    /// Render the private, versioned identity witness for a diagnostic record.
    pub fn as_json(&self) -> serde_json::Value {
        serde_json::json!({
            "schema": 1,
            "process_id": self.process_id,
            "process_start_ticks": self.process_start_ticks,
            "boot_id": self.boot_id,
            "executable": self.executable,
            "clock": "CLOCK_MONOTONIC"
        })
    }
}

/// Read Linux's shared monotonic clock in milliseconds, not a process-relative epoch.
///
/// Compare only within the same kernel boot. This clock is for cross-process
/// interval binding; wall timestamps remain audit metadata and cannot replace it.
pub fn kernel_monotonic_ms() -> io::Result<f64> {
    #[cfg(target_os = "linux")]
    {
        let mut time = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: `time` is a live, correctly aligned timespec and the pointer is
        // writable for this synchronous syscall. No pointer escapes the call.
        if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut time) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if time.tv_sec < 0 || !(0..1_000_000_000).contains(&time.tv_nsec) {
            return Err(invalid("invalid kernel monotonic clock"));
        }
        let millis = time.tv_sec as f64 * 1000.0 + time.tv_nsec as f64 / 1_000_000.0;
        if !millis.is_finite() || millis > 9_007_199_254_740_991.0 {
            return Err(invalid("kernel monotonic clock is out of range"));
        }
        Ok(millis)
    }
    #[cfg(not(target_os = "linux"))]
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "native diagnostic clock requires Linux",
    ))
}

#[cfg(target_os = "linux")]
fn bounded_text(path: &str) -> io::Result<String> {
    use std::io::Read;
    let mut text = String::new();
    std::fs::File::open(path)?
        .take(8193)
        .read_to_string(&mut text)?;
    if text.len() > 8192 {
        return Err(invalid("kernel identity record exceeds byte bound"));
    }
    Ok(text)
}

#[cfg(any(target_os = "linux", test))]
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(any(target_os = "linux", test))]
fn start_ticks(stat: &str, expected_pid: u32) -> io::Result<u64> {
    let open = stat
        .find('(')
        .ok_or_else(|| invalid("malformed process stat"))?;
    let close = stat
        .rfind(')')
        .filter(|close| *close > open)
        .ok_or_else(|| invalid("malformed process stat"))?;
    if stat[..open].trim().parse::<u32>().ok() != Some(expected_pid) {
        return Err(invalid("process stat identity mismatch"));
    }
    stat[close + 1..]
        .split_whitespace()
        .nth(19)
        .and_then(|field| field.parse::<u64>().ok())
        .filter(|ticks| *ticks <= 9_007_199_254_740_991)
        .ok_or_else(|| invalid("missing or invalid process start ticks"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stat_parser_handles_parentheses_and_checks_identity() {
        let mut fields = vec!["0"; 20];
        fields[0] = "S";
        fields[19] = "4567";
        let record = format!("123 (name with ) and ( chars) {}", fields.join(" "));
        assert_eq!(start_ticks(&record, 123).unwrap(), 4567);
        assert!(start_ticks(&record, 124).is_err());
        assert!(start_ticks("123 (short) S 0", 123).is_err());
        fields[19] = "9007199254740992";
        assert!(start_ticks(&format!("123 (x) {}", fields.join(" ")), 123).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn native_identity_is_stable_and_clock_advances() {
        let before = kernel_monotonic_ms().unwrap();
        let first = DiagnosticProcessIdentity::capture().unwrap();
        let second = DiagnosticProcessIdentity::capture().unwrap();
        let after = kernel_monotonic_ms().unwrap();
        assert_eq!(first, second);
        assert_eq!(first.process_id, std::process::id());
        assert!(after >= before);
        assert_eq!(first.as_json()["clock"], "CLOCK_MONOTONIC");
    }
}
