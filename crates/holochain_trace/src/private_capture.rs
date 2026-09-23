//! Descriptor-pinned private artifact creation for local diagnostic captures.

use std::{
    ffi::CString,
    fs::{File, OpenOptions},
    io,
    path::Path,
};

/// Startup-opened private directory used only through descriptor-relative creation.
pub struct PrivateCaptureDirectory {
    descriptor: File,
    #[cfg(unix)]
    owner_uid: u32,
}

impl PrivateCaptureDirectory {
    #[cfg(test)]
    pub(crate) fn from_descriptor(descriptor: File) -> Self {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let owner_uid = descriptor.metadata().unwrap().uid();
            Self {
                descriptor,
                owner_uid,
            }
        }
        #[cfg(not(unix))]
        Self { descriptor }
    }

    /// Open an existing directory without following its final symlink and require no group/other access.
    #[cfg(unix)]
    pub fn open(path: &Path) -> io::Result<Self> {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        let descriptor = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let metadata = descriptor.metadata()?;
        // SAFETY: `geteuid` has no preconditions and reads process credentials.
        let effective_uid = unsafe { libc::geteuid() };
        if !metadata.is_dir() || metadata.mode() & 0o077 != 0 || metadata.uid() != effective_uid {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "diagnostic directory must be private and process-owned",
            ));
        }
        Ok(Self {
            descriptor,
            owner_uid: metadata.uid(),
        })
    }

    /// Refuse when descriptor-pinned directory creation is unavailable.
    #[cfg(not(unix))]
    pub fn open(_path: &Path) -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "descriptor-pinned private diagnostics require Unix",
        ))
    }

    /// Create one private regular file relative to the pinned directory descriptor.
    #[cfg(unix)]
    pub fn create_new(&self, basename: &str) -> io::Result<File> {
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::os::unix::fs::MetadataExt;
        let metadata = self.descriptor.metadata()?;
        if !metadata.is_dir() || metadata.mode() & 0o077 != 0 || metadata.uid() != self.owner_uid {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "diagnostic directory privacy changed after startup",
            ));
        }
        if basename.is_empty()
            || basename.as_bytes().contains(&b'/')
            || basename.as_bytes().contains(&0)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid private artifact basename",
            ));
        }
        let basename = CString::new(basename).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid private artifact basename",
            )
        })?;
        // SAFETY: both descriptors are owned and valid for this synchronous call; `basename`
        // is NUL-terminated and contains no path separator, and the returned fd is uniquely
        // transferred into `File` exactly once.
        let fd = unsafe {
            libc::openat(
                self.descriptor.as_raw_fd(),
                basename.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` is a fresh successful `openat` result and has no other owner.
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    /// Refuse when descriptor-pinned directory creation is unavailable.
    #[cfg(not(unix))]
    pub fn create_new(&self, _basename: &str) -> io::Result<File> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "descriptor-pinned private diagnostics require Unix",
        ))
    }
}

/// Validate the common diagnostic nonce alphabet and byte bound.
pub fn valid_capture_nonce(nonce: &str) -> bool {
    (1..=64).contains(&nonce.len())
        && nonce
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{fs, io::Write, os::unix::fs::PermissionsExt, time::SystemTime};

    fn private_dir(label: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "holochain-private-capture-{label}-{}-{:?}",
            std::process::id(),
            SystemTime::now()
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    #[test]
    fn create_is_private_exclusive_and_descriptor_pinned() {
        let path = private_dir("pinned");
        let moved = path.with_extension("moved");
        let directory = PrivateCaptureDirectory::open(&path).unwrap();
        fs::rename(&path, &moved).unwrap();
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();

        let mut file = directory.create_new("capture.jsonl").unwrap();
        file.write_all(b"private").unwrap();
        assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0o600);
        assert!(moved.join("capture.jsonl").is_file());
        assert!(!path.join("capture.jsonl").exists());
        assert_eq!(
            directory.create_new("capture.jsonl").unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );

        fs::remove_dir_all(path).unwrap();
        fs::remove_dir_all(moved).unwrap();
    }

    #[test]
    fn nonce_is_bounded_ascii_and_not_a_path() {
        assert!(valid_capture_nonce("capture_1-ok"));
        assert!(!valid_capture_nonce(""));
        assert!(!valid_capture_nonce("../escape"));
        assert!(!valid_capture_nonce(&"x".repeat(65)));
        assert!(!valid_capture_nonce("snowman-☃"));
    }

    #[test]
    fn create_refuses_when_pinned_directory_privacy_changes() {
        let path = private_dir("mode-change");
        let directory = PrivateCaptureDirectory::open(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            directory.create_new("capture.jsonl").unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        fs::remove_dir_all(path).unwrap();
    }
}
