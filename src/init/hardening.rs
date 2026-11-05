//! Apply KSPP runtime policy before accepting requests or launching a pivot.
use std::{
	fs, io,
	path::{Path, PathBuf},
};

const POLICY: &str = include_str!("hardening.sysctl");

fn entries(
	root: &Path,
) -> impl Iterator<Item = (&'static str, &'static str, PathBuf)> {
	POLICY.lines().map(str::trim).filter_map(move |line| {
		if line.is_empty() || line.starts_with('#') {
			return None;
		}
		let (key, value) = line.split_once('=').expect("invalid sysctl policy");
		let key = key.trim();
		let path = root.join(key.replace('.', "/"));
		Some((key, value.trim(), path))
	})
}

fn apply_at(root: &Path) -> io::Result<()> {
	for (key, value, path) in entries(root) {
		(|| {
			fs::write(&path, value)?;
			let actual = fs::read_to_string(&path)?;
			if actual.trim() != value {
				return Err(io::Error::other("sysctl readback mismatch"));
			}
			Ok(())
		})()
		.map_err(|error| {
			io::Error::new(
				error.kind(),
				format!("hardening sysctl {key}={value}: {error}"),
			)
		})?;
	}
	Ok(())
}

pub fn apply() {
	apply_at(Path::new("/proc/sys")).expect("failed to apply kernel hardening");
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::sync::atomic::{AtomicUsize, Ordering};

	static NEXT_ID: AtomicUsize = AtomicUsize::new(0);

	struct Sysctls(PathBuf);
	impl Sysctls {
		fn new() -> Self {
			let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
			let root = std::env::temp_dir()
				.join(format!("qos-sysctls-{}-{id}", std::process::id()));
			fs::create_dir(&root).unwrap();
			for (_, _, path) in entries(&root) {
				fs::create_dir_all(path.parent().unwrap()).unwrap();
				fs::write(path, "0").unwrap();
			}
			Self(root)
		}
	}

	impl Drop for Sysctls {
		fn drop(&mut self) {
			fs::remove_dir_all(&self.0).unwrap();
		}
	}

	#[test]
	fn applies_policy() {
		let sysctls = Sysctls::new();
		apply_at(&sysctls.0).unwrap();
		assert_eq!(
			fs::read_to_string(sysctls.0.join("kernel/kptr_restrict")).unwrap(),
			"2"
		);
		assert_eq!(
			fs::read_to_string(sysctls.0.join("kernel/yama/ptrace_scope"))
				.unwrap(),
			"3"
		);
		assert_eq!(
			fs::read_to_string(sysctls.0.join("fs/protected_regular")).unwrap(),
			"2"
		);
	}

	#[test]
	fn missing_required_control_fails_boot() {
		let error = apply_at(Path::new("/nonexistent-qos-sysctl-root"))
			.expect_err("missing sysctls must fail closed");
		assert_eq!(error.kind(), io::ErrorKind::NotFound);
		assert!(error.to_string().contains("kernel.kptr_restrict=2"));
	}
}
