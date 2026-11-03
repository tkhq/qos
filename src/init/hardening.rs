//! Apply KSPP runtime policy before accepting requests or launching a pivot.
use std::{fs, io, path::Path};

// A leading '-' permits ENOENT only for sysctls whose interfaces are compiled
// out by hardening.config. Other errors, missing controls, and readback
// mismatches abort boot. See docs/kernel_hardening.md for their dispositions.
const POLICY: &str = include_str!("hardening.sysctl");

fn apply_at(root: &Path) -> io::Result<()> {
	for line in POLICY.lines() {
		let line = line.trim();
		if line.is_empty() || line.starts_with('#') {
			continue;
		}
		let (key, value) = line.split_once('=').expect("invalid sysctl policy");
		let key = key.trim();
		let optional = key.starts_with('-');
		let key = key.trim_start_matches('-');
		let value = value.trim();
		let path = root.join(key.replace('.', "/"));
		let result = (|| {
			fs::write(&path, value)?;
			let actual = fs::read_to_string(&path)?;
			if actual.trim() != value {
				return Err(io::Error::other("sysctl readback mismatch"));
			}
			Ok(())
		})();
		if let Err(error) = result {
			if optional && error.kind() == io::ErrorKind::NotFound {
				continue;
			}
			return Err(io::Error::new(
				error.kind(),
				format!("hardening sysctl {key}={value}: {error}"),
			));
		}
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

	struct Sysctls(std::path::PathBuf);
	impl Sysctls {
		fn new() -> Self {
			let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
			let root = std::env::temp_dir()
				.join(format!("qos-sysctls-{}-{id}", std::process::id()));
			fs::create_dir(&root).unwrap();
			for line in POLICY.lines().map(str::trim) {
				if line.is_empty() || line.starts_with(['#', '-']) {
					continue;
				}
				let (key, _) = line.split_once('=').unwrap();
				let path = root.join(key.trim().replace('.', "/"));
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
	fn applies_policy_when_compiled_out_controls_are_absent() {
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
	fn optional_control_write_errors_still_fail_boot() {
		let sysctls = Sysctls::new();
		// A directory stands in for a control that exists but rejects writes.
		fs::create_dir(sysctls.0.join("kernel/modules_disabled")).unwrap();
		let error = apply_at(&sysctls.0).unwrap_err();
		assert!(error.to_string().contains("kernel.modules_disabled"));
	}

	#[test]
	fn missing_required_control_fails_boot() {
		let error = apply_at(Path::new("/nonexistent-qos-sysctl-root"))
			.expect_err("missing sysctls must fail closed");
		assert_eq!(error.kind(), io::ErrorKind::NotFound);
		assert!(error.to_string().contains("kernel.kptr_restrict=2"));
	}
}
