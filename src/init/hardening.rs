//! Apply KSPP sysctls before accepting requests or launching a pivot.
use std::fs;

/// Runtime sysctls the kernel config does not set, as (/proc/sys path, value).
const SYSCTLS: &[(&str, &str)] = &[
	("kernel/kptr_restrict", "2"),
	("kernel/yama/ptrace_scope", "3"),
	("kernel/unprivileged_bpf_disabled", "1"),
	("kernel/oops_limit", "1"),
	("net/core/bpf_jit_harden", "2"),
	("fs/protected_symlinks", "1"),
	("fs/protected_hardlinks", "1"),
	("fs/protected_fifos", "2"),
	("fs/protected_regular", "2"),
];

/// Panics, which aborts boot, if any sysctl does not apply.
pub fn apply() {
	for (key, value) in SYSCTLS {
		let path = format!("/proc/sys/{key}");
		fs::write(&path, value)
			.unwrap_or_else(|e| panic!("sysctl {key}={value}: {e}"));
	}
}
