//! Captures the git commit at build time and exposes it to the crate via the
//! `QOS_GIT_COMMIT` env var. Reads `QOS_GIT_COMMIT` from the environment if
//! set (intended for hermetic builds like `StageX` where the caller injects it),
//! otherwise falls back to `git rev-parse --short HEAD` for dev builds, and
//! finally to `"unknown"` if neither is available.

use std::process::Command;

fn main() {
	println!("cargo:rerun-if-env-changed=QOS_GIT_COMMIT");

	let commit = std::env::var("QOS_GIT_COMMIT")
		.ok()
		.or_else(git_short_sha)
		.unwrap_or_else(|| "unknown".to_string());

	println!("cargo:rustc-env=QOS_GIT_COMMIT={commit}");
}

fn git_short_sha() -> Option<String> {
	let out = Command::new("git")
		.args(["rev-parse", "--short", "HEAD"])
		.output()
		.ok()?;
	if !out.status.success() {
		return None;
	}
	let s = String::from_utf8(out.stdout).ok()?.trim().to_string();
	if s.is_empty() { None } else { Some(s) }
}
