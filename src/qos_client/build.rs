#![allow(missing_docs)]

use std::process::Command;

fn main() {
	let sha = Command::new("git")
		.args(["rev-parse", "--short", "HEAD"])
		.output()
		.ok()
		.filter(|o| o.status.success())
		.and_then(|o| String::from_utf8(o.stdout).ok())
		.map(|s| s.trim().to_string())
		.unwrap_or_else(|| "unknown".to_string());

	println!("cargo:rustc-env=GIT_SHA={sha}");
	println!("cargo:rerun-if-changed=../.git/HEAD");
}
