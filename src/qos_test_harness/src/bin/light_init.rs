use std::process::Command;

fn main() {
	let tcp_host = arg_value("qos_tcp_host").unwrap_or("0.0.0.0".to_string());
	let tcp_port = arg_value("qos_tcp_port").unwrap_or("3001".to_string());
	let status = Command::new("/qos_core")
		.args([
			"--tcp-host",
			&tcp_host,
			"--tcp-port",
			&tcp_port,
			"--mock",
			"--quorum-file",
			"/qos.quorum.key",
			"--pivot-file",
			"/tmp/qos.pivot.bin",
			"--ephemeral-file",
			"/tmp/qos.ephemeral.key",
			"--manifest-file",
			"/tmp/qos.manifest",
		])
		.status()
		.expect("failed to start /qos_core");
	std::process::exit(status.code().unwrap_or(1));
}

fn arg_value(name: &str) -> Option<String> {
	let prefix = format!("{name}=");
	std::env::args()
		.find_map(|arg| arg.strip_prefix(&prefix).map(ToString::to_string))
}
