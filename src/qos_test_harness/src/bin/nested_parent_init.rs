use std::{
	collections::BTreeMap,
	env, fs,
	io::{Read, Write},
	net::TcpStream,
	process::{Child, Command},
	thread,
	time::{Duration, Instant},
};

use qos_system::{dmesg, freopen, mount};

const DEFAULT_CONFIG_PATH: &str = "/work/nested-parent.env";
const HOST_READY_TIMEOUT: Duration = Duration::from_secs(60);
const CHILD_START_DELAY: Duration = Duration::from_millis(500);

fn main() {
	if let Err(err) = run() {
		eprintln!("nested_parent_init failed: {err}");
		std::process::exit(1);
	}
}

fn run() -> Result<(), String> {
	boot_rootfs();
	let config_path =
		env::args().nth(1).unwrap_or_else(|| DEFAULT_CONFIG_PATH.to_string());
	let config = Config::read(&config_path)?;
	dmesg(format!("nested parent init config: {config_path}"));

	let mut children = Vec::new();
	children.push(spawn("vhost-device-vsock", vhost_command(&config)?)?);
	thread::sleep(CHILD_START_DELAY);
	children.push(spawn("qemu-nitro-enclave", inner_qemu_command(&config)?)?);
	thread::sleep(CHILD_START_DELAY);
	children.push(spawn("qos_host", qos_host_command(&config)?)?);
	wait_for_host_ready(&config, &mut children)?;

	run_command("qos_client", qos_client_command(&config)?)?;
	children.push(spawn("qos_bridge", qos_bridge_command(&config)?)?);

	dmesg("nested parent init boot sequence completed".to_string());
	monitor_children(children)
}

fn boot_rootfs() {
	for dir in ["/dev", "/proc", "/run", "/sys", "/sys/fs/cgroup", "/tmp"] {
		let _ = fs::create_dir_all(dir);
	}

	match mount("devtmpfs", "/dev", "devtmpfs", 0, "mode=0755") {
		Ok(()) => dmesg("mounted /dev".to_string()),
		Err(err) => eprintln!("{err}"),
	}
	for dir in ["/dev/pts", "/dev/shm"] {
		let _ = fs::create_dir_all(dir);
	}

	for (src, target, fstype, flags, data) in [
		("devpts", "/dev/pts", "devpts", 0, ""),
		("shm", "/dev/shm", "tmpfs", 0, "mode=0755"),
		("proc", "/proc", "proc", 0, ""),
		("tmpfs", "/run", "tmpfs", 0, "mode=0755"),
		("tmpfs", "/tmp", "tmpfs", 0, "mode=1777"),
		("sysfs", "/sys", "sysfs", 0, ""),
		("cgroup_root", "/sys/fs/cgroup", "tmpfs", 0, "mode=0755"),
	] {
		match mount(src, target, fstype, flags, data) {
			Ok(()) => dmesg(format!("mounted {target}")),
			Err(err) => eprintln!("{err}"),
		}
	}

	for (filename, mode, file) in [
		("/dev/console", "r", 0),
		("/dev/console", "w", 1),
		("/dev/console", "w", 2),
	] {
		if let Err(err) = freopen(filename, mode, file) {
			eprintln!("{err}");
		}
	}
}

fn vhost_command(config: &Config) -> Result<Command, String> {
	let mut command = Command::new(config.required("VHOST_DEVICE_VSOCK")?);
	let guest_cid = config.get_u32("NESTED_GUEST_CID", 4)?;
	let forward_cid = config.get_u32("NESTED_FORWARD_CID", 1)?;
	let forward_listen = config.get("VHOST_FORWARD_LISTEN", "3+3000");
	let socket = config.get("VHOST_SOCKET", "/tmp/qos-nitro-vhost.socket");
	command.arg("--vm").arg(format!(
		"guest-cid={guest_cid},forward-cid={forward_cid},forward-listen={forward_listen},socket={socket}"
	));
	Ok(command)
}

fn inner_qemu_command(config: &Config) -> Result<Command, String> {
	let mut command = Command::new(config.required("INNER_QEMU")?);
	let chardev_id = config.get("INNER_QEMU_CHARDEV_ID", "c");
	command
		.arg("-M")
		.arg(format!(
			"nitro-enclave,vsock={chardev_id},id={}",
			config.get("INNER_QEMU_ID", "qos-test-harness")
		))
		.arg("-kernel")
		.arg(config.get("INNER_EIF", "/work/nitro.eif"))
		.arg("-nographic")
		.arg("-m")
		.arg(config.get("INNER_QEMU_MEMORY", "4G"))
		.arg("-chardev")
		.arg(format!(
			"socket,id={chardev_id},path={}",
			config.get("VHOST_SOCKET", "/tmp/qos-nitro-vhost.socket")
		));

	if config.get_bool("INNER_QEMU_ENABLE_KVM", false)? {
		command.arg("--enable-kvm").arg("-cpu").arg("host");
	}
	Ok(command)
}

fn qos_host_command(config: &Config) -> Result<Command, String> {
	let mut command = Command::new(config.required("QOS_HOST")?);
	command
		.arg("--host-ip")
		.arg(config.get("QOS_PARENT_HOST", "0.0.0.0"))
		.arg("--host-port")
		.arg(config.get("QOS_PARENT_CONTROL_PORT", "3001"))
		.arg("--cid")
		.arg(config.get("NESTED_FORWARD_CID", "1"))
		.arg("--port")
		.arg(config.get("NESTED_CORE_PORT", "3"))
		.arg("--vsock-to-host")
		.arg(config.get("QOS_HOST_VSOCK_TO_HOST", "false"));
	Ok(command)
}

fn qos_client_command(config: &Config) -> Result<Command, String> {
	let mut command = Command::new(config.required("QOS_CLIENT")?);
	command
		.arg("dangerous-dev-boot")
		.arg("--host-ip")
		.arg(config.get("QOS_PARENT_CONTROL_HOST", "127.0.0.1"))
		.arg("--host-port")
		.arg(config.get("QOS_PARENT_CONTROL_PORT", "3001"))
		.arg("--pivot-path")
		.arg(config.get("PIVOT_PATH", "/work/signed_echo"))
		.arg("--restart-policy")
		.arg(config.get("RESTART_POLICY", "never"))
		.arg("--pivot-args")
		.arg(config.required("PIVOT_ARGS")?)
		.arg("--bridge-config")
		.arg(config.required("BRIDGE_CONFIG")?);
	Ok(command)
}

fn qos_bridge_command(config: &Config) -> Result<Command, String> {
	let mut command = Command::new(config.required("QOS_BRIDGE")?);
	command
		.arg("--cid")
		.arg(config.get("NESTED_FORWARD_CID", "1"))
		.arg("--control-url")
		.arg(format!(
			"http://{}:{}/qos",
			config.get("QOS_PARENT_CONTROL_HOST", "127.0.0.1"),
			config.get("QOS_PARENT_CONTROL_PORT", "3001")
		))
		.arg("--host-port-override")
		.arg(config.get("QOS_PARENT_APP_PORT", "3000"))
		.arg("--vsock-to-host")
		.arg(config.get("QOS_BRIDGE_VSOCK_TO_HOST", "false"));
	Ok(command)
}

fn wait_for_host_ready(
	config: &Config,
	children: &mut [ManagedChild],
) -> Result<(), String> {
	let url = format!(
		"http://{}:{}/qos/host-health",
		config.get("QOS_PARENT_CONTROL_HOST", "127.0.0.1"),
		config.get("QOS_PARENT_CONTROL_PORT", "3001")
	);
	let start = Instant::now();
	while start.elapsed() < HOST_READY_TIMEOUT {
		fail_if_child_exited(children)?;
		if host_health_ok(config) {
			return Ok(());
		}
		thread::sleep(Duration::from_millis(250));
	}
	Err(format!("timed out waiting for {url}"))
}

fn host_health_ok(config: &Config) -> bool {
	let addr = format!(
		"{}:{}",
		config.get("QOS_PARENT_CONTROL_HOST", "127.0.0.1"),
		config.get("QOS_PARENT_CONTROL_PORT", "3001")
	);
	let Ok(mut stream) = TcpStream::connect(addr) else {
		return false;
	};
	let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
	let _ = stream.set_write_timeout(Some(Duration::from_millis(500)));
	if stream
		.write_all(b"GET /qos/host-health HTTP/1.1\r\nHost: localhost\r\n\r\n")
		.is_err()
	{
		return false;
	}
	let mut response = [0_u8; 64];
	let Ok(read) = stream.read(&mut response) else {
		return false;
	};
	let response = String::from_utf8_lossy(&response[..read]);
	response.starts_with("HTTP/1.1 200") || response.starts_with("HTTP/1.0 200")
}

fn spawn(name: &str, mut command: Command) -> Result<ManagedChild, String> {
	dmesg(format!("spawning {name}: {command:?}"));
	let child = command
		.spawn()
		.map_err(|err| format!("failed to spawn {name}: {err}"))?;
	Ok(ManagedChild { name: name.to_string(), child })
}

fn run_command(name: &str, mut command: Command) -> Result<(), String> {
	dmesg(format!("running {name}: {command:?}"));
	let output = command
		.output()
		.map_err(|err| format!("failed to run {name}: {err}"))?;
	if output.status.success() {
		print!("{}", String::from_utf8_lossy(&output.stdout));
		eprint!("{}", String::from_utf8_lossy(&output.stderr));
		return Ok(());
	}
	Err(format!(
		"{name} exited with {}: {}{}",
		output.status,
		String::from_utf8_lossy(&output.stdout),
		String::from_utf8_lossy(&output.stderr)
	))
}

fn monitor_children(mut children: Vec<ManagedChild>) -> Result<(), String> {
	loop {
		fail_if_child_exited(&mut children)?;
		thread::sleep(Duration::from_secs(1));
	}
}

fn fail_if_child_exited(children: &mut [ManagedChild]) -> Result<(), String> {
	for child in children {
		if let Some(message) = child.exited()? {
			return Err(message);
		}
	}
	Ok(())
}

struct ManagedChild {
	name: String,
	child: Child,
}

impl ManagedChild {
	fn exited(&mut self) -> Result<Option<String>, String> {
		match self
			.child
			.try_wait()
			.map_err(|err| format!("{} status failed: {err}", self.name))?
		{
			Some(status) => {
				Ok(Some(format!("{} exited with {status}", self.name)))
			}
			None => Ok(None),
		}
	}
}

struct Config {
	values: BTreeMap<String, String>,
}

impl Config {
	fn read(path: &str) -> Result<Self, String> {
		let raw = fs::read_to_string(path)
			.map_err(|err| format!("failed to read {path}: {err}"))?;
		let mut values = BTreeMap::new();
		for (index, line) in raw.lines().enumerate() {
			let line = line.trim();
			if line.is_empty() || line.starts_with('#') {
				continue;
			}
			let Some((key, value)) = line.split_once('=') else {
				return Err(format!(
					"invalid config line {} in {path}: {line}",
					index + 1
				));
			};
			values.insert(key.trim().to_string(), value.trim().to_string());
		}
		Ok(Self { values })
	}

	fn required(&self, key: &str) -> Result<&str, String> {
		self.values
			.get(key)
			.map(String::as_str)
			.ok_or_else(|| format!("missing required config key {key}"))
	}

	fn get<'a>(&'a self, key: &str, fallback: &'a str) -> &'a str {
		self.values.get(key).map_or(fallback, String::as_str)
	}

	fn get_bool(&self, key: &str, fallback: bool) -> Result<bool, String> {
		let raw = self.get(key, if fallback { "true" } else { "false" });
		match raw {
			"1" | "true" | "TRUE" | "yes" | "YES" => Ok(true),
			"0" | "false" | "FALSE" | "no" | "NO" => Ok(false),
			_ => Err(format!("{key} must be a boolean, got {raw}")),
		}
	}

	fn get_u32(&self, key: &str, fallback: u32) -> Result<u32, String> {
		self.get(key, "").parse().or_else(|_| {
			if self.values.contains_key(key) {
				Err(format!("{key} must be a u32"))
			} else {
				Ok(fallback)
			}
		})
	}
}
