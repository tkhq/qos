use std::{
	fs::create_dir_all,
	io::{self, Write},
	mem::MaybeUninit,
	net::{Shutdown, TcpListener},
	os::unix::net::UnixStream,
	path::Path,
	process::exit,
	ptr, thread,
};

use libc::{
	SIG_BLOCK, SIGINT, SIGTERM, c_int, sigaddset, sigemptyset, sigprocmask,
	sigset_t, sigwaitinfo,
};
use nitro_cli::{
	CID_TO_CONSOLE_PORT_OFFSET, VMADDR_CID_HYPERVISOR,
	common::{
		EnclaveProcessCommandType, ExitGracefully,
		commands_parser::{DescribeEnclavesArgs, EmptyArgs, RunEnclavesArgs},
		enclave_proc_command_send_single,
		json_output::{EnclaveDescribeInfo, EnclaveRunInfo},
		logger::init_logger,
	},
	enclave_proc_comm::{
		enclave_proc_command_send_all, enclave_proc_connect_to_single,
		enclave_proc_spawn, enclave_process_handle_all_replies,
	},
	get_id_by_name,
	utils::Console,
};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

const RUN_ENCLAVE_STR: &str = "Run Enclave";

fn init_tracing() {
	let env_filter = EnvFilter::try_from_default_env()
		.unwrap_or_else(|_| EnvFilter::new("info"));
	tracing_subscriber::fmt()
		.json()
		.with_env_filter(env_filter)
		.with_writer(io::stdout)
		.init();
}

/// A [`Write`] sink that adapts the enclave's serial console output into the
/// host's structured JSON log stream.
///
/// Unlike `qos_enclave`'s own `info!`/`error!` events (emitted straight to JSON
/// by the subscriber, see [`init_tracing`]), this handles a *foreign* source:
/// the raw plain-text bytes read off the Nitro serial console via
/// `Console::read_to` — kernel/init/NSM/app output. It only runs when `LOGS`
/// attaches the console, and Nitro only emits console output in debug mode
/// (`DEBUG`), so this is a diagnostics path, not a production-hot one.
///
/// We re-emit each console line as a JSON event (`target: "qos_enclave::console"`)
/// rather than forwarding raw bytes, which would interleave non-JSON text with
/// the host's JSON events and break Grafana's parser. Framing is line-based
/// because the newline is the **only** delimiter a raw console stream offers (a
/// multi-line message thus fragments into several events, as with any log
/// shipper). Bytes without a trailing newline are buffered until the next
/// `write` completes the line, or until `flush` emits the remainder.
#[derive(Default)]
struct EnclaveConsoleWriter {
	buffer: Vec<u8>,
}

impl EnclaveConsoleWriter {
	fn emit_line(line: &[u8]) {
		let line = String::from_utf8_lossy(line);
		let line = line.trim_end_matches('\r');
		if !line.is_empty() {
			info!(target: "qos_enclave::console", "{}", line);
		}
	}
}

impl Write for EnclaveConsoleWriter {
	fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
		self.buffer.extend_from_slice(buf);

		let mut consumed = 0;
		while let Some(newline_offset) =
			self.buffer[consumed..].iter().position(|byte| *byte == b'\n')
		{
			let newline_index = consumed + newline_offset;
			Self::emit_line(&self.buffer[consumed..newline_index]);
			consumed = newline_index + 1;
		}

		if consumed > 0 {
			self.buffer.drain(..consumed);
		}

		Ok(buf.len())
	}

	fn flush(&mut self) -> io::Result<()> {
		if !self.buffer.is_empty() {
			Self::emit_line(&self.buffer);
			self.buffer.clear();
		}
		Ok(())
	}
}

fn healthy() -> Result<(), Box<dyn std::error::Error>> {
	let mut replies: Vec<UnixStream> = vec![];
	let describe_args = DescribeEnclavesArgs { metadata: false };

	let comms = match enclave_proc_command_send_all::<DescribeEnclavesArgs>(
		EnclaveProcessCommandType::Describe,
		Some(&describe_args),
	) {
		Ok((comms, _)) => comms,
		_ => return Err("Unable to send command to Enclave")?,
	};
	replies.extend(comms);

	let describe_info = match enclave_process_handle_all_replies::<
		EnclaveDescribeInfo,
	>(&mut replies, 0, false, vec![0])
	{
		Ok(describe_info) => describe_info,
		_ => return Err("Unable to process enclave replies")?,
	};

	match describe_info
		.first()
		.map(|describe_info| describe_info.state.clone())
		.as_deref()
	{
		Some("RUNNING") => Ok(()),
		_ => Err("Status is not RUNNING")?,
	}
}

fn boot() -> (String, Option<Console>) {
	// TODO: allow_skip: do not bail if boot fails
	//
	// currently ignored until we figure out how to hook into the nitro CLI
	// libs properly, or re-implement some of their functions
	// fn boot(const allow_skip: bool) {

	let eif_path =
		std::env::var("EIF_PATH").unwrap_or("/aws-x86_64.eif".to_string());
	let enclave_cid = std::env::var("ENCLAVE_CID").unwrap_or("16".to_string());
	let memory_mib = std::env::var("MEMORY_MIB").unwrap_or("1024".to_string());
	let cpu_count = std::env::var("CPU_COUNT").unwrap_or("2".to_string());
	let debug_mode = std::env::var("DEBUG").unwrap_or("false".to_string());
	let logs_mode = std::env::var("LOGS").unwrap_or("false".to_string());
	let enclave_name =
		std::env::var("ENCLAVE_NAME").unwrap_or("nitro".to_string());
	let enclave_cid_u32 = enclave_cid
		.parse::<u32>()
		.expect("enclave_cid must be a valid u32 to boot an enclave");
	let run_args = RunEnclavesArgs {
		eif_path,
		enclave_cid: Some(enclave_cid_u32.into()),
		memory_mib: memory_mib.parse::<u64>().unwrap(),
		cpu_ids: None,
		debug_mode: debug_mode.parse::<bool>().unwrap(),
		attach_console: logs_mode.parse::<bool>().unwrap(),
		cpu_count: Some(cpu_count.parse::<u32>().unwrap()),
		enclave_name: Some(enclave_name.clone()),
	};
	info!(?run_args, "Run enclave arguments");

	// Socket directory must exist or Nitro SDK crashes with generic error
	if !Path::new("/run/nitro_enclaves").is_dir() {
		create_dir_all("/run/nitro_enclaves")
			.expect("Failed to create /run/nitro_enclaves");
	}

	let logger = init_logger()
		.map_err(|e| e.set_action("Logger initialization".to_string()))
		.ok_or_exit_with_errno(None);
	let mut replies: Vec<UnixStream> = vec![];

	logger
		.update_logger_id(format!("nitro-cli:{}", std::process::id()).as_str())
		.map_err(|e| e.set_action("Update CLI Process Logger ID".to_string()))
		.ok_or_exit_with_errno(None);

	let mut cli_socket = enclave_proc_spawn(&logger)
		.map_err(|err| {
			err.add_subaction("Failed to spawn enclave process".to_string())
				.set_action(RUN_ENCLAVE_STR.to_string())
		})
		.ok_or_exit_with_errno(None);

	enclave_proc_command_send_single(
		EnclaveProcessCommandType::Run,
		Some(&run_args),
		&mut cli_socket,
	)
	.map_err(|e| {
		e.add_subaction("Failed to send single command".to_string())
			.set_action(RUN_ENCLAVE_STR.to_string())
	})
	.ok_or_exit_with_errno(None);

	replies.push(cli_socket);

	enclave_process_handle_all_replies::<EnclaveRunInfo>(
		&mut replies,
		0,
		false,
		vec![0],
	)
	.map_err(|e| {
		e.add_subaction(
			"Failed to handle all enclave process replies".to_string(),
		)
		.set_action(RUN_ENCLAVE_STR.to_string())
	})
	.ok_or_exit_with_errno(None);

	let console = match run_args.attach_console {
		true => Some(
			Console::new(
				VMADDR_CID_HYPERVISOR,
				enclave_cid_u32 + CID_TO_CONSOLE_PORT_OFFSET,
			)
			.map_err(|err| {
				err.add_subaction(
					"Failed to attach console to enclave".to_string(),
				)
				.set_action(RUN_ENCLAVE_STR.to_string())
			})
			.ok_or_exit_with_errno(None),
		),
		false => None,
	};

	// return result
	(
		get_id_by_name(enclave_name)
			.map_err(|_| "Failed to parse enclave name")
			.unwrap(),
		console,
	)
}

fn shutdown(enclave_id: String, sig_num: i32) {
	info!(sig_num, "Got signal");
	info!("Shutting down Enclave");

	// Best-effort graceful Terminate: if the EnclaveProc IPC socket is
	// unreachable (e.g. the proc has already exited, or the socket is
	// momentarily stalled while the kernel sends SIGTERM during a kubelet-
	// initiated shutdown), don't escalate to a panic. Panicking here turns a
	// graceful stop request into an abnormal exit (SIGABRT / non-zero status),
	// which obscures the real reason the orchestrator is shutting us down and
	// can cause container runtimes to flag the pod as crashed instead of
	// terminated.
	match enclave_proc_connect_to_single(&enclave_id) {
		Ok(mut comm) => {
			// TODO: Replicate output of old CLI on invalid enclave IDs.
			let _ = enclave_proc_command_send_single::<EmptyArgs>(
				EnclaveProcessCommandType::Terminate,
				None,
				&mut comm,
			)
			.map_err(|_| "Unable to terminate Enclave");
		}
		Err(_) => {
			error!(
				%enclave_id,
				"Failed to connect to EnclaveProc; skipping graceful Terminate",
			);
		}
	}

	exit(0);
}

fn health_service() {
	info!("Starting health service");
	let listener = TcpListener::bind("0.0.0.0:8080").unwrap();
	for stream in listener.incoming() {
		thread::spawn(move || {
			let mut stream = stream.unwrap();
			let healthy_resp = b"HTTP/1.1 200 OK\r\n\r\n";
			let unhealthy_resp = b"HTTP/1.1 503 Service Unavailable\r\n\r\n";
			let response = match healthy() {
				Ok(_) => &healthy_resp[..],
				_ => &unhealthy_resp[..],
			};
			match stream.write_all(response) {
				Ok(_) => info!("Health response sent"),
				Err(e) => error!(error = %e, "Failed sending health response"),
			};
			stream.shutdown(Shutdown::Write).unwrap();
		});
	}
}

fn handle_signals() -> c_int {
	let mut mask: sigset_t = unsafe {
		let mut masku = MaybeUninit::<sigset_t>::uninit();
		sigemptyset(masku.as_mut_ptr());
		masku.assume_init()
	};
	unsafe { sigaddset(&mut mask, SIGINT) };
	unsafe { sigaddset(&mut mask, SIGTERM) };
	unsafe { sigprocmask(SIG_BLOCK, &mask, ptr::null_mut()) };
	// return signal
	(unsafe { sigwaitinfo(&mask, ptr::null_mut()) }) as i32
}

fn read_logs(console: Console) {
	info!("Reading logs to stdout");
	let disconnect_timeout_sec: Option<u64> = None;
	let mut writer = EnclaveConsoleWriter::default();
	let _ = console.read_to(&mut writer, disconnect_timeout_sec);
	let _ = writer.flush();
}

fn main() {
	init_tracing();
	info!("Booting Nitro Enclave");

	let (enclave_id, maybe_console) = boot();

	match healthy() {
		Ok(_) => info!("Enclave is healthy"),
		Err(e) => error!(error = %e, "Enclave is sad"),
	};

	// TODO: return listener so shutdown() can clean it up properly
	thread::spawn(|| {
		health_service();
	});

	if let Some(console) = maybe_console {
		thread::spawn(|| {
			read_logs(console);
		});
	}

	let sig_num = handle_signals();

	shutdown(enclave_id.clone(), sig_num);
}

#[cfg(test)]
mod tests {
	use std::{
		io::{self, Write},
		sync::{Arc, Mutex},
	};

	use serde_json::Value;
	use tracing_subscriber::{EnvFilter, fmt::MakeWriter};

	#[derive(Clone, Default)]
	struct CapturedOutput(Arc<Mutex<Vec<u8>>>);

	impl Write for CapturedOutput {
		fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
			self.0.lock().unwrap().write(buf)
		}

		fn flush(&mut self) -> io::Result<()> {
			self.0.lock().unwrap().flush()
		}
	}

	impl<'writer> MakeWriter<'writer> for CapturedOutput {
		type Writer = CapturedOutput;

		fn make_writer(&'writer self) -> Self::Writer {
			self.clone()
		}
	}

	fn capture_console_logs(chunks: &[&[u8]], flush: bool) -> Vec<Value> {
		let writer = CapturedOutput::default();
		let subscriber = tracing_subscriber::fmt()
			.json()
			.with_env_filter(EnvFilter::new("info"))
			.with_writer(writer.clone())
			.finish();

		tracing::subscriber::with_default(subscriber, || {
			let mut console_writer = super::EnclaveConsoleWriter::default();
			for chunk in chunks {
				console_writer.write_all(chunk).unwrap();
			}
			if flush {
				console_writer.flush().unwrap();
			}
		});

		let output =
			String::from_utf8(writer.0.lock().unwrap().clone()).unwrap();
		output
			.lines()
			.map(|line| serde_json::from_str::<Value>(line).unwrap())
			.collect()
	}

	fn messages(logs: &[Value]) -> Vec<&str> {
		logs.iter()
			.map(|log| log["fields"]["message"].as_str().unwrap())
			.collect()
	}

	#[test]
	fn tracing_subscriber_emits_json_logs() {
		let writer = CapturedOutput::default();
		let subscriber = tracing_subscriber::fmt()
			.json()
			.with_env_filter(EnvFilter::new("info"))
			.with_writer(writer.clone())
			.finish();

		tracing::subscriber::with_default(subscriber, || {
			tracing::info!(enclave_id = "nitro", "Enclave is healthy");
		});

		let output =
			String::from_utf8(writer.0.lock().unwrap().clone()).unwrap();
		let log: Value = serde_json::from_str(output.trim()).unwrap();

		assert_eq!(log["level"], "INFO");
		assert_eq!(log["fields"]["message"], "Enclave is healthy");
		assert_eq!(log["fields"]["enclave_id"], "nitro");
	}

	#[test]
	fn console_log_writer_emits_one_json_log_per_line() {
		let logs = capture_console_logs(&[b"first\nsecond\n"], false);

		assert_eq!(logs.len(), 2);
		assert_eq!(logs[0]["fields"]["message"], "first");
		assert_eq!(logs[1]["fields"]["message"], "second");
	}

	#[test]
	fn console_log_writer_handles_arbitrary_write_boundaries() {
		let input = b"first\nsecond\r\n\nthird";

		for chunk_size in 1..=input.len() {
			let chunks = input.chunks(chunk_size).collect::<Vec<_>>();
			let logs = capture_console_logs(&chunks, true);
			assert_eq!(messages(&logs), ["first", "second", "third"]);
		}
	}

	#[test]
	fn console_log_writer_buffers_incomplete_line_until_flush() {
		assert!(capture_console_logs(&[b"partial"], false).is_empty());

		let logs = capture_console_logs(&[b"partial"], true);
		assert_eq!(messages(&logs), ["partial"]);
	}
}
