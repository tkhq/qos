use std::{
	io::Write,
	net::{Shutdown, TcpListener},
	os::unix::net::UnixStream,
	process::exit,
	thread,
};

use libc::{SIGINT, SIGTERM};
use nitro_cli::{
	common::{
		commands_parser::{DescribeEnclavesArgs, EmptyArgs, RunEnclavesArgs},
		enclave_proc_command_send_single,
		json_output::{EnclaveDescribeInfo, EnclaveRunInfo},
		logger::init_logger,
		EnclaveProcessCommandType, ExitGracefully,
	},
	enclave_proc_comm::{
		enclave_proc_command_send_all, enclave_proc_connect_to_single,
		enclave_proc_spawn, enclave_process_handle_all_replies,
	},
	get_id_by_name,
};

const RUN_ENCLAVE_STR: &str = "Run Enclave";

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

fn boot() {
	//TODO: allow_skip: do not bail if boot fails
	// currently ignored until we figure out how to hook into the nitro CLI
	// libs properly, or re-implement some of their functions
	// fn boot(const allow_skip: bool){

	let eif_path =
		std::env::var("EIF_PATH").unwrap_or("/aws-x86_64.eif".to_string());
	let enclave_cid = std::env::var("ENCLAVE_CID").unwrap_or("16".to_string());
	let memory_mib = std::env::var("MEMORY_MIB").unwrap_or("1024".to_string());
	let cpu_count = std::env::var("CPU_COUNT").unwrap_or("2".to_string());
	let enclave_name =
		std::env::var("ENCLAVE_NAME").unwrap_or("nitro".to_string());
	let run_args = RunEnclavesArgs {
		eif_path,
		enclave_cid: Some(enclave_cid.parse::<u64>().unwrap()),
		memory_mib: memory_mib.parse::<u64>().unwrap(),
		cpu_ids: None,
		debug_mode: false,
		attach_console: false,
		cpu_count: Some(cpu_count.parse::<u32>().unwrap()),
		enclave_name: Some(enclave_name),
	};
	println!("{:?}", run_args);

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
}

fn shutdown() {
	println!("Shutting down Enclave");
	let enclave_name =
		std::env::var("ENCLAVE_NAME").unwrap_or("nitro".to_string());
	let enclave_id = get_id_by_name(enclave_name)
		.or_else(|_| Err("Failed to parse enclave name"))
		.unwrap();
	let mut comm = enclave_proc_connect_to_single(&enclave_id)
		.or_else(|_| Err("Failed to send command to Enclave"))
		.unwrap();

	// TODO: Replicate output of old CLI on invalid enclave IDs.
	let _ = enclave_proc_command_send_single::<EmptyArgs>(
		EnclaveProcessCommandType::Terminate,
		None,
		&mut comm,
	)
	.or_else(|_| Err("Unable to terminate Enclave"));
}

fn health_service() {
	println!("Starting health service");
	let listener = TcpListener::bind("0.0.0.0:8080").unwrap();
	for stream in listener.incoming() {
		thread::spawn(move || {
			let mut stream = stream.unwrap();
			let healthy_resp = b"HTTP/1.1 200 OK\r\r\n\r";
			let unhealthy_resp = b"HTTP/1.1 503 Service Unavailable\r\r\n\r";
			let response = match healthy() {
				Ok(_) => &healthy_resp[..],
				_ => &unhealthy_resp[..],
			};
			match stream.write_all(response) {
				Ok(_) => println!("Health response sent"),
				Err(e) => println!("Failed sending health response: {}!", e),
			};
			stream.shutdown(Shutdown::Write).unwrap();
		});
	}
}

fn register_signal_handlers() {
	unsafe {
		libc::signal(SIGINT, handle_sigint as usize);
		libc::signal(SIGTERM, handle_sigterm as usize);
	}
}

fn handle_sigint(_signal: i32) {
	register_signal_handlers();
	shutdown();
	exit(130);
}

fn handle_sigterm(_signal: i32) {
	register_signal_handlers();
	shutdown();
	exit(143);
}

fn main() {
	println!("Booting Nitro Enclave:");
	register_signal_handlers();

	//TODO: Implement ability to allow skipping boot
	//let allow_skip: _ = std::env::var("ALLOW_SKIP_BOOT")
	//    .unwrap_or("false".to_string())
	//    .trim().parse::<F>().unwrap();
	//boot(allow_skip);

	boot();

	match healthy() {
		Ok(_) => eprintln!("{}", "Enclave is healthy"),
		Err(e) => eprintln!("Enclave is sad: {}", e),
	};

	health_service();
}
