use std::{
	fs::create_dir_all,
	io::Write,
	mem::MaybeUninit,
	net::{Shutdown, TcpListener},
	os::unix::net::UnixStream,
	path::Path,
	process::exit,
	ptr, thread,
};

use libc::{
	c_int, sigaddset, sigemptyset, sigprocmask, sigset_t, sigwaitinfo, SIGINT,
	SIGTERM, SIG_BLOCK,
};
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

fn boot() -> String {
	//TODO: allow_skip: do not bail if boot fails
	// currently ignored until we figure out how to hook into the nitro CLI
	// libs properly, or re-implement some of their functions
	// fn boot(const allow_skip: bool){

	let eif_path =
		std::env::var("EIF_PATH").unwrap_or("/aws-x86_64.eif".to_string());
	let enclave_cid = std::env::var("ENCLAVE_CID").unwrap_or("16".to_string());
	let memory_mib = std::env::var("MEMORY_MIB").unwrap_or("1024".to_string());
	let cpu_count = std::env::var("CPU_COUNT").unwrap_or("2".to_string());
	let debug_mode = std::env::var("DEBUG").unwrap_or("false".to_string());
	let enclave_name =
		std::env::var("ENCLAVE_NAME").unwrap_or("nitro".to_string());
	let run_args = RunEnclavesArgs {
		eif_path,
		enclave_cid: Some(enclave_cid.parse::<u64>().unwrap()),
		memory_mib: memory_mib.parse::<u64>().unwrap(),
		cpu_ids: None,
		debug_mode: debug_mode.parse::<bool>().unwrap(),
		attach_console: false,
		cpu_count: Some(cpu_count.parse::<u32>().unwrap()),
		enclave_name: Some(enclave_name.clone()),
	};
	println!("{:?}", run_args);

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

	return get_id_by_name(enclave_name)
		.or_else(|_| Err("Failed to parse enclave name"))
		.unwrap();
}

fn shutdown(enclave_id: String, sig_num: i32) {
	println!("Got signal: {}", sig_num);
	println!("Shutting down Enclave");
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

	exit(0);
}

fn health_service() {
	println!("Starting health service");
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
				Ok(_) => println!("Health response sent"),
				Err(e) => println!("Failed sending health response: {}!", e),
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
	let signal = unsafe { sigwaitinfo(&mask, ptr::null_mut()) } as i32;
	return signal;
}

fn main() {
	println!("Booting Nitro Enclave:");

	//TODO: Implement ability to allow skipping boot
	//let allow_skip: _ = std::env::var("ALLOW_SKIP_BOOT")
	//    .unwrap_or("false".to_string())
	//    .trim().parse::<F>().unwrap();
	//boot(allow_skip);

	let enclave_id = boot();

	match healthy() {
		Ok(_) => eprintln!("{}", "Enclave is healthy"),
		Err(e) => eprintln!("Enclave is sad: {}", e),
	};

	// TODO: return listener so shutdown() can clean it up properly
	thread::spawn(|| {
		health_service();
	});

	let sig_num = handle_signals();

	shutdown(enclave_id.clone(), sig_num);
}
