use std::{
    os::unix::net::UnixStream,
    thread,
    io::Write,
    net::{TcpListener, Shutdown},
};
use nitro_cli::{
    enclave_proc_comm::enclave_proc_spawn,
    common::{
        commands_parser::RunEnclavesArgs,
        enclave_proc_command_send_single,
        logger,
        EnclaveProcessCommandType,
        ExitGracefully
    }
};

const RUN_ENCLAVE_STR: &str = "Run Enclave";

fn main() {

    let eif_path = std::env::var("EIF_PATH").unwrap_or("/nitro.eif".to_string());
    let enclave_cid = std::env::var("ENCLAVE_CID").unwrap_or("16".to_string());
    let memory_mib = std::env::var("MEMORY_MIB").unwrap_or("1024".to_string());
    let cpu_count = std::env::var("CPU_COUNT").unwrap_or("2".to_string());
    let enclave_name = std::env::var("ENCLAVE_NAME").unwrap_or("nitro".to_string());

    let logger = logger::init_logger()
        .map_err(|e| e.set_action("Logger initialization".to_string()))
        .ok_or_exit_with_errno(None);
    let mut replies: Vec<UnixStream> = vec![];

    logger
        .update_logger_id(format!("nitro-cli:{}", std::process::id()).as_str())
        .map_err(|e| e.set_action("Update CLI Process Logger ID".to_string()))
        .ok_or_exit_with_errno(None);

    let mut socket = enclave_proc_spawn(&logger)
        .map_err(|err| {
            err.add_subaction("Failed to spawn enclave process".to_string())
                .set_action(RUN_ENCLAVE_STR.to_string())
        })
        .ok_or_exit_with_errno(None);

    let run_args = RunEnclavesArgs {
        eif_path: eif_path,
        enclave_cid: Some(enclave_cid.parse::<u64>().unwrap()),
        memory_mib: memory_mib.parse::<u64>().unwrap(),
        cpu_ids: None,
        debug_mode: false,
        attach_console: false,
        cpu_count: Some(cpu_count.parse::<u32>().unwrap()),
        enclave_name: Some(enclave_name),
    };

    println!("Booting Nitro Enclave:");
    println!("{:?}",run_args);

    enclave_proc_command_send_single(
        EnclaveProcessCommandType::Run,
        Some(&run_args),
        &mut socket,
    )
    .map_err(|e| {
        e.add_subaction("Failed to send single command".to_string())
            .set_action(RUN_ENCLAVE_STR.to_string())
    })
    .ok_or_exit_with_errno(None);

    replies.push(socket);

    //TODO: This is maybe a lie. We should implement a describe-enclaves here
    println!("Nitro socket connected.");

    println!("Starting health service");
    let listener = TcpListener::bind("127.0.0.1:8080").unwrap();
    for stream in listener.incoming() {
        thread::spawn(move || {
            let mut stream = stream.unwrap();
            match stream.write(b"HTTP/1.1 200 OK\r\r\n\r") {
                Ok(_) => println!("Health response sent"),
                Err(e) => println!("Failed sending health response: {}!", e),
            }
            stream.shutdown(Shutdown::Write).unwrap();
        });
    }
}
