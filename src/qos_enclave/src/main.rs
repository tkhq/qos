use std::os::unix::net::UnixStream;

use nitro_cli::common::commands_parser::RunEnclavesArgs;
use nitro_cli::common::{
    enclave_proc_command_send_single, logger
};
use nitro_cli::common::{EnclaveProcessCommandType, ExitGracefully};
use nitro_cli::enclave_proc_comm::enclave_proc_spawn;

const RUN_ENCLAVE_STR: &str = "Run Enclave";

fn main() {
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
        eif_path: String::from("/home/lrvick/qos/out/aws-x86_64.eif"),
        enclave_cid: None,
        memory_mib: 512,
        cpu_ids: None,
        debug_mode: false,
        attach_console: false,
        cpu_count: Some(2),
        enclave_name: Some(String::from("nitro")),
    };

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
}
