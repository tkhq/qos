// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Compatibility code copied from AWS Nitro CLI v1.4.5.
//!
//! Source: <https://github.com/aws/aws-nitro-enclaves-cli/blob/18a5f6f35f110c0f235f193ae3caff9434d64ee1/src/enclave_proc_comm.rs#L142-L258>

use log::debug;
use nitro_cli::{
	common::{
		ENCLAVE_PROC_WAIT_TIMEOUT_MSEC, EnclaveProcessCommandType,
		MSG_ENCLAVE_CONFIRM, NitroCliErrorEnum, NitroCliFailure,
		NitroCliResult, enclave_proc_command_send_single, read_u64_le,
	},
	enclave_proc_comm::enclave_proc_connect_to_all,
	new_nitro_cli_failure,
};
use nix::sys::epoll;
use nix::sys::epoll::{EpollEvent, EpollFlags, EpollOp};
use serde::Serialize;
use std::borrow::BorrowMut;
use std::os::unix::io::{FromRawFd, IntoRawFd, RawFd};
use std::os::unix::net::UnixStream;

/// Broadcast a command to all available enclave processes.
#[rustfmt::skip]
pub fn enclave_proc_command_send_all<T>(
    cmd: EnclaveProcessCommandType,
    args: Option<&T>,
) -> NitroCliResult<(Vec<UnixStream>, usize)>
where
    T: Serialize,
{
    // Open a connection to each valid socket.
    let mut replies: Vec<UnixStream> = vec![];
    let epoll_fd = epoll::epoll_create().map_err(|e| {
        new_nitro_cli_failure!(
            &format!("Failed to create epoll: {e:?}"),
            NitroCliErrorEnum::EpollError
        )
    })?;
    let comms: Vec<NitroCliResult<()>> = enclave_proc_connect_to_all()
        .map_err(|e| {
            e.add_subaction("Failed to send command to all enclave processes".to_string())
        })?
        .into_iter()
        .map(|mut socket| {
            // Send the command.
            enclave_proc_command_send_single(cmd, args, socket.borrow_mut())?;

            let raw_fd = socket.into_raw_fd();
            let mut process_evt = EpollEvent::new(EpollFlags::EPOLLIN, raw_fd as u64);

            // Add each valid connection to epoll.
            epoll::epoll_ctl(epoll_fd, EpollOp::EpollCtlAdd, raw_fd, &mut process_evt).map_err(
                |e| {
                    new_nitro_cli_failure!(
                        &format!("Failed to register socket with epoll: {e:?}"),
                        NitroCliErrorEnum::EpollError
                    )
                },
            )?;

            Ok(())
        })
        .collect();

    // Don't proceed unless at least one connection has been established.
    if comms.is_empty() {
        return Ok((vec![], 0));
    }

    // Get the number of transmission errors.
    let mut num_errors = comms.iter().filter(|result| result.is_err()).count();

    // Get the number of expected replies.
    let mut num_replies_expected = comms.len() - num_errors;
    let mut events = [EpollEvent::empty(); 1];

    while num_replies_expected > 0 {
        let num_events = loop {
            match epoll::epoll_wait(epoll_fd, &mut events[..], ENCLAVE_PROC_WAIT_TIMEOUT_MSEC) {
                Ok(num_events) => break num_events,
                Err(nix::errno::Errno::EINTR) => continue,
                // TODO: Handle bad descriptors (closed remote connections).
                Err(e) => {
                    return Err(new_nitro_cli_failure!(
                        &format!("Failed to wait on epoll: {e:?}"),
                        NitroCliErrorEnum::EpollError
                    ))
                }
            }
        };

        // We will handle this reply, irrespective of its status (successful or failed).
        num_replies_expected -= 1;

        // Check if a time-out has occurred.
        if num_events == 0 {
            continue;
        }

        let input_stream_raw_fd = events[0].data() as RawFd;
        let mut input_stream = unsafe { UnixStream::from_raw_fd(input_stream_raw_fd) };

        // Handle the reply we received.
        if let Ok(reply) = read_u64_le(&mut input_stream) {
            if reply == MSG_ENCLAVE_CONFIRM {
                debug!("Got confirmation from {:?}", input_stream);
                replies.push(input_stream);
            }
        }

        epoll::epoll_ctl(
            epoll_fd,
            EpollOp::EpollCtlDel,
            input_stream_raw_fd,
            Option::None,
        )
        .map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Failed to remove socket from epoll: {e:?}"),
                NitroCliErrorEnum::EpollError
            )
        })?;
    }

    // Update the number of connections that have yielded errors.
    num_errors = comms.len() - replies.len();

    Ok((replies, num_errors))
}
