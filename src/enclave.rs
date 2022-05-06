#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(warnings)]

use std::os::unix::io::{AsRawFd, RawFd};
use std::ops::Drop;
use std::convert::TryInto;

use nix::sys::socket::{socket, listen, bind, accept, connect};
use nix::sys::socket::{AddressFamily, Shutdown, SockAddr, SockFlag, SockType};

use std::path::Path;
use std::fs::remove_file;

use crate::protocol_helpers::{recv_loop, recv_u64, send_loop, send_u64};

const BACKLOG: usize = 128;
const BUF_MAX_LEN: usize = 8192;
const SOCKET_PATH: &str = "/var/run/qos/qos.sock";
const MAX_CONNECTION_ATTEMPTS: usize = 5;

pub struct Server {
  pub fd: RawFd,
  pub addr: SockAddr,
}

impl Server {
  pub fn new() -> Result<Self, String> {
    let fd = new_socket()?;

    // TODO: Should this be executed in Drop?
    if Path::new(SOCKET_PATH).exists() {
      println!("Deleting socket...");
      remove_file(SOCKET_PATH);
    }  

    let addr = new_address()?;
  
    Ok(Server{ fd, addr })
  }

  pub fn serve(&self) -> Result<(), String> {
    bind(self.fd, &self.addr).map_err(|err| format!("Bind failed: {:?}", err))?;
    listen(self.fd, BACKLOG).map_err(|err| format!("Listen failed: {:?}", err))?;

    println!("Listening on {}", SOCKET_PATH);

    loop {
      let fd = accept(self.fd).map_err(|err| format!("Accept failed: {:?}", err))?;
      let len = recv_u64(fd)?;
      let mut buf = [0u8; BUF_MAX_LEN];
      recv_loop(fd, &mut buf, len)?;
      self.echo(fd, &buf);
    }
  }

  pub fn echo(&self, socket: RawFd, buf: &[u8]) -> Result<(), String> {
    let len: u64 = buf.len().try_into().map_err(|err| format!("{:?}", err))?;
    send_u64(socket, len)?;
    send_loop(socket, &buf, len)?;
    
    Ok(())
  }
}

pub struct Client {
  pub fd: RawFd,
  pub addr: SockAddr,
}

impl Client {
  pub fn new() -> Result<Self, String> {

    let addr = new_address()?;
    let fd = Client::try_connect(addr)?;
  
    Ok(Client { fd, addr })
  }

  pub fn try_connect(addr: SockAddr) -> Result<RawFd, String> {
    let mut err = String::new();

    for i in 0..MAX_CONNECTION_ATTEMPTS {
      let fd = new_socket()?;
      match connect(fd, &addr) {
          Ok(_) => return Ok(fd),
          Err(e) => err = format!("Failed to connect: {}", e),
      }
  
      // Exponentially backoff before retrying to connect to the socket
      std::thread::sleep(std::time::Duration::from_secs(1 << i));
    }

    Err(err)
  }

  pub fn send(&self, data: &[u8]) -> Result<Vec<u8>, String> {
    let len: u64 = data.len().try_into().map_err(|err| format!("{:?}", err))?;
    send_u64(self.fd, len)?;
    send_loop(self.fd, &data, len)?;

    let len = recv_u64(self.fd)?;
    let mut response = [0u8; BUF_MAX_LEN];
    recv_loop(self.fd, &mut response, len)?;
    Ok(response.to_vec())
  }
}

fn new_socket() -> Result<RawFd, String> {
  socket(
    AddressFamily::Unix,
    SockType::Stream,
    SockFlag::empty(),
    None
  ).map_err(|err| format!("Failed to create the socket: {:?}", err))
}

fn new_address() -> Result<SockAddr, String> {
  SockAddr::new_unix(SOCKET_PATH)
    .map_err(|err| format!("Create socket failed: {:?}", err))
}