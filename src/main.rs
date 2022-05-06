#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(warnings)]

use clap::{App, AppSettings, Arg, SubCommand};
use qos::create_app;
use qos::enclave;

const BACKLOG: usize = 128;
const BUF_MAX_LEN: usize = 8192;
const MAX_CONNECTION_ATTEMPTS: usize = 5;

fn main() {
  ctrlc::set_handler(move || {
    std::process::exit(1);
  }).expect("Error setting Ctrl-C handler");

  let app = create_app!();
  let args = app.get_matches();

  match args.subcommand() {
    ("server", Some(args)) => {
      let s = enclave::Server::new().unwrap();
      s.serve();
    }
    ("client", Some(args)) => {
      let c = enclave::Client::new().unwrap();
      let data = "Hello, server!".as_bytes();
      match c.send(&data) {
        Ok(response) => {
          println!("Response!");
          println!("{}", String::from_utf8(response).unwrap());
        },
        Err(err) => println!("{:?}", err)
      };
    }
    (&_, _) => {}
  }
}