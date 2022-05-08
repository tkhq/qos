mod io;
// mod server;
mod protocol;

pub fn main() {
	println!("Hello, world");
}

// // "The client making a connection should provide the CID of a remote virtual
// machine or host." const SERVER_CID: u32 = libc::VMADDR_CID_ANY;

// // "The port number is arbitrary, although server (listener) and client
// (connector) must use the same number," const SERVER_PORT: u32 = 1234;

// // Commands
// #[derive(Debug, StructOpt)]
// #[structopt(name = "Command")]
// enum Cmd {
// 	Server, //{
// 	// #[structopt(subcommand)]
// 	// opt: Opt,
// 	// },
// 	Client, // {
// 	        // #[structopt(subcommand)]
// 	        // opt: Opt,
// 	        // }
// }

// // Options
// // #[derive(Debug, StructOpt)]
// // struct Opt {
// // 	#[structopt(long)]
// // 	port: u32,
// // 	#[structopt(long)]
// // 	cid: u32,
// // }

// fn main() -> Result<(), io::IOError> {
// 	ctrlc::set_handler(move || {
// 		std::process::exit(1);
// 	})
// 	.expect("Error setting Ctrl-C handler");

// 	println!("enter bin");

// 	match Cmd::from_args() {
// 		Cmd::Server => {
// 			println!("server");
// 			server::ClientServer::try_serve(SERVER_CID, SERVER_PORT)?
// 		}
// 		Cmd::Client => {
// 			println!("client");

// 			let server =
// 				server::ClientServer::try_connect(SERVER_CID, SERVER_PORT)?;

// 			server.send_buf(&b"HELLO WORLD :)".to_vec())?;

// 			let resp = server.recv_buf()?;
// 			println!("Received: {:?}", resp);
// 		}
// 	}

// 	println!("exiting");

// 	Ok(())
// }
