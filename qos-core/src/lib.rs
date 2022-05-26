#![forbid(unsafe_code)]

pub mod cli;
pub use cli::CLI;

pub mod client;
pub mod coordinator;
pub mod io;
pub mod protocol;
pub mod server;

#[cfg(not(feature = "vm"))]
pub const SECRET_FILE: &str = "./qos.secret";
#[cfg(feature = "vm")]
pub const SECRET_FILE: &str = "/qos.secret";

#[cfg(not(feature = "vm"))]
pub const PIVOT_FILE: &str = "../target/debug/pivot_ok";
#[cfg(feature = "vm")]
pub const PIVOT_FILE: &str = "/qos.pivot";
