//! Primitive types for test setup.

use std::{
	net::TcpListener,
	ops::{Deref, Range},
	thread,
	time::Duration,
};

use rand::prelude::*;

const MAX_PORT_BIND_WAIT_TIME: Duration = Duration::from_secs(90);
const PORT_BIND_WAIT_TIME_INCREMENT: Duration = Duration::from_millis(500);
const POST_BIND_SLEEP: Duration = Duration::from_millis(500);
const SERVER_PORT_RANGE: Range<u16> = 10000..60000;
const MAX_PORT_SEARCH_ATTEMPTS: u16 = 50;

/// Wrapper type for [`std::process::Child`] that kills the process on drop.
#[derive(Debug)]
pub struct ChildWrapper(std::process::Child);

impl From<std::process::Child> for ChildWrapper {
	fn from(child: std::process::Child) -> Self {
		Self(child)
	}
}

impl Drop for ChildWrapper {
	fn drop(&mut self) {
		// Kill the process and explicitly ignore the result
		drop(self.0.kill());
	}
}

#[derive(Debug)]
enum Internal<'a> {
	String(String),
	Str(&'a str),
}

/// Wrapper type for [`std::path::Path`] that attempts to remove a file or
/// directory at the path on drop.
#[derive(Debug)]
pub struct PathWrapper<'a>(Internal<'a>);

impl<'a> From<&'a str> for PathWrapper<'a> {
	fn from(path: &'a str) -> Self {
		Self(Internal::Str(path))
	}
}

impl<'a> From<String> for PathWrapper<'a> {
	fn from(path: String) -> Self {
		Self(Internal::String(path))
	}
}

impl<'a> Drop for PathWrapper<'a> {
	fn drop(&mut self) {
		let path = match &self.0 {
			Internal::String(i) => i,
			Internal::Str(i) => *i,
		};

		// Try removing it both as a file and as a directory. One of these
		// will always fail
		drop(std::fs::remove_dir_all(path));
		drop(std::fs::remove_file(path));
	}
}

impl<'a> Deref for PathWrapper<'a> {
	type Target = str;

	fn deref(&self) -> &Self::Target {
		match &self.0 {
			Internal::String(i) => i,
			Internal::Str(i) => i,
		}
	}
}

/// Get a bind-able TCP port on the local system.
#[must_use]
pub fn find_free_port() -> Option<u16> {
	let mut rng = rand::thread_rng();
	for _ in 0..MAX_PORT_SEARCH_ATTEMPTS {
		let port = rng.gen_range(SERVER_PORT_RANGE);
		if port_is_available(port) {
			return Some(port);
		}
	}

	None
}

/// Wait until the given `port` is bound. Helpful for telling if something is
/// listening on the given port.
///
/// # Panics
///
/// Panics if the the port is not bound to within `MAX_PORT_BIND_WAIT_TIME`.
pub fn wait_until_port_is_bound(port: u16) {
	let mut wait_time = PORT_BIND_WAIT_TIME_INCREMENT;

	while wait_time < MAX_PORT_BIND_WAIT_TIME {
		thread::sleep(wait_time);
		if port_is_available(port) {
			wait_time += PORT_BIND_WAIT_TIME_INCREMENT;
		} else {
			thread::sleep(POST_BIND_SLEEP);
			return;
		}
	}
	panic!(
		"Server has not come up: port {} is still available after {}s",
		port,
		MAX_PORT_BIND_WAIT_TIME.as_secs()
	)
}

/// Return wether or not the port can be bind-ed too.
fn port_is_available(port: u16) -> bool {
	TcpListener::bind(("127.0.0.1", port)).is_ok()
}
