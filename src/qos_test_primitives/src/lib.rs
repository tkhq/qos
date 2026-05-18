//! Primitive types for test setup.

use std::{
	net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream},
	ops::{Deref, DerefMut},
	path::Path,
	process::Child,
	thread,
	time::Duration,
};

const MAX_PORT_BIND_WAIT_TIME: Duration = Duration::from_secs(5);
const PORT_BIND_WAIT_TIME_INCREMENT: Duration = Duration::from_millis(500);
const POST_BIND_SLEEP: Duration = Duration::from_millis(500);
const FIND_FREE_PORT_RETRY_DELAY: Duration = Duration::from_millis(50);
const MAX_FIND_FREE_PORT_ATTEMPTS: usize = 50;
const EXIT_DELAY: Duration = Duration::from_millis(50);

/// Wrapper type for [`std::process::Child`] that kills the process on drop.
#[derive(Debug)]
pub struct ChildWrapper(Child);

impl From<Child> for ChildWrapper {
	fn from(child: Child) -> Self {
		Self(child)
	}
}

impl Deref for ChildWrapper {
	type Target = Child;

	fn deref(&self) -> &Self::Target {
		&self.0
	}
}

impl DerefMut for ChildWrapper {
	fn deref_mut(&mut self) -> &mut Self::Target {
		&mut self.0
	}
}

impl Drop for ChildWrapper {
	fn drop(&mut self) {
		#[cfg(unix)]
		{
			use nix::{sys::signal::Signal::SIGINT, unistd::Pid};
			let pid = Pid::from_raw(self.0.id() as i32);
			match nix::sys::signal::kill(pid, SIGINT) {
				Ok(()) => {}
				Err(err) => eprintln!("error sending signal to child: {err}"),
			}

			// allow clean exit
			std::thread::sleep(EXIT_DELAY);
		}

		// Kill the process and explicitly ignore the result
		drop(self.0.kill());
	}
}

/// Generic wrapper type for anything that implements [`std::convert::AsRef<std::path::Path>`] that attempts to remove a file or
/// directory at the path on drop.
#[derive(Debug)]
pub struct PathWrapper<P: AsRef<Path>>(P);

impl<P: AsRef<Path>> From<P> for PathWrapper<P> {
	fn from(value: P) -> Self {
		Self(value)
	}
}

impl<P: AsRef<Path>> Drop for PathWrapper<P> {
	fn drop(&mut self) {
		// will always fail
		drop(std::fs::remove_dir_all(&self.0));
		drop(std::fs::remove_file(&self.0));
	}
}

impl<P: AsRef<Path>> Deref for PathWrapper<P> {
	type Target = Path;

	fn deref(&self) -> &Self::Target {
		self.as_ref()
	}
}

impl<P: AsRef<Path>> AsRef<Path> for PathWrapper<P> {
	fn as_ref(&self) -> &Path {
		self.0.as_ref()
	}
}

/// Get a bind-able TCP port on the local system.
#[must_use]
pub fn find_free_port() -> Option<u16> {
	let mut last_err = None;

	for _ in 0..MAX_FIND_FREE_PORT_ATTEMPTS {
		match TcpListener::bind(("127.0.0.1", 0)) {
			Ok(listener) => {
				return listener.local_addr().ok().map(|addr| addr.port());
			}
			Err(err) => {
				last_err = Some(err);
				thread::sleep(FIND_FREE_PORT_RETRY_DELAY);
			}
		}
	}

	if let Some(err) = last_err {
		eprintln!("failed to find free port: {err}");
	}

	None
}

/// Wait until the given `port` is bound. Helpful for telling if something is
/// listening on the given port.
///
/// # Panics
///
/// Panics if the port is not bound to within `MAX_PORT_BIND_WAIT_TIME`.
pub fn wait_until_port_is_bound(port: u16) {
	let mut wait_time = PORT_BIND_WAIT_TIME_INCREMENT;

	while wait_time < MAX_PORT_BIND_WAIT_TIME {
		thread::sleep(wait_time);
		if !can_connect_to_port(port) {
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

/// Return whether or not a server is accepting connections on the given port.
fn can_connect_to_port(port: u16) -> bool {
	let addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, port);
	TcpStream::connect_timeout(&addr.into(), Duration::from_millis(100)).is_ok()
}
