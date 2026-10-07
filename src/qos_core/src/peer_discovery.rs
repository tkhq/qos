//! Untrusted host-provided peer list. The guest does not verify it.

use std::{
	collections::BTreeSet,
	fs::{self, File},
	io,
	net::IpAddr,
	os::unix::fs::FileExt,
	path::PathBuf,
};

/// Guest file holding the peer IP addresses as a newline-separated list.
pub const UNTRUSTED_PEERS_FILE: &str = "/run/qos/untrusted_host_provided_peers";

/// The published peer list. The file is created on the first update.
pub(crate) struct Peers {
	ips: BTreeSet<IpAddr>,
	path: PathBuf,
	file: Option<File>,
}

impl Peers {
	pub(crate) fn new(path: PathBuf) -> Self {
		Self { ips: BTreeSet::new(), path, file: None }
	}

	/// Apply `change` and rewrite the file in place. On error the list is
	/// unchanged.
	pub(crate) fn update(
		&mut self,
		change: impl FnOnce(&mut BTreeSet<IpAddr>),
	) -> io::Result<()> {
		let mut ips = self.ips.clone();
		change(&mut ips);
		let contents: String =
			ips.iter().map(|ip| ip.to_string() + "\n").collect();

		if self.file.is_none() {
			// Only create the directory if creating the file fails.
			let file = File::create(&self.path).or_else(|_| {
				if let Some(directory) = self.path.parent() {
					fs::create_dir_all(directory)?;
				}
				File::create(&self.path)
			})?;
			self.file = Some(file);
		}
		let Some(file) = &self.file else { unreachable!() };
		file.write_all_at(contents.as_bytes(), 0)?;
		file.set_len(contents.len() as u64)?;
		self.ips = ips;
		Ok(())
	}
}
