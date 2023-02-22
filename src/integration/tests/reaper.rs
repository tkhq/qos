use std::fs;

use integration::{PIVOT_ABORT_PATH, PIVOT_OK_PATH, PIVOT_PANIC_PATH};
use qos_core::{
	handles::Handles, io::SocketAddress,
	protocol::services::boot::ManifestEnvelope, reaper::Reaper,
};
use qos_nsm::mock::MockNsm;

#[test]
fn coordinator_works() {
	let secret_path = "./coordinator_works.secret";
	// let eph_path = "coordinator_works.eph.key";
	let usock = "./coordinator_works/coordinator_works.sock";
	let manifest_path = "coordinator_works.manifest";
	let msg = "durp-a-durp";

	// For our sanity, ensure the secret does not yet exist
	drop(fs::remove_file(secret_path));

	let handles = Handles::new(
		"eph_path".to_string(),
		secret_path.to_string(),
		manifest_path.to_string(),
		PIVOT_OK_PATH.to_string(),
	);

	// Make sure we have written everything necessary to pivot, except the
	// quorum key
	let mut manifest_envelope = ManifestEnvelope::default();
	manifest_envelope.manifest.pivot.args =
		vec!["--msg".to_string(), msg.to_string()];

	handles.put_manifest_envelope(&manifest_envelope).unwrap();
	assert!(handles.pivot_exists());

	let coordinator_handle = std::thread::spawn(move || {
		Reaper::execute(
			&handles,
			Box::new(MockNsm),
			SocketAddress::new_unix(usock),
			SocketAddress::new_unix("./never.sock"),
			None,
		)
	});

	// Give the enclave server time to bind to the socket
	std::thread::sleep(std::time::Duration::from_secs(1));

	// Check that the coordinator is still running, presumably waiting for
	// the secret.
	assert!(!coordinator_handle.is_finished());

	// Create the file with the secret, which should cause the coordinator
	// to start executable.
	fs::write(secret_path, b"super dank tank secret tech").unwrap();

	// Make the sure the coordinator executed successfully.
	coordinator_handle.join().unwrap();
	let contents = fs::read(integration::PIVOT_OK_SUCCESS_FILE).unwrap();
	assert_eq!(std::str::from_utf8(&contents).unwrap(), msg);
	assert!(fs::remove_file(integration::PIVOT_OK_SUCCESS_FILE).is_ok());

	// Clean up
	drop(fs::remove_file(secret_path));
	drop(fs::remove_file(usock));
	drop(fs::remove_file(manifest_path));
}

#[test]
fn coordinator_handles_non_zero_exits() {
	let secret_path = "./coordinator_handles_non_zero_exits.secret";
	let usock = "./coordinator_handles_non_zero_exits.sock";
	let manifest_path = "./coordinator_handles_non_zero_exits.manifest";

	// For our sanity, ensure the secret does not yet exist
	drop(fs::remove_file(secret_path));

	let handles = Handles::new(
		"eph_path".to_string(),
		secret_path.to_string(),
		manifest_path.to_string(),
		PIVOT_ABORT_PATH.to_string(),
	);

	// Make sure we have written everything necessary to pivot, except the
	// quorum key
	handles.put_manifest_envelope(&Default::default()).unwrap();
	assert!(handles.pivot_exists());

	let coordinator_handle = std::thread::spawn(move || {
		Reaper::execute(
			&handles,
			Box::new(MockNsm),
			SocketAddress::new_unix(usock),
			SocketAddress::new_unix("./never.sock"),
			None,
		)
	});

	// Give the enclave server time to bind to the socket
	std::thread::sleep(std::time::Duration::from_secs(1));

	// Check that the coordinator is still running, presumably waiting for
	// the secret.
	assert!(!coordinator_handle.is_finished());

	// Create the file with the secret, which should cause the coordinator
	// to start executable.
	fs::write(secret_path, b"super dank tank secret tech").unwrap();

	// Ensure the coordinator has enough time to detect the secret, launch the
	// pivot, and let the pivot exit.
	std::thread::sleep(std::time::Duration::from_secs(2));

	assert!(coordinator_handle.is_finished());

	// Clean up
	drop(fs::remove_file(secret_path));
	drop(fs::remove_file(usock));
	drop(fs::remove_file(manifest_path));
}

#[test]
fn coordinator_handles_panic() {
	let secret_path = "./coordinator_handles_panics.secret";
	let usock = "./coordinator_handles_panics.sock";
	let manifest_path = "./coordinator_handles_panics.manifest";

	// For our sanity, ensure the secret does not yet exist
	drop(fs::remove_file(secret_path));

	let handles = Handles::new(
		"eph_path".to_string(),
		secret_path.to_string(),
		manifest_path.to_string(),
		PIVOT_PANIC_PATH.to_string(),
	);

	// Make sure we have written everything necessary to pivot, except the
	// quorum key
	handles.put_manifest_envelope(&Default::default()).unwrap();
	assert!(handles.pivot_exists());

	let coordinator_handle = std::thread::spawn(move || {
		Reaper::execute(
			&handles,
			Box::new(MockNsm),
			SocketAddress::new_unix(usock),
			SocketAddress::new_unix("./never.sock"),
			None,
		)
	});

	// Give the enclave server time to bind to the socket
	std::thread::sleep(std::time::Duration::from_secs(1));

	// Check that the coordinator is still running, presumably waiting for
	// the secret.
	assert!(!coordinator_handle.is_finished());

	// Create the file with the secret, which should cause the coordinator
	// to start executable.
	fs::write(secret_path, b"super dank tank secret tech").unwrap();

	// Ensure the coordinator has enough time to detect the secret, launch the
	// pivot, and let the pivot exit.
	std::thread::sleep(std::time::Duration::from_secs(2));

	assert!(coordinator_handle.is_finished());

	// Clean up
	drop(fs::remove_file(secret_path));
	drop(fs::remove_file(usock));
	drop(fs::remove_file(manifest_path));
}

#[test]
fn can_restart_panicking_pivot() {
	// Create a manifest with restart option

	// Create a different panicking pivot

	// Start coordinator

	// Make sure it hasn't finished

	// Write the secret
}
