use std::fs;

use integration::{
	wait_for_usock, PIVOT_ABORT_PATH, PIVOT_OK_PATH, PIVOT_PANIC_PATH,
	PIVOT_POOL_SIZE_PATH,
};
use qos_core::{
	handles::Handles,
	io::{SocketAddress, StreamPool},
	protocol::services::boot::ManifestEnvelope,
	reaper::{Reaper, REAPER_EXIT_DELAY},
};
use qos_nsm::mock::MockNsm;
use qos_test_primitives::PathWrapper;

#[tokio::test]
async fn reaper_works() {
	let secret_path: PathWrapper = "/tmp/reaper_works.secret".into();
	// let eph_path = "reaper_works.eph.key";
	let usock: PathWrapper = "/tmp/reaper_works.sock".into();
	let manifest_path: PathWrapper = "/tmp/reaper_works.manifest".into();
	let msg = "durp-a-durp";

	// For our sanity, ensure the secret does not yet exist
	drop(fs::remove_file(&*secret_path));

	let handles = Handles::new(
		"eph_path".to_string(),
		(*secret_path).to_string(),
		(*manifest_path).to_string(),
		PIVOT_OK_PATH.to_string(),
	);

	// Make sure we have written everything necessary to pivot, except the
	// quorum key
	let mut manifest_envelope = ManifestEnvelope::default();
	manifest_envelope.manifest.pivot.args =
		vec!["--msg".to_string(), msg.to_string()];
	manifest_envelope.manifest.client_timeout_ms = Some(2000); // check if this gets applied

	handles.put_manifest_envelope(&manifest_envelope).unwrap();
	assert!(handles.pivot_exists());

	let enclave_pool =
		StreamPool::new(SocketAddress::new_unix(&usock), 1).unwrap();

	let app_pool =
		StreamPool::new(SocketAddress::new_unix("./never.sock"), 1).unwrap();

	let reaper_handle = tokio::spawn(async move {
		Reaper::execute(
			&handles,
			Box::new(MockNsm),
			enclave_pool,
			app_pool,
			None,
		)
		.await;
	});

	// Give the enclave server time to bind to the socket
	tokio::time::sleep(std::time::Duration::from_secs(1)).await;

	// Check that the reaper is still running, presumably waiting for
	// the secret.
	assert!(!reaper_handle.is_finished());

	// Create the file with the secret, which should cause the reaper
	// to start executable.
	fs::write(&*secret_path, b"super dank tank secret tech").unwrap();

	// Make the sure the reaper executed successfully.
	reaper_handle.await.unwrap();
	let contents = fs::read(integration::PIVOT_OK_SUCCESS_FILE).unwrap();
	assert_eq!(std::str::from_utf8(&contents).unwrap(), msg);
	assert!(fs::remove_file(integration::PIVOT_OK_SUCCESS_FILE).is_ok());
}

#[tokio::test]
async fn reaper_handles_non_zero_exits() {
	let secret_path: PathWrapper =
		"/tmp/reaper_handles_non_zero_exits.secret".into();
	let usock: PathWrapper = "/tmp/reaper_handles_non_zero_exits.sock".into();
	let manifest_path: PathWrapper =
		"/tmp/reaper_handles_non_zero_exits.manifest".into();

	// For our sanity, ensure the secret does not yet exist
	drop(fs::remove_file(&*secret_path));

	let handles = Handles::new(
		"eph_path".to_string(),
		(*secret_path).to_string(),
		(*manifest_path).to_string(),
		PIVOT_ABORT_PATH.to_string(),
	);

	// Make sure we have written everything necessary to pivot, except the
	// quorum key
	handles.put_manifest_envelope(&Default::default()).unwrap();
	assert!(handles.pivot_exists());

	let enclave_pool =
		StreamPool::new(SocketAddress::new_unix(&usock), 1).unwrap();

	let app_pool =
		StreamPool::new(SocketAddress::new_unix("./never.sock"), 1).unwrap();

	let reaper_handle = tokio::spawn(async move {
		Reaper::execute(
			&handles,
			Box::new(MockNsm),
			enclave_pool,
			app_pool,
			None,
		)
		.await;
	});

	// Give the enclave server time to bind to the socket
	tokio::time::sleep(std::time::Duration::from_secs(1)).await;

	// Check that the reaper is still running, presumably waiting for
	// the secret.
	assert!(!reaper_handle.is_finished());

	// Create the file with the secret, which should cause the reaper
	// to start executable.
	fs::write(&*secret_path, b"super dank tank secret tech").unwrap();

	// Ensure the reaper has enough time to detect the secret, launch the
	// pivot, and let the pivot exit.
	tokio::time::sleep(REAPER_EXIT_DELAY * 2).await;

	assert!(reaper_handle.is_finished());
}

#[tokio::test]
async fn reaper_handles_panic() {
	let secret_path: PathWrapper = "/tmp/reaper_handles_panics.secret".into();
	let usock: PathWrapper = "/tmp/reaper_handles_panics.sock".into();
	let manifest_path: PathWrapper =
		"/tmp/reaper_handles_panics.manifest".into();

	// For our sanity, ensure the secret does not yet exist
	drop(fs::remove_file(&*secret_path));

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

	let enclave_pool =
		StreamPool::new(SocketAddress::new_unix(&usock), 1).unwrap();

	let app_pool =
		StreamPool::new(SocketAddress::new_unix("./never.sock"), 1).unwrap();

	let reaper_handle = tokio::spawn(async move {
		Reaper::execute(
			&handles,
			Box::new(MockNsm),
			enclave_pool,
			app_pool,
			None,
		)
		.await;
	});

	// Give the enclave server time to bind to the socket
	tokio::time::sleep(std::time::Duration::from_secs(1)).await;

	// Check that the reaper is still running, presumably waiting for
	// the secret.
	assert!(!reaper_handle.is_finished());

	// Create the file with the secret, which should cause the reaper
	// to start executable.
	fs::write(&*secret_path, b"super dank tank secret tech").unwrap();

	// Ensure the reaper has enough time to detect the secret, launch the
	// pivot, and let the pivot exit.
	tokio::time::sleep(REAPER_EXIT_DELAY * 2).await;

	assert!(reaper_handle.is_finished());
}

#[tokio::test]
async fn reaper_handles_pool_size() {
	let secret_path: PathWrapper =
		"/tmp/reaper_handles_pool_size.secret".into();
	// let eph_path = "reaper_works.eph.key";
	let usock: PathWrapper = "/tmp/reaper_handles_pool_size.sock".into();
	let manifest_path: PathWrapper =
		"/tmp/reaper_handles_pool_size.manifest".into();
	let msg = "5"; // must match pool-size in manifest bellow (test thing)

	// For our sanity, ensure the secret does not yet exist
	drop(fs::remove_file(&*secret_path));

	let handles = Handles::new(
		"eph_path".to_string(),
		(*secret_path).to_string(),
		(*manifest_path).to_string(),
		PIVOT_POOL_SIZE_PATH.to_string(),
	);

	// Make sure we have written everything necessary to pivot, except the
	// quorum key
	let mut manifest_envelope = ManifestEnvelope::default();
	manifest_envelope.manifest.pivot.args =
		vec!["--msg".to_string(), msg.to_string()];
	// set a pool size > 1
	manifest_envelope.manifest.pool_size = Some(5);

	handles.put_manifest_envelope(&manifest_envelope).unwrap();
	assert!(handles.pivot_exists());

	let enclave_pool =
		StreamPool::single(SocketAddress::new_unix(&usock)).unwrap();

	let app_pool =
		StreamPool::single(SocketAddress::new_unix("/tmp/never.sock")).unwrap();

	let reaper_handle = tokio::spawn(async move {
		Reaper::execute(
			&handles,
			Box::new(MockNsm),
			enclave_pool,
			app_pool,
			None,
		)
		.await;
	});

	// wait for enclave to listen
	wait_for_usock(&usock).await;

	// Check that the reaper is still running, presumably waiting for
	// the secret.
	assert!(!reaper_handle.is_finished());

	// Create the file with the secret, which should cause the reaper
	// to start executable.
	fs::write(&*secret_path, b"super dank tank secret tech").unwrap();

	// Make the sure the reaper executed successfully.
	reaper_handle.await.unwrap();
	let contents = fs::read(integration::PIVOT_POOL_SIZE_SUCCESS_FILE).unwrap();
	assert_eq!(std::str::from_utf8(&contents).unwrap(), msg);
	assert!(fs::remove_file(integration::PIVOT_POOL_SIZE_SUCCESS_FILE).is_ok());
}

#[test]
fn can_restart_panicking_pivot() {
	// Create a manifest with restart option

	// Create a different panicking pivot

	// Start reaper

	// Make sure it hasn't finished

	// Write the secret
}
