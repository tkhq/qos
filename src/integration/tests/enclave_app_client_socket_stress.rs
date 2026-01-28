use std::time::Duration;

use borsh::BorshDeserialize;
use integration::{
	wait_for_usock, PivotSocketStressMsg, PIVOT_SOCKET_STRESS_PATH,
};
use qos_core::{
	client::{ClientError, SocketClient},
	handles::Handles,
	io::{IOError, SocketAddress, StreamPool},
	protocol::{
		services::boot::{
			Manifest, ManifestEnvelope, ManifestSet, Namespace, NitroConfig,
			PivotConfig, RestartPolicy, ShareSet,
		},
		ProtocolPhase,
	},
	reaper::Reaper,
};
use qos_nsm::mock::MockNsm;
use qos_p256::QosKeySet;
use qos_test_primitives::PathWrapper;

const TEST_TMP: &str = "/tmp/enclave_app_client_socket_stress";
const ENCLAVE_SOCK: &str = "/tmp/enclave_app_client_socket_stress/enclave.sock";
const APP_SOCK: &str = "/tmp/enclave_app_client_socket_stress/app.sock";

#[tokio::test]
async fn enclave_app_client_socket_stress() {
	let _: PathWrapper = TEST_TMP.into();
	std::fs::create_dir_all(TEST_TMP).unwrap();

	let manifest = Manifest {
		namespace: Namespace {
			name: String::default(),
			nonce: 0,
			quorum_key: vec![],
		},
		pivot: PivotConfig {
			hash: [1; 32],
			restart: RestartPolicy::Always,
			args: vec![APP_SOCK.to_string()],
			..Default::default()
		},
		manifest_set: ManifestSet { threshold: 0, members: vec![] },
		share_set: ShareSet { threshold: 0, members: vec![] },
		enclave: NitroConfig {
			pcr0: vec![1; 32],
			pcr1: vec![1; 32],
			pcr2: vec![1; 32],
			pcr3: vec![1; 32],
			aws_root_certificate: vec![],
			qos_commit: String::default(),
		},
		..Default::default()
	};

	let manifest_envelope = ManifestEnvelope {
		manifest,
		manifest_set_approvals: vec![],
		share_set_approvals: vec![],
	};
	let manifest_path = "/tmp/enclave_app_client_socket_stress/manifest";
	let quorum_key_path =
		"/tmp/enclave_app_client_socket_stress/quorum_key.secret";

	let handles = Handles::new(
		"secret_path_never".to_string(),
		quorum_key_path.to_string(),
		manifest_path.to_string(),
		PIVOT_SOCKET_STRESS_PATH.to_string(),
	);

	let p256_pair = QosKeySet::generate().unwrap();
	// Enclave app already exists, but we need to add a quorum key and manifest
	// envelope so the reaper pivots.
	handles.put_manifest_envelope(&manifest_envelope).unwrap();
	handles.put_quorum_key(&p256_pair).unwrap();

	let enclave_socket = SocketAddress::new_unix(ENCLAVE_SOCK);

	tokio::spawn(async move {
		Reaper::execute(
			&handles,
			Box::new(MockNsm),
			enclave_socket,
			// Force the phase to quorum key provisioned so message proxy-ing
			// works
			Some(ProtocolPhase::QuorumKeyProvisioned),
		)
		.await;
	});

	// Make sure the pivot has some time to start up
	wait_for_usock(APP_SOCK).await;

	let app_client_pool =
		StreamPool::single(SocketAddress::new_unix(APP_SOCK)).unwrap();
	let app_client = SocketClient::new(
		app_client_pool.shared(),
		Duration::from_millis(2000),
	);

	let request = borsh::to_vec(&PivotSocketStressMsg::PanicRequest).unwrap();
	let raw_response = app_client.call(&request).await.unwrap_err();

	match raw_response {
		ClientError::IOError(IOError::RecvConnectionClosed) => {} // expected
		_ => panic!("unexpected error received: {raw_response:?}"),
	}

	// we need to give the panicking pivot time to quit and close the old socket before trying to see
	// if it restarted a new one. Since we don't know the PID we need to do a basic sleep here.
	tokio::time::sleep(Duration::from_millis(500)).await;

	// Make sure the pivot has some time to restart
	wait_for_usock(APP_SOCK).await;

	// The pivot panicked and should have been restarted.
	let request = borsh::to_vec(&PivotSocketStressMsg::OkRequest(1)).unwrap();
	let raw_response = app_client.call(&request).await.unwrap();
	let response = PivotSocketStressMsg::try_from_slice(&raw_response).unwrap();
	assert_eq!(response, PivotSocketStressMsg::OkResponse(1));

	// Send a request that the app will take too long to respond to
	let request =
		borsh::to_vec(&PivotSocketStressMsg::SlowRequest(2100)).unwrap();
	let raw_response = app_client.call(&request).await.unwrap_err();

	match raw_response {
		ClientError::IOError(IOError::RecvTimeout) => {} // expected
		_ => panic!("unexpected error received: {raw_response:?}"),
	}
}
