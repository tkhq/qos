use std::time::Duration;

use borsh::{ser::BorshSerialize, BorshDeserialize};
use integration::{
	PivotMaybePanicMsg, PIVOT_MAYBE_PANIC_PATH, PIVOT_MAYBE_PANIC_SOCK,
};
use qos_core::{
	client::Client,
	handles::Handles,
	io::SocketAddress,
	protocol::{
		msg::ProtocolMsg,
		services::boot::{
			Manifest, ManifestEnvelope, ManifestSet, Namespace, NitroConfig,
			PivotConfig, RestartPolicy, ShareSet,
		},
		ProtocolError, ProtocolPhase, ENCLAVE_APP_SOCKET_CLIENT_TIMEOUT_SECS,
	},
	reaper::Reaper,
};
use qos_nsm::mock::MockNsm;
use qos_p256::P256Pair;
use qos_test_primitives::PathWrapper;

const TEST_TMP: &str = "/tmp/enclave_app_client_timeout";
const ENCLAVE_SOCK: &str = "/tmp/enclave_app_client_timeout/enclave.sock";

#[test]
fn enclave_app_client_timeout() {
	let _: PathWrapper = TEST_TMP.into();
	std::fs::create_dir_all(TEST_TMP).unwrap();

	let manifest = Manifest {
		namespace: Namespace {
			name: String::default(),
			nonce: 0,
			quorum_key: vec![],
		},
		pivot: PivotConfig {
			commit: String::default(),
			hash: [1; 32],
			restart: RestartPolicy::Always,
			args: vec![],
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
	};

	let manifest_envelope = ManifestEnvelope {
		manifest,
		manifest_set_approvals: vec![],
		share_set_approvals: vec![],
	};
	let manifest_path = "/tmp/enclave_app_client_timeout/manifest";
	let quorum_key_path = "/tmp/enclave_app_client_timeout/quorum_key.secret";

	let handles = Handles::new(
		"secret_path_never".to_string(),
		quorum_key_path.to_string(),
		manifest_path.to_string(),
		PIVOT_MAYBE_PANIC_PATH.to_string(),
	);

	let p256_pair = P256Pair::generate().unwrap();
	// Enclave app already exists, but we need to add a quorum key and manifest
	// envelope so the reaper pivots.
	handles.put_manifest_envelope(&manifest_envelope).unwrap();
	handles.put_quorum_key(&p256_pair).unwrap();

	std::thread::spawn(move || {
		Reaper::execute(
			&handles,
			Box::new(MockNsm),
			SocketAddress::new_unix(ENCLAVE_SOCK),
			SocketAddress::new_unix(PIVOT_MAYBE_PANIC_SOCK),
			// Force the phase to quorum key provisioned so message proxy-ing works
			Some(ProtocolPhase::QuorumKeyProvisioned),
		)
	});

	let enclave_client = Client::new(
		SocketAddress::new_unix(ENCLAVE_SOCK),
		Duration::from_secs(ENCLAVE_APP_SOCKET_CLIENT_TIMEOUT_SECS + 1),
	);

	let app_request = PivotMaybePanicMsg::PanicRequest.try_to_vec().unwrap();
	let request =
		ProtocolMsg::ProxyRequest { data: app_request }.try_to_vec().unwrap();

	let raw_response = enclave_client.send_timeout(&request).unwrap();
	let response = ProtocolMsg::try_from_slice(&raw_response).unwrap();
	assert_eq!(
		response,
		ProtocolMsg::ProtocolErrorResponse(
			ProtocolError::AppClientTimeoutError
		)
	);

	// The pivot panicked and should have been restarted.
	let app_request = PivotMaybePanicMsg::OkRequest.try_to_vec().unwrap();
	let request =
		ProtocolMsg::ProxyRequest { data: app_request }.try_to_vec().unwrap();
	let raw_response = enclave_client.send_timeout(&request).unwrap();
	let response = {
		let msg = ProtocolMsg::try_from_slice(&raw_response).unwrap();
		let data = match msg {
			ProtocolMsg::ProxyResponse { data } => data,
			x => panic!("Expected proxy response, got {x:?}"),
		};
		PivotMaybePanicMsg::try_from_slice(&data).unwrap()
	};
	assert_eq!(response, PivotMaybePanicMsg::OkResponse);
}
