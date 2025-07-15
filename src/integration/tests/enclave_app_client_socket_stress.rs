use borsh::BorshDeserialize;
use integration::{
	wait_for_usock, PivotSocketStressMsg, PIVOT_SOCKET_STRESS_PATH,
};
use qos_core::{
	async_client::AsyncClient,
	handles::Handles,
	io::{AsyncStreamPool, SocketAddress, TimeVal, TimeValLike},
	protocol::{
		msg::ProtocolMsg,
		services::boot::{
			Manifest, ManifestEnvelope, ManifestSet, Namespace, NitroConfig,
			PivotConfig, RestartPolicy, ShareSet,
		},
		ProtocolError, ProtocolPhase, ENCLAVE_APP_SOCKET_CLIENT_TIMEOUT_SECS,
	},
	reaper::{Reaper, REAPER_RESTART_DELAY_IN_SECONDS},
};
use qos_nsm::mock::MockNsm;
use qos_p256::P256Pair;
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

	let p256_pair = P256Pair::generate().unwrap();
	// Enclave app already exists, but we need to add a quorum key and manifest
	// envelope so the reaper pivots.
	handles.put_manifest_envelope(&manifest_envelope).unwrap();
	handles.put_quorum_key(&p256_pair).unwrap();

	let enclave_pool =
		AsyncStreamPool::new(SocketAddress::new_unix(ENCLAVE_SOCK), 1).unwrap();

	let app_pool =
		AsyncStreamPool::new(SocketAddress::new_unix(APP_SOCK), 1).unwrap();

	std::thread::spawn(move || {
		Reaper::execute(
			&handles,
			Box::new(MockNsm),
			enclave_pool,
			app_pool,
			// Force the phase to quorum key provisioned so message proxy-ing
			// works
			Some(ProtocolPhase::QuorumKeyProvisioned),
		)
	});

	// Make sure the pivot has some time to start up
	wait_for_usock(APP_SOCK).await;

	let enclave_client_pool =
		AsyncStreamPool::new(SocketAddress::new_unix(ENCLAVE_SOCK), 1).unwrap();
	let enclave_client = AsyncClient::new(
		enclave_client_pool.shared(),
		TimeVal::seconds(ENCLAVE_APP_SOCKET_CLIENT_TIMEOUT_SECS + 3), // needs to be bigger than the slow request below + some time for recovery
	);

	let app_request =
		borsh::to_vec(&PivotSocketStressMsg::PanicRequest).unwrap();
	let request =
		borsh::to_vec(&ProtocolMsg::ProxyRequest { data: app_request })
			.unwrap();
	let raw_response = enclave_client.call(&request).await.unwrap();
	let response = ProtocolMsg::try_from_slice(&raw_response).unwrap();

	assert_eq!(
		response,
		ProtocolMsg::ProtocolErrorResponse(
			ProtocolError::AppClientRecvConnectionClosed
		)
	);

	tokio::time::sleep(std::time::Duration::from_secs(
		REAPER_RESTART_DELAY_IN_SECONDS + 1,
	))
	.await;
	// The pivot panicked and should have been restarted.
	let app_request = borsh::to_vec(&PivotSocketStressMsg::OkRequest).unwrap();
	let request =
		borsh::to_vec(&ProtocolMsg::ProxyRequest { data: app_request })
			.unwrap();
	let raw_response = enclave_client.call(&request).await.unwrap();
	let response = {
		let msg = ProtocolMsg::try_from_slice(&raw_response).unwrap();
		let data = match msg {
			ProtocolMsg::ProxyResponse { data } => data,
			x => panic!("Expected proxy response, got {x:?}"),
		};
		PivotSocketStressMsg::try_from_slice(&data).unwrap()
	};
	assert_eq!(response, PivotSocketStressMsg::OkResponse);

	// Send a request that the app will take too long to respond to
	let app_request =
		borsh::to_vec(&PivotSocketStressMsg::SlowRequest(5500)).unwrap();
	let request =
		borsh::to_vec(&ProtocolMsg::ProxyRequest { data: app_request })
			.unwrap();
	let raw_response = enclave_client.call(&request).await.unwrap();
	let response = ProtocolMsg::try_from_slice(&raw_response).unwrap();
	assert_eq!(
		response,
		ProtocolMsg::ProtocolErrorResponse(ProtocolError::AppClientRecvTimeout)
	);
}
