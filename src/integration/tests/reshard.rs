//! One-file integration test for the reshard stack (simulator_enclave + reshard_app + reshard_host).

#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(missing_docs)]

use std::{fs, path::PathBuf, process::Command};

use borsh::to_vec as borsh_to_vec;
use futures::future::FutureExt;
use generated::grpc::health::v1::{
    health_check_response::ServingStatus, health_client::HealthClient, HealthCheckRequest,
};
use generated::services::health_check::v1::health_check_service_client::HealthCheckServiceClient;
use generated::services::reshard::v1::{
    reshard_service_client::ReshardServiceClient, RetrieveReshardRequest,
};
use qos_core::protocol::services::boot::{Manifest, ManifestEnvelope};
use qos_hex::encode as hex_encode;
use qos_p256::P256Pair;
use rand::{thread_rng, Rng};
use tonic::transport::Channel;

/// Local host IP address.
pub const LOCAL_HOST: &str = "127.0.0.1";
/// Path to the enclave simulator binary.
const SIMULATOR_ENCLAVE_PATH: &str = "../target/debug/simulator_enclave";
/// Max gRPC message size (25MB).
pub const GRPC_MAX_RECV_MSG_SIZE: usize = 26_214_400;

/// Arguments passed to the user test callback.
#[derive(Default)]
pub struct TestArgs {
    /// Reshard gRPC client.
    pub reshard_client: Option<ReshardServiceClient<Channel>>,
    /// Reshard host base address (e.g., `http://127.0.0.1:PORT`).
    pub reshard_client_addr: Option<String>,
    /// App health client.
    pub health_check_client: Option<HealthCheckServiceClient<Channel>>,
    /// Canonical k8s health client.
    pub k8_health_client: Option<HealthClient<Channel>>,
}

/// Kills a child process on drop.
#[derive(Debug)]
pub struct ChildWrapper(std::process::Child);
impl From<std::process::Child> for ChildWrapper {
    fn from(child: std::process::Child) -> Self {
        Self(child)
    }
}
impl Drop for ChildWrapper {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Minimal harness builder living in this file.
#[derive(Default)]
pub struct Builder {
    setup_reshard: bool,
}

impl Builder {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set up reshard enclave/app/host.
    #[must_use]
    pub fn setup_reshard(mut self) -> Self {
        self.setup_reshard = true;
        self
    }

    /// Bring up the stack, run `test`, then tear down.
    pub async fn execute<F, T>(self, test: F)
    where
        F: Fn(TestArgs) -> T,
        T: std::future::Future<Output = ()>,
    {
        let test_id = format!("{:016x}", thread_rng().gen::<u64>());
        let mut process_handles: Vec<ChildWrapper> = vec![];
        let mut file_handles: Vec<PathBuf> = vec![];
        let mut test_args = TestArgs::default();

        if self.setup_reshard {
            // Socket paths
            let app_sock = PathBuf::from(format!("./{test_id}.reshard.app.sock"));
            let enc_sock = PathBuf::from(format!("./{test_id}.reshard.enclave.sock"));
            file_handles.extend([app_sock.clone(), enc_sock.clone()]);

            // Minimal manifest envelope (borsh) on disk
            let manifest_path = PathBuf::from(format!("./{test_id}.manifest_envelope"));
            write_minimal_manifest(&manifest_path);
            file_handles.push(manifest_path.clone());

            // ShareSet JSON (threshold 2 of 3)
            let share_set_json = make_share_set_json(3, 2);

            // 1) simulator_enclave
            let sim: ChildWrapper = Command::new(SIMULATOR_ENCLAVE_PATH)
                .arg(&enc_sock)
                .arg(&app_sock)
                .spawn()
                .expect("spawn simulator_enclave")
                .into();
            process_handles.push(sim);

            // 2) reshard_app
            let quorum_secret = "./fixtures/reshard/quorum.secret";
            let ephemeral_secret = "./fixtures/reshard/ephemeral.secret";
            let app: ChildWrapper = Command::new("../target/debug/reshard_app")
                .arg("--usock")
                .arg(&app_sock)
                .arg("--quorum-file")
                .arg(quorum_secret)
                .arg("--ephemeral-file")
                .arg(ephemeral_secret)
                .arg("--manifest-file")
                .arg(&manifest_path)
                .arg("--new-share-set")
                .arg(&share_set_json)
                .arg("--mock-nsm")
                .spawn()
                .expect("spawn reshard_app")
                .into();
            process_handles.push(app);

            // 3) reshard_host
            let host_port = qos_test_primitives::find_free_port().expect("find free port");
            let host: ChildWrapper = Command::new("../target/debug/reshard_host")
                .arg("--host-ip")
                .arg(LOCAL_HOST)
                .arg("--host-port")
                .arg(host_port.to_string())
                .arg("--usock")
                .arg(&enc_sock)
                .spawn()
                .expect("spawn reshard_host")
                .into();
            process_handles.push(host);
            qos_test_primitives::wait_until_port_is_bound(host_port);

            let host_addr = format!("http://{LOCAL_HOST}:{host_port}");
            test_args.reshard_client_addr = Some(host_addr.clone());

            // Clients
            let health = HealthCheckServiceClient::connect(host_addr.clone()).await.unwrap();
            test_args.health_check_client = Some(health);
            let k8 = HealthClient::connect(host_addr.clone()).await.unwrap();
            test_args.k8_health_client = Some(k8);
            let reshard = ReshardServiceClient::connect(host_addr)
                .await
                .unwrap()
                .max_decoding_message_size(GRPC_MAX_RECV_MSG_SIZE);
            test_args.reshard_client = Some(reshard);
        }

        // Run the user test and ensure cleanup.
        let res = std::panic::AssertUnwindSafe(test(test_args))
            .catch_unwind()
            .await;

        for p in file_handles {
            let _ = fs::remove_file(p);
        }

        assert!(res.is_ok(), "test body panicked");
    }
}

/// Write a minimal borsh-encoded `ManifestEnvelope` to `path`.
fn write_minimal_manifest(path: &PathBuf) {
    let env = ManifestEnvelope {
        manifest: Manifest { ..Default::default() },
        ..Default::default()
    };
    let bytes = borsh_to_vec(&env).expect("borsh ManifestEnvelope");
    fs::write(path, bytes).expect("write manifest");
}

/// Build ShareSet JSON (threshold `t` of `n`) from ephemeral P256 pubkeys.
fn make_share_set_json(n: usize, t: usize) -> String {
    assert!(t > 0 && t <= n);
    let members: Vec<String> = (0..n)
        .map(|i| {
            let pk_hex = hex_encode(&P256Pair::generate().unwrap().public_key().to_bytes());
            format!(r#"{{"alias":"reshard-{i}","pubKey":"{pk_hex}"}}"#)
        })
        .collect();
    format!(r#"{{"threshold":{t},"members":[{}]}}"#, members.join(","))
}

/// Optional helper if you want to assert canonical k8s health too.
pub async fn k8_health(mut k8: HealthClient<Channel>) {
    let live = k8
        .check(tonic::Request::new(HealthCheckRequest {
            service: "liveness".to_string(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(live.status, ServingStatus::Serving as i32);

    let ready = k8
        .check(tonic::Request::new(HealthCheckRequest {
            service: "readiness".to_string(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(ready.status, ServingStatus::Serving as i32);
}

#[tokio::test]
async fn reshard_e2e_json() {
    async fn test(mut args: TestArgs) {
        let mut client: ReshardServiceClient<_> = args.reshard_client.take().unwrap();

        let resp = client
            .retrieve_reshard(tonic::Request::new(RetrieveReshardRequest {}))
            .await
            .unwrap()
            .into_inner();

        assert!(
            !resp.reshard_bundle.is_empty(),
            "server returned empty JSON"
        );
        
        let v: serde_json::Value =
            serde_json::from_str(&resp.reshard_bundle).expect("valid JSON");
        for key in ["quorumPublicKey", "memberOutputs", "manifest", "signature"] {
            assert!(v.get(key).is_some(), "missing `{key}` in reshard bundle JSON");
        }

        println!(
            "{}",
            serde_json::to_string_pretty(&v).expect("pretty json")
        );

    }

    Builder::new().setup_reshard().execute(test).await;
}
