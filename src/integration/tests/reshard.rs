//! One-file integration test for the reshard stack (simulator_enclave + reshard_app + reshard_host).

#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(missing_docs)]

use std::{fs, path::PathBuf, process::Command};
use reshard_app::ReshardBundle;

use borsh::to_vec as borsh_to_vec;
use futures::future::FutureExt;
use generated::services::reshard::v1::reshard_service_client::ReshardServiceClient;
use generated::services::reshard::v1::RetrieveReshardRequest;
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
            let share_set_json = std::fs::read_to_string("./fixtures/reshard/new-share-set/new-share-set.json")
                .expect("read new-share-set.json");
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
        // Make sure we can rehydrate the bundle
        let bundle: ReshardBundle =
            serde_json::from_str(&resp.reshard_bundle).expect("valid JSON");

        println!(
            "{}",
            serde_json::to_string_pretty(&v).expect("pretty json")
        );

        // Decrypt each member's share using the fixture private keys
        let secrets_dir = PathBuf::from("./fixtures/reshard/new-share-set-secrets");
        let mut shares: Vec<Vec<u8>> = Vec::with_capacity(bundle.member_outputs.len());
        for m in bundle.member_outputs.iter() {
            let alias = m.share_set_member.alias.clone();
            let sk_path = secrets_dir.join(format!("{alias}.secret"));
            let pair = P256Pair::from_hex_file(sk_path.to_str().unwrap())
                .expect("load member private key");
            let pt = pair.decrypt(&m.encrypted_quorum_key_share)
                .expect("decrypt share");

            // integrity: verify hash matches
            assert_eq!(
                qos_crypto::sha_512(&pt),
                m.share_hash,
                "share hash mismatch for {alias}",
            );

            shares.push(pt);
        }

        let quorum_secret_path = "./fixtures/reshard/quorum.secret";
        let expected_pair = qos_p256::P256Pair::from_hex_file(
            quorum_secret_path
        ).expect("load quorum.secret");
        let expected_pub = expected_pair.public_key().to_bytes();
        let mut found = false;
        let k: usize = bundle.manifest_envelope.manifest.share_set.threshold
            .try_into()
            .expect("threshold doesn't fit into usize");

        for combo in qos_crypto::n_choose_k::combinations(&shares, k) {
            let seed_vec = qos_crypto::shamir::shares_reconstruct(&combo).unwrap();

            let seed: [u8; 32] = seed_vec
                .as_slice()
                .try_into()
                .expect("reconstructed seed must be 32 bytes");
                
            let quorum_key = P256Pair::from_master_seed(&seed).unwrap();

            assert_eq!(
                quorum_key.public_key().to_bytes(),
                expected_pub,
                "quorum key public mismatch",
            );
        }
    }

    Builder::new().setup_reshard().execute(test).await;
}
