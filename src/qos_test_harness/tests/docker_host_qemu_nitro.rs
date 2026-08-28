mod support;

use std::{collections::BTreeMap, path::PathBuf, time::Duration};

use qos_core::protocol::services::boot::{
	EnclaveV3, ManifestV3, ManifestVersion, OciImageRef, OciName,
	OciRestartPolicy, WorkloadV3,
};
use qos_p256::P256Public;
use qos_test_harness::{
	BridgeConfig, BuildMode, DnsConfig, OciStartCondition, OciStartSpec, Pivot,
	RunningAppGuard, StartAppSpec, TestRunner, VersionedManifest,
};
use support::preparation::{
	DockerHostQemuNitroPreparation, PreparedDockerHostQemuNitro, QemuCiImages,
};

#[cfg(all(feature = "qemu-ci", feature = "impure-builder"))]
compile_error!("qemu-ci and impure-builder select different artifact sources");

const APP_ARGS: [&str; 4] = ["--host", "0.0.0.0", "--port", "3000"];
const HEALTH_PATH: &str = "/health";
const ECHO_PATH: &str = "/echo";
const GET_URL_PATH: &str = "/get_url";
const EGRESS_URL: &str = "https://example.com/";
const PROBE_TIMEOUT: Duration = Duration::from_secs(30);

#[tokio::test]
async fn signed_echo_ingress() {
	let (prepared, pivot) = prepare().await;
	let manifest = prepared
		.manifest_template(&pivot)
		.unwrap()
		.pivot_args(APP_ARGS.into_iter().map(str::to_string).collect())
		.bridge_config(vec![BridgeConfig::Server {
			port: 3000,
			host: "0.0.0.0".to_string(),
		}])
		.build()
		.unwrap();
	let mut runner = prepared.runner;
	let app = runner
		.start_app(StartAppSpec {
			name: "signed_echo".to_string(),
			artifact: pivot,
			manifest,
		})
		.await
		.unwrap();
	let ingress_url = app.app().ingress_url.clone();

	let result = async {
		wait_for_http_ok(&url(&ingress_url, HEALTH_PATH), PROBE_TIMEOUT)
			.await?;

		let (status, body) = response(
			ureq::post(&url(&ingress_url, ECHO_PATH)).send_string("hello"),
		)?;
		if status != 200 {
			return Err(format!("echo returned status {status}: {body}"));
		}
		verify_echo_response(&body)?;
		Ok(())
	}
	.await;
	let cleanup = app.stop().await;

	assert!(result.is_ok(), "ingress assertion failed: {result:?}");
	cleanup.unwrap();
}

#[tokio::test]
async fn signed_echo_egress_get_url() {
	let (prepared, pivot) = prepare().await;
	let manifest = prepared
		.manifest_template(&pivot)
		.unwrap()
		.pivot_args(APP_ARGS.into_iter().map(str::to_string).collect())
		.bridge_config(vec![
			BridgeConfig::Server { port: 3000, host: "0.0.0.0".to_string() },
			BridgeConfig::Client {
				port: 443,
				host: Some("example.com".to_string()),
			},
		])
		.dns(DnsConfig { resolvers: vec!["1.1.1.1".parse().unwrap()] })
		.build()
		.unwrap();
	let mut runner = prepared.runner;
	let app = runner
		.start_app(StartAppSpec {
			name: "signed_echo".to_string(),
			artifact: pivot,
			manifest,
		})
		.await
		.unwrap();
	let ingress_url = app.app().ingress_url.clone();

	let result = async {
		wait_for_http_ok(&url(&ingress_url, HEALTH_PATH), PROBE_TIMEOUT)
			.await?;
		let request_path = format!(
			"{GET_URL_PATH}?url={}",
			percent_encode_query_value(EGRESS_URL)
		);
		let body = wait_for_get_url_ok(
			&url(&ingress_url, &request_path),
			PROBE_TIMEOUT,
		)
		.await?;
		let response = verify_echo_response(&body)?;
		let payload: signed_echo::SignedGetUrlPayload = serde_json::from_str(
			&response.signed_payload_json,
		)
		.map_err(|err| format!("invalid signed get_url payload: {err}"))?;
		if payload.url != EGRESS_URL {
			return Err(format!(
				"signed get_url URL mismatch: expected {EGRESS_URL}, got {}",
				payload.url
			));
		}
		if !payload.body.contains("Example Domain") {
			return Err("signed get_url body did not contain Example Domain"
				.to_string());
		}
		Ok(())
	}
	.await;
	let cleanup = app.stop().await;

	assert!(result.is_ok(), "egress assertion failed: {result:?}");
	cleanup.unwrap();
}

#[tokio::test]
async fn postgres_oci_smoke_on_qemu() {
	let (prepared, _) = prepare().await;
	let image = prepared.postgres_smoke_image().unwrap();
	let base =
		prepared.manifest_template(&prepared.pivot).unwrap().build().unwrap();
	let VersionedManifest::V2(base) = base else {
		panic!("test manifest template must be V2");
	};
	let enclave = EnclaveV3::Nitro {
		pcr0: base.enclave.pcr0,
		pcr1: base.enclave.pcr1,
		pcr2: base.enclave.pcr2,
		pcr3: base.enclave.pcr3,
		aws_root_certificate: base.enclave.aws_root_certificate,
		qos_commit: base.enclave.qos_commit,
	};
	let manifest = ManifestV3 {
		version: ManifestVersion::V3,
		namespace: base.namespace,
		manifest_set: base.manifest_set,
		share_set: base.share_set,
		enclave,
		workloads: vec![WorkloadV3::Oci {
			name: OciName::try_from("postgres-smoke".to_string()).unwrap(),
			image: OciImageRef::OciManifest { digest: image.digest.clone() },
			restart: OciRestartPolicy::Never,
			mounts: vec![],
		}],
		volumes: BTreeMap::new(),
		dns: None,
	};
	manifest.validate().unwrap();
	let mut runner = prepared.runner;
	let app = runner
		.start_oci(OciStartSpec {
			name: "postgres_oci_smoke".into(),
			artifact: image,
			manifest: VersionedManifest::V3(manifest),
			condition: OciStartCondition::ExitSuccess,
		})
		.await
		.unwrap();
	app.stop().await.unwrap();
}

async fn prepare() -> (PreparedDockerHostQemuNitro, Pivot) {
	let root = workspace_root();
	let ci_images = if cfg!(feature = "qemu-ci") {
		Some(QemuCiImages::from_env().unwrap())
	} else {
		None
	};
	let build_mode = if cfg!(feature = "impure-builder") {
		BuildMode::Fast
	} else {
		BuildMode::Slow
	};
	let prepared = DockerHostQemuNitroPreparation {
		root: root.clone(),
		docker_bin: PathBuf::from("docker"),
		build_mode,
		ci_images,
	}
	.prepare()
	.await
	.unwrap();
	let pivot = prepared.pivot.clone();
	(prepared, pivot)
}

async fn wait_for_http_ok(url: &str, timeout: Duration) -> Result<(), String> {
	let start = std::time::Instant::now();
	let mut last_error = None;
	while start.elapsed() < timeout {
		match response(ureq::get(url).call()) {
			Ok((200, _)) => return Ok(()),
			Ok((status, body)) => {
				last_error = Some(format!("{url} returned {status}: {body}"));
			}
			Err(err) => last_error = Some(err),
		}
		tokio::time::sleep(Duration::from_secs(1)).await;
	}
	Err(last_error.unwrap_or_else(|| format!("timed out waiting for {url}")))
}

async fn wait_for_get_url_ok(
	url: &str,
	timeout: Duration,
) -> Result<String, String> {
	let start = std::time::Instant::now();
	let mut last_error = None;
	while start.elapsed() < timeout {
		match response(ureq::get(url).call()) {
			Ok((200, body)) => return Ok(body),
			Ok((status, body)) => {
				last_error = Some(format!("get_url returned {status}: {body}"));
			}
			Err(err) => last_error = Some(err),
		}
		tokio::time::sleep(Duration::from_secs(1)).await;
	}
	Err(last_error.unwrap_or_else(|| format!("timed out waiting for {url}")))
}

fn response(
	result: Result<ureq::Response, ureq::Error>,
) -> Result<(u16, String), String> {
	let response = match result {
		Ok(response) | Err(ureq::Error::Status(_, response)) => response,
		Err(err) => return Err(err.to_string()),
	};
	let status = response.status();
	let body = response.into_string().map_err(|err| err.to_string())?;
	Ok((status, body))
}

fn verify_echo_response(
	body: &str,
) -> Result<signed_echo::EchoResponse, String> {
	let response: signed_echo::EchoResponse = serde_json::from_str(body)
		.map_err(|err| format!("invalid echo response: {err}"))?;
	let public_key = P256Public::from_bytes(
		&qos_hex::decode(&response.public_key_hex)
			.map_err(|err| format!("invalid response public key: {err:?}"))?,
	)
	.map_err(|err| format!("invalid response public key: {err:?}"))?;
	let signature = qos_hex::decode(&response.signature_hex)
		.map_err(|err| format!("invalid response signature: {err:?}"))?;
	public_key
		.verify(response.signed_payload_json.as_bytes(), &signature)
		.map_err(|err| format!("invalid response signature: {err:?}"))?;
	Ok(response)
}

fn url(base: &str, path: &str) -> String {
	format!("{}/{}", base.trim_end_matches('/'), path.trim_start_matches('/'))
}

fn percent_encode_query_value(value: &str) -> String {
	let mut encoded = String::new();
	for byte in value.bytes() {
		if byte.is_ascii_alphanumeric()
			|| matches!(byte, b'-' | b'.' | b'_' | b'~')
		{
			encoded.push(byte as char);
		} else {
			encoded.push_str(&format!("%{byte:02X}"));
		}
	}
	encoded
}

fn workspace_root() -> PathBuf {
	PathBuf::from(env!("CARGO_MANIFEST_DIR"))
		.parent()
		.and_then(std::path::Path::parent)
		.expect("qos_test_harness is under src/")
		.to_path_buf()
}
