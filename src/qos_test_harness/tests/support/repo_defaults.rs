//! Repository-specific defaults for the QEMU integration harness.

use std::{
	path::{Path, PathBuf},
	time::Duration,
};

use qos_core::protocol::services::boot::{
	ManifestBuilder, ManifestSet, ManifestVersion, Namespace, NitroConfig,
	QuorumMember, RestartPolicy, ShareSet,
};
use qos_crypto::{sha_256, sha_384};
use qos_nsm::nitro::{AWS_ROOT_CERT_PEM, cert_from_pem};
use qos_p256::P256Public;

use qos_test_harness::{
	ApprovingUserMaterial, BootClientFixture, BootMaterial, BuildError,
	DockerHostQemuNitroSpec, DockerMount, DockerProgram, DockerRunSpec,
	DockerVolumeSocket, Eif, ImageRef, KeySetMaterial, MaterialFile, Pivot,
	QemuEifBaseImages, QemuRuntimeSpec, QosReleaseMaterial, RunnerError,
};

/// Inputs for the repo-local Docker-host/QEMU-Nitro runner defaults.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct DockerHostQemuNitroDefaults {
	/// Workspace root.
	pub(super) root: PathBuf,
	/// Runner work directory.
	pub(super) work_dir: PathBuf,
	/// Docker binary.
	pub(super) docker_bin: PathBuf,
	/// Host port for `qos_host`.
	pub(super) host_port: u16,
	/// Host port for app ingress.
	pub(super) ingress_port: u16,
}

/// Create a v2 manifest builder with the standard Docker/QEMU test fixtures.
///
/// Tests add their pivot arguments and bridge configuration before calling
/// [`ManifestBuilder::build`].
pub(super) fn test_manifest_template(
	root: &Path,
	pivot: &Pivot,
) -> Result<ManifestBuilder, BuildError> {
	let fixture_dir = root.join("src/integration/mock");
	let namespace_name = "quit-coding-to-vape";
	let quorum_key = P256Public::from_hex_file(
		fixture_dir
			.join("namespaces")
			.join(namespace_name)
			.join("quorum_key.pub"),
	)
	.map_err(|err| BuildError::Manifest(format!("read quorum key: {err:?}")))?;
	let pivot_hash: [u8; 32] = sha_256(&std::fs::read(&pivot.path)?)
		.try_into()
		.expect("SHA-256 output is 32 bytes");

	Ok(ManifestBuilder::new()
		.with_version(ManifestVersion::V2)
		.namespace(Namespace {
			name: namespace_name.to_string(),
			nonce: 2,
			quorum_key: quorum_key.to_bytes(),
		})
		.pivot_hash(pivot_hash)
		.restart_policy(RestartPolicy::Never)
		.debug_mode(true)
		.manifest_set(read_manifest_set(
			&fixture_dir.join("keys/manifest-set"),
		)?)
		.share_set(read_share_set(&fixture_dir.join("keys/share-set"))?)
		.enclave(read_nitro_config(&fixture_dir)?))
}

fn read_manifest_set(root: &Path) -> Result<ManifestSet, BuildError> {
	Ok(ManifestSet {
		threshold: read_threshold(root)?,
		members: read_members(root)?,
	})
}

fn read_share_set(root: &Path) -> Result<ShareSet, BuildError> {
	Ok(ShareSet {
		threshold: read_threshold(root)?,
		members: read_members(root)?,
	})
}

fn read_threshold(root: &Path) -> Result<u32, BuildError> {
	std::fs::read_to_string(root.join("quorum_threshold"))?
		.trim()
		.parse()
		.map_err(|err| {
			BuildError::Manifest(format!("parse quorum threshold: {err}"))
		})
}

fn read_members(root: &Path) -> Result<Vec<QuorumMember>, BuildError> {
	let mut members = Vec::new();
	for entry in std::fs::read_dir(root)? {
		let path = entry?.path();
		if path.extension().is_none_or(|extension| extension != "pub") {
			continue;
		}
		let alias = path
			.file_stem()
			.and_then(|name| name.to_str())
			.ok_or_else(|| {
				BuildError::Manifest(format!(
					"invalid member path: {}",
					path.display()
				))
			})?
			.to_string();
		let public = P256Public::from_hex_file(&path).map_err(|err| {
			BuildError::Manifest(format!(
				"read member {}: {err:?}",
				path.display()
			))
		})?;
		members.push(QuorumMember { alias, pub_key: public.to_bytes() });
	}
	members.sort();
	Ok(members)
}

fn read_nitro_config(fixture_dir: &Path) -> Result<NitroConfig, BuildError> {
	let pcrs =
		std::fs::read_to_string(fixture_dir.join("dist/aws-x86_64.pcrs"))?;
	let mut values = pcrs
		.lines()
		.map(|line| {
			let mut fields = line.split_whitespace();
			let value = fields.next().ok_or_else(|| {
				BuildError::Manifest("missing PCR value".to_string())
			})?;
			let label = fields.next().ok_or_else(|| {
				BuildError::Manifest("missing PCR label".to_string())
			})?;
			Ok::<_, BuildError>((
				label.to_string(),
				qos_hex::decode(value).map_err(|err| {
					BuildError::Manifest(format!("decode {label}: {err:?}"))
				})?,
			))
		})
		.collect::<Result<Vec<_>, _>>()?;
	if values.len() != 3
		|| values[0].0 != "PCR0"
		|| values[1].0 != "PCR1"
		|| values[2].0 != "PCR2"
	{
		return Err(BuildError::Manifest(
			"invalid test PCR fixture".to_string(),
		));
	}
	let role_arn = std::fs::read_to_string(
		fixture_dir.join("namespaces/pcr3-preimage.txt"),
	)?;
	let mut pcr3_preimage = vec![0_u8; 48];
	pcr3_preimage.extend_from_slice(role_arn.trim().as_bytes());
	Ok(NitroConfig {
		pcr0: values.remove(0).1,
		pcr1: values.remove(0).1,
		pcr2: values.remove(0).1,
		pcr3: sha_384(&pcr3_preimage).to_vec(),
		aws_root_certificate: cert_from_pem(AWS_ROOT_CERT_PEM).map_err(
			|err| {
				BuildError::Manifest(format!(
					"decode AWS root certificate: {err:?}"
				))
			},
		)?,
		qos_commit: String::new(),
	})
}

/// Build the repo-local `qos_client` boot fixture from integration fixtures.
fn boot_client_fixture(root: &Path) -> Result<BootClientFixture, BuildError> {
	let fixture_dir = root.join("src/integration/mock");
	let personal_dir = fixture_dir.join("boot-e2e/all-personal-dir");
	let namespace = "quit-coding-to-vape".to_string();

	Ok(BootClientFixture {
		material: BootMaterial {
			pcr3_preimage: std::fs::read(
				fixture_dir.join("namespaces/pcr3-preimage.txt"),
			)?,
			qos_release: QosReleaseMaterial {
				files: read_material_dir(&fixture_dir.join("dist"))?,
			},
			manifest_set: KeySetMaterial {
				files: read_material_dir(
					&fixture_dir.join("keys/manifest-set"),
				)?,
			},
			share_set: KeySetMaterial {
				files: read_material_dir(&fixture_dir.join("keys/share-set"))?,
			},
			quorum_key: std::fs::read(
				fixture_dir
					.join("namespaces")
					.join(&namespace)
					.join("quorum_key.pub"),
			)?,
		},
		approving_users: ["user1", "user2"]
			.into_iter()
			.map(|alias| {
				let user_dir = personal_dir.join(format!("{alias}-dir"));
				Ok(ApprovingUserMaterial {
					alias: alias.to_string(),
					secret: std::fs::read(
						user_dir.join(format!("{alias}.secret")),
					)?,
					share: std::fs::read(
						user_dir.join(format!("{alias}.share")),
					)?,
				})
			})
			.collect::<Result<Vec<_>, std::io::Error>>()?,
		unsafe_skip_attestation: true,
		unsafe_auto_confirm: true,
	})
}

/// Build the repo-local Docker-host/QEMU-Nitro runner spec.
pub(super) fn docker_host_qemu_nitro_spec(
	defaults: DockerHostQemuNitroDefaults,
) -> Result<DockerHostQemuNitroSpec, RunnerError> {
	let root = defaults.root;
	let work_mount = DockerMount {
		host_path: defaults.work_dir.clone(),
		container_path: PathBuf::from("/qos-work"),
		read_only: false,
	};
	let eif_mount = DockerMount {
		host_path: root.join("out"),
		container_path: PathBuf::from("/qos-artifacts"),
		read_only: true,
	};
	Ok(DockerHostQemuNitroSpec {
		eif: Eif { path: root.join("out/nitro.eif"), pcrs_path: None },
		host_program: DockerProgram::ImageEntrypoint {
			image: qemu_image("qos_host")
				.map_err(build_error_to_runner_error)?,
		},
		host_run: DockerRunSpec {
			privileged: true,
			..DockerRunSpec::default()
		},
		bridge_program: DockerProgram::ImageEntrypoint {
			image: qemu_image("qos_bridge")
				.map_err(build_error_to_runner_error)?,
		},
		bridge_run: DockerRunSpec {
			privileged: true,
			..DockerRunSpec::default()
		},
		bridge_egress_bin_path: None,
		client_program: DockerProgram::ImageEntrypoint {
			image: local_image("qos_client")
				.map_err(build_error_to_runner_error)?,
		},
		client_run: DockerRunSpec {
			mounts: vec![work_mount],
			privileged: false,
		},
		qemu: QemuRuntimeSpec {
			qemu_bin: PathBuf::from("/usr/bin/qemu-system-x86_64"),
			vhost_device_vsock_bin: PathBuf::from(
				"/usr/bin/vhost-device-vsock",
			),
			qemu_tool_image: Some(
				local_image("qos_test_harness_nitro_tools")
					.map_err(build_error_to_runner_error)?,
			),
			egress_setup_image: Some(
				local_image("qos_test_harness_egress_tools")
					.map_err(build_error_to_runner_error)?,
			),
			qemu_tool_vhost_socket: Some(DockerVolumeSocket {
				volume_name: format!(
					"qos-test-harness-vhost-{}-{}",
					defaults.host_port, defaults.ingress_port
				),
				socket_path: PathBuf::from("/vhost/vhost.socket"),
			}),
			docker_bin: defaults.docker_bin,
			docker_tool_run: DockerRunSpec {
				mounts: vec![eif_mount],
				privileged: true,
			},
			docker_host_network: false,
			work_dir: defaults.work_dir.clone(),
			vhost_socket_path: defaults.work_dir.join("vhost4.socket"),
			guest_cid: 4,
			host_cid: 1,
			control_vsock_port: 9001,
			host_ip: "0.0.0.0".to_string(),
			host_connect_ip: "host.docker.internal".to_string(),
			ingress_ip: "127.0.0.1".to_string(),
			host_port: defaults.host_port,
			ingress_port: defaults.ingress_port,
			memory: "4G".to_string(),
			cpu: "max".to_string(),
			enable_kvm: false,
			startup_delay: Duration::from_secs(2),
			guest_boot_delay: Duration::from_secs(25),
			readiness_timeout: Duration::from_secs(60),
		},
		boot_fixture: boot_client_fixture(&root)
			.map_err(build_error_to_runner_error)?,
	})
}

/// Build the repo-local Docker-host/QEMU-Nitro runner spec for fast local
/// binary iteration.
pub(super) fn docker_host_qemu_nitro_fast_spec(
	defaults: DockerHostQemuNitroDefaults,
) -> Result<DockerHostQemuNitroSpec, RunnerError> {
	let root = defaults.root;
	let artifact_mount = DockerMount {
		host_path: root.join("target"),
		container_path: PathBuf::from("/qos/target"),
		read_only: true,
	};
	let work_mount = DockerMount {
		host_path: defaults.work_dir.clone(),
		container_path: PathBuf::from("/qos-work"),
		read_only: false,
	};
	let runtime_image = ImageRef::new("debian:bookworm-slim")
		.map_err(build_error_to_runner_error)?;
	Ok(DockerHostQemuNitroSpec {
		eif: Eif {
			path: defaults.work_dir.join("nitro.eif"),
			pcrs_path: Some(defaults.work_dir.join("nitro.pcrs")),
		},
		host_program: DockerProgram::MountedBinary {
			image: runtime_image.clone(),
			path: fast_container_binary_path("release", "qos_host"),
		},
		host_run: DockerRunSpec {
			mounts: vec![artifact_mount.clone()],
			privileged: true,
		},
		bridge_program: DockerProgram::MountedBinary {
			image: runtime_image.clone(),
			path: fast_container_binary_path("release", "ingress"),
		},
		bridge_run: DockerRunSpec {
			mounts: vec![artifact_mount.clone()],
			privileged: true,
		},
		bridge_egress_bin_path: Some(fast_container_binary_path(
			"release-panic-abort",
			"egress",
		)),
		client_program: DockerProgram::MountedBinary {
			image: runtime_image,
			path: fast_container_binary_path("release", "qos_client"),
		},
		client_run: DockerRunSpec {
			mounts: vec![artifact_mount, work_mount.clone()],
			privileged: false,
		},
		qemu: QemuRuntimeSpec {
			qemu_bin: PathBuf::from("/usr/bin/qemu-system-x86_64"),
			vhost_device_vsock_bin: PathBuf::from(
				"/usr/bin/vhost-device-vsock",
			),
			qemu_tool_image: Some(
				local_image("qos_test_harness_nitro_tools")
					.map_err(build_error_to_runner_error)?,
			),
			egress_setup_image: Some(
				local_image("qos_test_harness_egress_tools")
					.map_err(build_error_to_runner_error)?,
			),
			qemu_tool_vhost_socket: Some(DockerVolumeSocket {
				volume_name: format!(
					"qos-test-harness-vhost-{}-{}",
					defaults.host_port, defaults.ingress_port
				),
				socket_path: PathBuf::from("/vhost/vhost.socket"),
			}),
			docker_bin: defaults.docker_bin,
			docker_tool_run: DockerRunSpec {
				mounts: vec![work_mount],
				privileged: true,
			},
			docker_host_network: false,
			work_dir: defaults.work_dir.clone(),
			vhost_socket_path: defaults.work_dir.join("vhost4.socket"),
			guest_cid: 4,
			host_cid: 1,
			control_vsock_port: 9001,
			host_ip: "0.0.0.0".to_string(),
			host_connect_ip: "host.docker.internal".to_string(),
			ingress_ip: "127.0.0.1".to_string(),
			host_port: defaults.host_port,
			ingress_port: defaults.ingress_port,
			memory: "4G".to_string(),
			cpu: "max".to_string(),
			enable_kvm: false,
			startup_delay: Duration::from_secs(2),
			guest_boot_delay: Duration::from_secs(25),
			readiness_timeout: Duration::from_secs(60),
		},
		boot_fixture: boot_client_fixture(&root)
			.map_err(build_error_to_runner_error)?,
	})
}

/// StageX base images used to assemble a QEMU EIF.
pub(super) fn qemu_eif_base_images() -> Result<QemuEifBaseImages, BuildError> {
	Ok(QemuEifBaseImages {
		build: ImageRef::new(
			"ghcr.io/tkhq/base/rust:sha-bfaaeb25fd43e17468e6583208166fc7c4313226@sha256:9868bdab0b602a487ec9ea42995992ac0a381d7fc34d5ba9c41d14c18be716d2",
		)?,
		eif_build: ImageRef::new(
			"stagex/eif_build:0.2.2@sha256:291653f1ca528af48fd05858749c443300f6b24d2ffefa7f5a3a06c27c774566",
		)?,
		gen_initramfs: ImageRef::new(
			"stagex/gen_initramfs:6.8@sha256:f5b9271cca6003e952cbbb9ef041ffa92ba328894f563d1d77942e6b5cdeac1a",
		)?,
		linux_nitro: ImageRef::new(
			"stagex/linux-nitro:sx2024.03.0@sha256:073c4603686e3bdc0ed6755fee3203f6f6f1512e0ded09eaea8866b002b04264",
		)?,
		libunwind: ImageRef::new(
			"stagex/core-libunwind:1.7.2@sha256:eb66122d8fc543f5e2f335bb1616f8c3a471604383e2c0a9df4a8e278505d3bc",
		)?,
		iproute2: ImageRef::new(
			"stagex/iproute2:sx2024.11.0@sha256:65da03aa94d17dd6310b022f426a6cc8b3c55bb267e4bac1697bc57d6c850570",
		)?,
		musl: ImageRef::new(
			"stagex/musl:sx2024.11.0@sha256:d7f6c365f5724c65cadb2b96d9f594e46132ceb366174c89dbf7554897f2bc53",
		)?,
	})
}

/// Repo-local image name.
pub(super) fn local_image(name: &str) -> Result<ImageRef, BuildError> {
	ImageRef::new(format!("qos-local/{name}:latest"))
}

/// Repo-local QEMU feature image name.
pub(super) fn qemu_image(name: &str) -> Result<ImageRef, BuildError> {
	ImageRef::new(format!("qos-local/{name}_qemu:latest"))
}

const FAST_QEMU_TARGET: &str = "x86_64-unknown-linux-musl";

fn fast_container_binary_path(profile_dir: &str, name: &str) -> PathBuf {
	PathBuf::from("/qos")
		.join("target")
		.join(FAST_QEMU_TARGET)
		.join(profile_dir)
		.join(name)
}

fn read_material_dir(root: &Path) -> Result<Vec<MaterialFile>, BuildError> {
	let mut files = Vec::new();
	read_material_dir_inner(root, root, &mut files)?;
	files.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
	Ok(files)
}

fn read_material_dir_inner(
	root: &Path,
	dir: &Path,
	files: &mut Vec<MaterialFile>,
) -> Result<(), BuildError> {
	for entry in std::fs::read_dir(dir)? {
		let entry = entry?;
		let path = entry.path();
		if path.is_dir() {
			read_material_dir_inner(root, &path, files)?;
		} else if path.is_file() {
			files.push(MaterialFile {
				relative_path: path
					.strip_prefix(root)
					.expect("material path is under root")
					.to_path_buf(),
				contents: std::fs::read(&path)?,
			});
		}
	}
	Ok(())
}

fn build_error_to_runner_error(err: BuildError) -> RunnerError {
	match err {
		BuildError::Io(err) => RunnerError::Io(err),
		err => RunnerError::InvalidConfig(err.to_string()),
	}
}
