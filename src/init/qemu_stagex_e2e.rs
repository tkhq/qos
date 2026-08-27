use std::{collections::HashSet, fs, path::PathBuf};

use oci_spec::runtime::{
	Capabilities, Capability, Linux, LinuxCapabilitiesBuilder, Spec,
	RootBuilder, get_rootless_mounts,
};
use qos_core::{
	handles::Handles,
	oci_runtime,
	protocol::services::boot::{
		OciDigest, OciPlatform, OciRuntimeLimits, PivotEnv, PivotKind,
		PivotOciImageConfigV2, RestartPolicy,
		oci::{import_oci_layout_archive, prepare_oci_runtime_bundle},
	},
};

const ROOT: &str = "/run/qos-stagex-e2e";
const ARCHIVE: &str = "/stagex.oci.tar";
const DIGEST: &str = "/stagex.digest";

pub fn run() -> Result<(), String> {
	println!("QOS_STAGEX_BUILDKIT_E2E_START");
	fs::create_dir_all(ROOT).map_err(|error| error.to_string())?;
	let handles = handles()?;
	let pivot = pivot()?;
	let archive = fs::read(ARCHIVE).map_err(|error| {
		format!("failed to read embedded OCI archive: {error}")
	})?;
	import_oci_layout_archive(&handles, &pivot, &archive)
		.map_err(|error| format!("OCI import failed: {error:?}"))?;
	let bundle = prepare_oci_runtime_bundle(&handles, &pivot)
		.map_err(|error| format!("OCI bundle preparation failed: {error:?}"))?;
	let status = oci_runtime::run(
		&bundle.bundle_dir,
		&handles.oci_dir().join("runtime"),
		"stagex-buildkit",
		true,
	)?;
	if status != 0 {
		return Err(format!("StageX builder exited with status {status}"));
	}
	println!("QOS_STAGEX_BUILDKIT_E2E_OK");
	Ok(())
}

fn handles() -> Result<Handles, String> {
	let root = PathBuf::from(ROOT);
	let handles = Handles::new_with_oci_dir(
		root.join("ephemeral.key").display().to_string(),
		root.join("quorum.key").display().to_string(),
		root.join("manifest.json").display().to_string(),
		root.join("pivot").display().to_string(),
		root.join("oci"),
	);
	for path in [
		root.join("ephemeral.key"),
		root.join("quorum.key"),
		root.join("manifest.json"),
	] {
		fs::write(path, b"qemu-stagex-e2e")
			.map_err(|error| error.to_string())?;
	}
	Ok(handles)
}

fn pivot() -> Result<PivotOciImageConfigV2, String> {
	let digest = fs::read_to_string(DIGEST)
		.map_err(|error| format!("failed to read OCI digest: {error}"))?;
	let mut runtime = Spec::default();
	runtime.set_linux(Some(Linux::rootless(1000, 1000)));
	runtime.set_mounts(Some(get_rootless_mounts()));
	runtime.set_root(Some(
		RootBuilder::default()
			.path("rootfs")
			.readonly(false)
			.build()
			.map_err(|error| error.to_string())?,
	));
	let process = runtime
		.process_mut()
		.as_mut()
		.ok_or_else(|| "default runtime spec omitted process".to_string())?;
	process.user_mut().set_uid(0);
	process.user_mut().set_gid(0);
	process.set_no_new_privileges(Some(false));
	let capabilities: Capabilities = [
		Capability::AuditWrite,
		Capability::Chown,
		Capability::DacOverride,
		Capability::Fowner,
		Capability::Fsetid,
		Capability::Kill,
		Capability::Mknod,
		Capability::NetBindService,
		Capability::NetRaw,
		Capability::Setfcap,
		Capability::Setgid,
		Capability::Setpcap,
		Capability::Setuid,
		Capability::SysAdmin,
		Capability::SysChroot,
	]
	.into_iter()
	.collect::<HashSet<_>>();
	let caps = LinuxCapabilitiesBuilder::default()
		.bounding(capabilities.clone())
		.effective(capabilities.clone())
		.inheritable(capabilities.clone())
		.permitted(capabilities.clone())
		.ambient(capabilities)
		.build()
		.map_err(|error| error.to_string())?;
	process.set_capabilities(Some(caps));

	Ok(PivotOciImageConfigV2 {
		r#type: PivotKind::OciImage,
		digest: OciDigest::new(digest.trim())?,
		platform: OciPlatform {
			os: "linux".to_string(),
			architecture: "amd64".to_string(),
		},
		restart: RestartPolicy::Never,
		args: Some(vec!["/usr/bin/qos-stagex-build".to_string()]),
		env: PivotEnv::default(),
		debug_mode: true,
		bridge_config: vec![],
		limits: OciRuntimeLimits {
			max_compressed_bytes: 512 * 1024 * 1024,
			max_unpacked_bytes: 1024 * 1024 * 1024,
			max_entries: 100_000,
		},
		runtime: Some(runtime),
	})
}
