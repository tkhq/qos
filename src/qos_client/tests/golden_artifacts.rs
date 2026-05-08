#![allow(missing_docs)]

use std::{
	path::PathBuf,
	process::{Command, Output},
	time::{SystemTime, UNIX_EPOCH},
};

use qos_test_primitives::PathWrapper;

const QOS_CLIENT: &str = env!("CARGO_BIN_EXE_qos_client");
const PIVOT_BYTES: &[u8] = b"mono compat pivot bytes";
const PIVOT_SHA256_HEX: &str =
	"6851e7d5d3200c971307b7f3d02c35dc685413215392f1b35fa5ecb53264d963";
const MANIFEST_BORSH_LEN: usize = 1436;
const MANIFEST_BORSH_SHA256_HEX: &str =
	"f06b3417893b3c2648b36d25134c3d854405db7a609cc1d41b86c4f63fd476fd";
const MANIFEST_ENVELOPE_BORSH_LEN: usize = 1653;
const MANIFEST_ENVELOPE_BORSH_SHA256_HEX: &str =
	"45052f0eba6f9a13f178b7eb25eafff323db7cb859e7cf024ca44136e706f4ab";
const MANIFEST_V0_BORSH_LEN: usize = 1422;
const MANIFEST_V0_BORSH_SHA256_HEX: &str =
	"af2d3ce6fa8a7040fd560529c54ce031c66724b628925f2f37fe2c75a8729f91";

const EXPECTED_MANIFEST_JSON: &str = concat!(
	"{\"namespace\":{\"name\":\"production/signer\",\"nonce\":31,\"quo",
	"rumKey\":\"040f461f922c36cfdf16a65f3f370f106e33157d24608e1",
	"541291bc20e7d8182fa5030e074bb663a8d10ed424bcd26a369bd275",
	"3cbbf19162a5492b5d592d2b33e042d79aeeb3d76adde343d7dba361",
	"4bc63d8c7e247478bc7cfaec41e572ef20b1e637303393e16baf7891",
	"d8c6cdaba124ff098d1d9d8df9bfaff8fd1423e57d025\"},\"pivot\":",
	"{\"hash\":\"6851e7d5d3200c971307b7f3d02c35dc685413215392f1b",
	"35fa5ecb53264d963\",\"restart\":\"Always\",\"bridgeConfig\":[{\"",
	"type\":\"server\",\"port\":3000,\"host\":\"0.0.0.0\"}],\"debugMode",
	"\":true,\"args\":[\"--config\",\"/etc/config.json\"]},\"manifest",
	"Set\":{\"threshold\":1,\"members\":[{\"alias\":\"dev\",\"pubKey\":\"",
	"040f461f922c36cfdf16a65f3f370f106e33157d24608e1541291bc2",
	"0e7d8182fa5030e074bb663a8d10ed424bcd26a369bd2753cbbf1916",
	"2a5492b5d592d2b33e042d79aeeb3d76adde343d7dba3614bc63d8c7",
	"e247478bc7cfaec41e572ef20b1e637303393e16baf7891d8c6cdaba",
	"124ff098d1d9d8df9bfaff8fd1423e57d025\"}]},\"shareSet\":{\"th",
	"reshold\":1,\"members\":[{\"alias\":\"dev\",\"pubKey\":\"040f461f9",
	"22c36cfdf16a65f3f370f106e33157d24608e1541291bc20e7d8182f",
	"a5030e074bb663a8d10ed424bcd26a369bd2753cbbf19162a5492b5d",
	"592d2b33e042d79aeeb3d76adde343d7dba3614bc63d8c7e247478bc",
	"7cfaec41e572ef20b1e637303393e16baf7891d8c6cdaba124ff098d",
	"1d9d8df9bfaff8fd1423e57d025\"}]},\"enclave\":{\"pcr0\":\"181bd",
	"012baaecfd0bd4d6f617bea65ad5a76413d2a0c09b18efe72bff3fdc",
	"4b55f7416ec6d88a4d3236ce02d83b5eb8b\",\"pcr1\":\"181bd012baa",
	"ecfd0bd4d6f617bea65ad5a76413d2a0c09b18efe72bff3fdc4b55f7",
	"416ec6d88a4d3236ce02d83b5eb8b\",\"pcr2\":\"21b9efbc184807662",
	"e966d34f390821309eeac6802309798826296bf3e8bec7c10edb3094",
	"8c90ba67310f7b964fc500a\",\"pcr3\":\"78fce75db17cd4e0a3fb8da",
	"d3ad128ca5e77edbb2b2c7f75329dccd99aa5f6ef4fc1f1a452e315b",
	"9e98f9e312e6921e6\",\"awsRootCertificate\":\"308202113082019",
	"6a003020102021100f93175681b90afe11d46ccb4e4e7f856300a060",
	"82a8648ce3d0403033049310b3009060355040613025553310f300d0",
	"60355040a0c06416d617a6f6e310c300a060355040b0c03415753311",
	"b301906035504030c126177732e6e6974726f2d656e636c617665733",
	"01e170d3139313032383133323830355a170d3439313032383134323",
	"830355a3049310b3009060355040613025553310f300d060355040a0",
	"c06416d617a6f6e310c300a060355040b0c03415753311b301906035",
	"504030c126177732e6e6974726f2d656e636c6176657330763010060",
	"72a8648ce3d020106052b8104002203620004fc0254eba608c1f3687",
	"0e29ada90be46383292736e894bfff672d989444b5051e534a4b1f6d",
	"be3c0bc581a32b7b176070ede12d69a3fea211b66e752cf7dd1dd095",
	"f6f1370f4170843d9dc100121e4cf63012809664487c9796284304dc",
	"53ff4a3423040300f0603551d130101ff040530030101ff301d06035",
	"51d0e041604149025b50dd90547e796c396fa729dcf99a9df4b96300",
	"e0603551d0f0101ff040403020186300a06082a8648ce3d040303036",
	"9003066023100a37f2f91a1c9bd5ee7b8627c1698d255038e1f0343f",
	"95b63a9628c3d39809545a11ebcbf2e3b55d8aeee71b4c3d6adf3023",
	"100a2f39b1605b27028a5dd4ba069b5016e65b4fbde8fe0061d6a531",
	"97f9cdaf5d943bc61fc2beb03cb6fee8d2302f3dff6\",\"qosCommit\"",
	":\"\"},\"patchSet\":{\"threshold\":1,\"members\":[{\"pubKey\":\"040",
	"f461f922c36cfdf16a65f3f370f106e33157d24608e1541291bc20e7",
	"d8182fa5030e074bb663a8d10ed424bcd26a369bd2753cbbf19162a5",
	"492b5d592d2b33e042d79aeeb3d76adde343d7dba3614bc63d8c7e24",
	"7478bc7cfaec41e572ef20b1e637303393e16baf7891d8c6cdaba124",
	"ff098d1d9d8df9bfaff8fd1423e57d025\"}]}}",
);

const EXPECTED_APPROVAL_JSON: &str = concat!(
	"{\"signature\":\"ecbfbd26aa2be141d991a574bd78aea7fc940f7bf6",
	"096db3aa2de0c07d9d9f0c9eef0a061fd64ca5e10bf8f2dce831c26f",
	"a6eb42838d7aca89bbabca35e47374\",\"member\":{\"alias\":\"dev\",",
	"\"pubKey\":\"040f461f922c36cfdf16a65f3f370f106e33157d24608e",
	"1541291bc20e7d8182fa5030e074bb663a8d10ed424bcd26a369bd27",
	"53cbbf19162a5492b5d592d2b33e042d79aeeb3d76adde343d7dba36",
	"14bc63d8c7e247478bc7cfaec41e572ef20b1e637303393e16baf789",
	"1d8c6cdaba124ff098d1d9d8df9bfaff8fd1423e57d025\"}}",
);

const EXPECTED_MANIFEST_ENVELOPE_JSON: &str = concat!(
	"{\"manifest\":{\"namespace\":{\"name\":\"production/signer\",\"no",
	"nce\":31,\"quorumKey\":\"040f461f922c36cfdf16a65f3f370f106e3",
	"3157d24608e1541291bc20e7d8182fa5030e074bb663a8d10ed424bc",
	"d26a369bd2753cbbf19162a5492b5d592d2b33e042d79aeeb3d76add",
	"e343d7dba3614bc63d8c7e247478bc7cfaec41e572ef20b1e6373033",
	"93e16baf7891d8c6cdaba124ff098d1d9d8df9bfaff8fd1423e57d02",
	"5\"},\"pivot\":{\"hash\":\"6851e7d5d3200c971307b7f3d02c35dc685",
	"413215392f1b35fa5ecb53264d963\",\"restart\":\"Always\",\"bridg",
	"eConfig\":[{\"type\":\"server\",\"port\":3000,\"host\":\"0.0.0.0\"}",
	"],\"debugMode\":true,\"args\":[\"--config\",\"/etc/config.json\"",
	"]},\"manifestSet\":{\"threshold\":1,\"members\":[{\"alias\":\"dev",
	"\",\"pubKey\":\"040f461f922c36cfdf16a65f3f370f106e33157d2460",
	"8e1541291bc20e7d8182fa5030e074bb663a8d10ed424bcd26a369bd",
	"2753cbbf19162a5492b5d592d2b33e042d79aeeb3d76adde343d7dba",
	"3614bc63d8c7e247478bc7cfaec41e572ef20b1e637303393e16baf7",
	"891d8c6cdaba124ff098d1d9d8df9bfaff8fd1423e57d025\"}]},\"sh",
	"areSet\":{\"threshold\":1,\"members\":[{\"alias\":\"dev\",\"pubKey",
	"\":\"040f461f922c36cfdf16a65f3f370f106e33157d24608e1541291",
	"bc20e7d8182fa5030e074bb663a8d10ed424bcd26a369bd2753cbbf1",
	"9162a5492b5d592d2b33e042d79aeeb3d76adde343d7dba3614bc63d",
	"8c7e247478bc7cfaec41e572ef20b1e637303393e16baf7891d8c6cd",
	"aba124ff098d1d9d8df9bfaff8fd1423e57d025\"}]},\"enclave\":{\"",
	"pcr0\":\"181bd012baaecfd0bd4d6f617bea65ad5a76413d2a0c09b18",
	"efe72bff3fdc4b55f7416ec6d88a4d3236ce02d83b5eb8b\",\"pcr1\":",
	"\"181bd012baaecfd0bd4d6f617bea65ad5a76413d2a0c09b18efe72b",
	"ff3fdc4b55f7416ec6d88a4d3236ce02d83b5eb8b\",\"pcr2\":\"21b9e",
	"fbc184807662e966d34f390821309eeac6802309798826296bf3e8be",
	"c7c10edb30948c90ba67310f7b964fc500a\",\"pcr3\":\"78fce75db17",
	"cd4e0a3fb8dad3ad128ca5e77edbb2b2c7f75329dccd99aa5f6ef4fc",
	"1f1a452e315b9e98f9e312e6921e6\",\"awsRootCertificate\":\"308",
	"2021130820196a003020102021100f93175681b90afe11d46ccb4e4e",
	"7f856300a06082a8648ce3d0403033049310b3009060355040613025",
	"553310f300d060355040a0c06416d617a6f6e310c300a060355040b0",
	"c03415753311b301906035504030c126177732e6e6974726f2d656e6",
	"36c61766573301e170d3139313032383133323830355a170d3439313",
	"032383134323830355a3049310b3009060355040613025553310f300",
	"d060355040a0c06416d617a6f6e310c300a060355040b0c034157533",
	"11b301906035504030c126177732e6e6974726f2d656e636c6176657",
	"33076301006072a8648ce3d020106052b8104002203620004fc0254e",
	"ba608c1f36870e29ada90be46383292736e894bfff672d989444b505",
	"1e534a4b1f6dbe3c0bc581a32b7b176070ede12d69a3fea211b66e75",
	"2cf7dd1dd095f6f1370f4170843d9dc100121e4cf63012809664487c",
	"9796284304dc53ff4a3423040300f0603551d130101ff04053003010",
	"1ff301d0603551d0e041604149025b50dd90547e796c396fa729dcf9",
	"9a9df4b96300e0603551d0f0101ff040403020186300a06082a8648c",
	"e3d0403030369003066023100a37f2f91a1c9bd5ee7b8627c1698d25",
	"5038e1f0343f95b63a9628c3d39809545a11ebcbf2e3b55d8aeee71b",
	"4c3d6adf3023100a2f39b1605b27028a5dd4ba069b5016e65b4fbde8",
	"fe0061d6a53197f9cdaf5d943bc61fc2beb03cb6fee8d2302f3dff6\"",
	",\"qosCommit\":\"\"},\"patchSet\":{\"threshold\":1,\"members\":[{\"",
	"pubKey\":\"040f461f922c36cfdf16a65f3f370f106e33157d24608e1",
	"541291bc20e7d8182fa5030e074bb663a8d10ed424bcd26a369bd275",
	"3cbbf19162a5492b5d592d2b33e042d79aeeb3d76adde343d7dba361",
	"4bc63d8c7e247478bc7cfaec41e572ef20b1e637303393e16baf7891",
	"d8c6cdaba124ff098d1d9d8df9bfaff8fd1423e57d025\"}]}},\"mani",
	"festSetApprovals\":[{\"signature\":\"ecbfbd26aa2be141d991a57",
	"4bd78aea7fc940f7bf6096db3aa2de0c07d9d9f0c9eef0a061fd64ca",
	"5e10bf8f2dce831c26fa6eb42838d7aca89bbabca35e47374\",\"memb",
	"er\":{\"alias\":\"dev\",\"pubKey\":\"040f461f922c36cfdf16a65f3f3",
	"70f106e33157d24608e1541291bc20e7d8182fa5030e074bb663a8d1",
	"0ed424bcd26a369bd2753cbbf19162a5492b5d592d2b33e042d79aee",
	"b3d76adde343d7dba3614bc63d8c7e247478bc7cfaec41e572ef20b1",
	"e637303393e16baf7891d8c6cdaba124ff098d1d9d8df9bfaff8fd14",
	"23e57d025\"}}],\"shareSetApprovals\":[]}",
);

const EXPECTED_MANIFEST_V0_JSON: &str = concat!(
	"{\"namespace\":{\"name\":\"production/signer\",\"nonce\":31,\"quo",
	"rumKey\":\"040f461f922c36cfdf16a65f3f370f106e33157d24608e1",
	"541291bc20e7d8182fa5030e074bb663a8d10ed424bcd26a369bd275",
	"3cbbf19162a5492b5d592d2b33e042d79aeeb3d76adde343d7dba361",
	"4bc63d8c7e247478bc7cfaec41e572ef20b1e637303393e16baf7891",
	"d8c6cdaba124ff098d1d9d8df9bfaff8fd1423e57d025\"},\"pivot\":",
	"{\"hash\":\"6851e7d5d3200c971307b7f3d02c35dc685413215392f1b",
	"35fa5ecb53264d963\",\"restart\":\"Always\",\"args\":[\"--config\"",
	",\"/etc/config.json\"]},\"manifestSet\":{\"threshold\":1,\"memb",
	"ers\":[{\"alias\":\"dev\",\"pubKey\":\"040f461f922c36cfdf16a65f3",
	"f370f106e33157d24608e1541291bc20e7d8182fa5030e074bb663a8",
	"d10ed424bcd26a369bd2753cbbf19162a5492b5d592d2b33e042d79a",
	"eeb3d76adde343d7dba3614bc63d8c7e247478bc7cfaec41e572ef20",
	"b1e637303393e16baf7891d8c6cdaba124ff098d1d9d8df9bfaff8fd",
	"1423e57d025\"}]},\"shareSet\":{\"threshold\":1,\"members\":[{\"a",
	"lias\":\"dev\",\"pubKey\":\"040f461f922c36cfdf16a65f3f370f106e",
	"33157d24608e1541291bc20e7d8182fa5030e074bb663a8d10ed424b",
	"cd26a369bd2753cbbf19162a5492b5d592d2b33e042d79aeeb3d76ad",
	"de343d7dba3614bc63d8c7e247478bc7cfaec41e572ef20b1e637303",
	"393e16baf7891d8c6cdaba124ff098d1d9d8df9bfaff8fd1423e57d0",
	"25\"}]},\"enclave\":{\"pcr0\":\"181bd012baaecfd0bd4d6f617bea65",
	"ad5a76413d2a0c09b18efe72bff3fdc4b55f7416ec6d88a4d3236ce0",
	"2d83b5eb8b\",\"pcr1\":\"181bd012baaecfd0bd4d6f617bea65ad5a76",
	"413d2a0c09b18efe72bff3fdc4b55f7416ec6d88a4d3236ce02d83b5",
	"eb8b\",\"pcr2\":\"21b9efbc184807662e966d34f390821309eeac6802",
	"309798826296bf3e8bec7c10edb30948c90ba67310f7b964fc500a\",",
	"\"pcr3\":\"78fce75db17cd4e0a3fb8dad3ad128ca5e77edbb2b2c7f75",
	"329dccd99aa5f6ef4fc1f1a452e315b9e98f9e312e6921e6\",\"awsRo",
	"otCertificate\":\"3082021130820196a003020102021100f9317568",
	"1b90afe11d46ccb4e4e7f856300a06082a8648ce3d0403033049310b",
	"3009060355040613025553310f300d060355040a0c06416d617a6f6e",
	"310c300a060355040b0c03415753311b301906035504030c12617773",
	"2e6e6974726f2d656e636c61766573301e170d313931303238313332",
	"3830355a170d3439313032383134323830355a3049310b3009060355",
	"040613025553310f300d060355040a0c06416d617a6f6e310c300a06",
	"0355040b0c03415753311b301906035504030c126177732e6e697472",
	"6f2d656e636c617665733076301006072a8648ce3d020106052b8104",
	"002203620004fc0254eba608c1f36870e29ada90be46383292736e89",
	"4bfff672d989444b5051e534a4b1f6dbe3c0bc581a32b7b176070ede",
	"12d69a3fea211b66e752cf7dd1dd095f6f1370f4170843d9dc100121",
	"e4cf63012809664487c9796284304dc53ff4a3423040300f0603551d",
	"130101ff040530030101ff301d0603551d0e041604149025b50dd905",
	"47e796c396fa729dcf99a9df4b96300e0603551d0f0101ff04040302",
	"0186300a06082a8648ce3d0403030369003066023100a37f2f91a1c9",
	"bd5ee7b8627c1698d255038e1f0343f95b63a9628c3d39809545a11e",
	"bcbf2e3b55d8aeee71b4c3d6adf3023100a2f39b1605b27028a5dd4b",
	"a069b5016e65b4fbde8fe0061d6a53197f9cdaf5d943bc61fc2beb03",
	"cb6fee8d2302f3dff6\",\"qosCommit\":\"\"},\"patchSet\":{\"thresho",
	"ld\":1,\"members\":[{\"pubKey\":\"040f461f922c36cfdf16a65f3f37",
	"0f106e33157d24608e1541291bc20e7d8182fa5030e074bb663a8d10",
	"ed424bcd26a369bd2753cbbf19162a5492b5d592d2b33e042d79aeeb",
	"3d76adde343d7dba3614bc63d8c7e247478bc7cfaec41e572ef20b1e",
	"637303393e16baf7891d8c6cdaba124ff098d1d9d8df9bfaff8fd142",
	"3e57d025\"}]}}",
);

struct Fixture {
	_tmp: PathWrapper<'static>,
	manifest_set: PathBuf,
	share_set: PathBuf,
	patch_set: PathBuf,
	approvals_dir: PathBuf,
	manifest_path: PathBuf,
	envelope_path: PathBuf,
	approval_path: PathBuf,
	manifest_borsh_path: PathBuf,
	envelope_borsh_path: PathBuf,
	manifest_v0_json_path: PathBuf,
	manifest_v0_borsh_path: PathBuf,
	pivot_path: PathBuf,
	pivot_hash_path: PathBuf,
	qos_release_dir: PathBuf,
	pcr3_preimage_path: PathBuf,
	quorum_key_path: PathBuf,
	secret_path: PathBuf,
}

impl Fixture {
	fn new(test_name: &str) -> Self {
		let nanos =
			SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
		let root = std::env::temp_dir().join(format!(
			"qos_client_golden_{test_name}_{}_{}",
			std::process::id(),
			nanos
		));
		let tmp: PathWrapper<'static> = root.display().to_string().into();

		let manifest_set = root.join("manifest-set");
		let share_set = root.join("share-set");
		let patch_set = root.join("patch-set");
		let approvals_dir = root.join("approvals");
		let qos_release_dir = root.join("dist");
		for dir in [
			&manifest_set,
			&share_set,
			&patch_set,
			&approvals_dir,
			&qos_release_dir,
		] {
			std::fs::create_dir_all(dir).unwrap();
		}

		let manifest_path = root.join("manifest");
		let envelope_path = approvals_dir.join("manifest_envelope");
		let approval_path =
			approvals_dir.join("dev-production-signer-31.approval");
		let manifest_borsh_path = root.join("manifest.borsh");
		let envelope_borsh_path = root.join("manifest_envelope.borsh");
		let manifest_v0_json_path = root.join("manifest_v0.json");
		let manifest_v0_borsh_path = root.join("manifest_v0.borsh");
		let pivot_path = root.join("pivot.bin");
		let pivot_hash_path = root.join("pivot.hash");
		let pcr3_preimage_path = root.join("pcr3_preimage");
		let quorum_key_path = root.join("quorum_key.pub");

		let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
		let primary_pub = manifest_dir.join("tests/mock/primary.pub");
		let secret_path = manifest_dir.join("tests/mock/primary.secret.keep");
		let integration_dist =
			manifest_dir.join("../integration/mock/dist/aws-x86_64.pcrs");
		let integration_pcr3 = manifest_dir
			.join("../integration/mock/namespaces/pcr3-preimage.txt");

		for set_dir in [&manifest_set, &share_set, &patch_set] {
			std::fs::write(set_dir.join("quorum_threshold"), b"1\n").unwrap();
			std::fs::copy(&primary_pub, set_dir.join("dev.pub")).unwrap();
		}
		std::fs::copy(&primary_pub, &quorum_key_path).unwrap();
		std::fs::copy(
			integration_dist,
			qos_release_dir.join("aws-x86_64.pcrs"),
		)
		.unwrap();
		std::fs::copy(integration_pcr3, &pcr3_preimage_path).unwrap();
		std::fs::write(&pivot_path, PIVOT_BYTES).unwrap();

		Self {
			_tmp: tmp,
			manifest_set,
			share_set,
			patch_set,
			approvals_dir,
			manifest_path,
			envelope_path,
			approval_path,
			manifest_borsh_path,
			envelope_borsh_path,
			manifest_v0_json_path,
			manifest_v0_borsh_path,
			pivot_path,
			pivot_hash_path,
			qos_release_dir,
			pcr3_preimage_path,
			quorum_key_path,
			secret_path,
		}
	}

	fn generate_artifacts(&self) {
		assert_success(&run_qos_client([
			"pivot-hash",
			"--output-path",
			self.pivot_hash_path.to_str().unwrap(),
			"--pivot-path",
			self.pivot_path.to_str().unwrap(),
		]));

		assert_success(&run_qos_client([
			"generate-manifest",
			"--nonce",
			"31",
			"--namespace",
			"production/signer",
			"--restart-policy",
			"always",
			"--manifest-path",
			self.manifest_path.to_str().unwrap(),
			"--pivot-hash-path",
			self.pivot_hash_path.to_str().unwrap(),
			"--qos-release-dir",
			self.qos_release_dir.to_str().unwrap(),
			"--pcr3-preimage-path",
			self.pcr3_preimage_path.to_str().unwrap(),
			"--pivot-args",
			"[--config,/etc/config.json]",
			"--manifest-set-dir",
			self.manifest_set.to_str().unwrap(),
			"--share-set-dir",
			self.share_set.to_str().unwrap(),
			"--patch-set-dir",
			self.patch_set.to_str().unwrap(),
			"--quorum-key-path",
			self.quorum_key_path.to_str().unwrap(),
			"--debug-mode",
			"true",
			"--bridge-config",
			"[{\"type\":\"server\",\"port\":3000,\"host\":\"0.0.0.0\"}]",
		]));

		assert_success(&run_qos_client([
			"approve-manifest",
			"--alias",
			"dev",
			"--manifest-approvals-dir",
			self.approvals_dir.to_str().unwrap(),
			"--manifest-path",
			self.manifest_path.to_str().unwrap(),
			"--manifest-set-dir",
			self.manifest_set.to_str().unwrap(),
			"--patch-set-dir",
			self.patch_set.to_str().unwrap(),
			"--share-set-dir",
			self.share_set.to_str().unwrap(),
			"--pcr3-preimage-path",
			self.pcr3_preimage_path.to_str().unwrap(),
			"--pivot-hash-path",
			self.pivot_hash_path.to_str().unwrap(),
			"--qos-release-dir",
			self.qos_release_dir.to_str().unwrap(),
			"--quorum-key-path",
			self.quorum_key_path.to_str().unwrap(),
			"--secret-path",
			self.secret_path.to_str().unwrap(),
			"--unsafe-auto-confirm",
		]));

		assert_success(&run_qos_client([
			"generate-manifest-envelope",
			"--manifest-approvals-dir",
			self.approvals_dir.to_str().unwrap(),
			"--manifest-path",
			self.manifest_path.to_str().unwrap(),
		]));
	}
}

fn run_qos_client<const N: usize>(args: [&str; N]) -> Output {
	Command::new(QOS_CLIENT).args(args).output().unwrap()
}

fn assert_success(output: &Output) {
	assert!(
		output.status.success(),
		"qos_client failed\nstatus: {:?}\nstdout:\n{}\nstderr:\n{}",
		output.status.code(),
		String::from_utf8_lossy(&output.stdout),
		String::from_utf8_lossy(&output.stderr),
	);
}

fn assert_file_json_exact(path: &std::path::Path, expected: &str) {
	let actual = std::fs::read_to_string(path).unwrap();
	assert_eq!(actual, expected);
}

fn assert_file_borsh_hash(
	path: &std::path::Path,
	expected_len: usize,
	expected_sha256_hex: &str,
) {
	let bytes = std::fs::read(path).unwrap();
	assert_eq!(bytes.len(), expected_len);
	assert_eq!(
		qos_hex::encode(&qos_crypto::sha_256(&bytes)),
		expected_sha256_hex
	);
}

#[test]
fn golden_manifest_approval_and_envelope_raw_bytes() {
	let fixture = Fixture::new("artifacts");
	fixture.generate_artifacts();

	assert_eq!(
		std::fs::read_to_string(&fixture.pivot_hash_path).unwrap(),
		PIVOT_SHA256_HEX
	);

	assert_file_json_exact(&fixture.manifest_path, EXPECTED_MANIFEST_JSON);
	assert_file_json_exact(&fixture.approval_path, EXPECTED_APPROVAL_JSON);
	assert_file_json_exact(
		&fixture.envelope_path,
		EXPECTED_MANIFEST_ENVELOPE_JSON,
	);
	assert_success(&run_qos_client([
		"json-to-borsh",
		"--display-type",
		"manifest",
		"--file-path",
		fixture.manifest_path.to_str().unwrap(),
		"--output-path",
		fixture.manifest_borsh_path.to_str().unwrap(),
	]));
	assert_success(&run_qos_client([
		"json-to-borsh",
		"--display-type",
		"manifest-envelope",
		"--file-path",
		fixture.envelope_path.to_str().unwrap(),
		"--output-path",
		fixture.envelope_borsh_path.to_str().unwrap(),
	]));

	std::fs::write(&fixture.manifest_v0_json_path, EXPECTED_MANIFEST_V0_JSON)
		.unwrap();
	assert_file_json_exact(
		&fixture.manifest_v0_json_path,
		EXPECTED_MANIFEST_V0_JSON,
	);
	assert_success(&run_qos_client([
		"json-to-borsh",
		"--display-type",
		"manifest",
		"--file-path",
		fixture.manifest_v0_json_path.to_str().unwrap(),
		"--output-path",
		fixture.manifest_v0_borsh_path.to_str().unwrap(),
	]));

	assert_file_borsh_hash(
		&fixture.manifest_borsh_path,
		MANIFEST_BORSH_LEN,
		MANIFEST_BORSH_SHA256_HEX,
	);
	assert_file_borsh_hash(
		&fixture.envelope_borsh_path,
		MANIFEST_ENVELOPE_BORSH_LEN,
		MANIFEST_ENVELOPE_BORSH_SHA256_HEX,
	);
	assert_file_borsh_hash(
		&fixture.manifest_v0_borsh_path,
		MANIFEST_V0_BORSH_LEN,
		MANIFEST_V0_BORSH_SHA256_HEX,
	);
}
