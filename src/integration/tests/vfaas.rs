//! End-to-end tests for `pivot_vfaas`: boot the pivot binary, register
//! quorum-approved artifacts over the usock, and drive every execution
//! outcome.
//!
//! The WASM fixtures are hand-written WAT implementing the guest ABI
//! (`memory` + `alloc` exports, `(ptr, len) -> packed u64` entrypoints), so
//! this test needs no wasm32 toolchain and no SDK build step. The
//! SDK-built examples get their end-to-end run via `cargo xtask demo`.

use std::{process::Command, time::Duration};

use borsh::BorshDeserialize;
use integration::{
	PIVOT_VFAAS_PATH,
	vfaas::{
		DEFAULT_FUEL_PER_CALL, VfaasMsg, engine_id,
		governance::{
			Artifact, ArtifactEnvelope, ArtifactKind, Ruleset, RulesetEnvelope,
			approve_artifact, approve_ruleset,
		},
		http, verify_execution_attestation,
	},
	wait_for_usock,
};
use qos_core::{
	client::SocketClient,
	io::{SocketAddress, StreamPool},
	protocol::services::boot::{
		Approval, Manifest, ManifestEnvelope, ManifestSet, QuorumMember,
		VersionedManifestEnvelope,
	},
};
use qos_crypto::sha_256;
use qos_p256::P256Pair;
use qos_test_primitives::{ChildWrapper, PathWrapper};
use vfaas_abi::{
	ExecutionAttestation, ExecutionAttestationPayload, ExecutionOutcome,
	PolicyHash, ProgramHash, Stage, VFAAS_ABI_VERSION,
};

/// Policy that returns Borsh `Decision::Allow` (`[0x00]`, staged in the
/// data segment at offset 0).
const ALLOW_ALL_POLICY_WAT: &str = r#"
(module
  (memory (export "memory") 1)
  (global $next (mut i32) (i32.const 1024))
  (func (export "alloc") (param $len i32) (result i32)
    (local $ptr i32)
    global.get $next
    local.set $ptr
    global.get $next
    local.get $len
    i32.add
    global.set $next
    local.get $ptr)
  (func (export "__vfaas_evaluate") (param i32 i32) (result i64)
    i64.const 1)
  (data (i32.const 0) "\00"))
"#;

/// Policy that returns Borsh `Decision::Deny("no fun")`:
/// `[0x01, 6u32-le, "no fun"]` = 11 bytes at offset 0.
const DENY_ALL_POLICY_WAT: &str = r#"
(module
  (memory (export "memory") 1)
  (global $next (mut i32) (i32.const 1024))
  (func (export "alloc") (param $len i32) (result i32)
    (local $ptr i32)
    global.get $next
    local.set $ptr
    global.get $next
    local.get $len
    i32.add
    global.set $next
    local.get $ptr)
  (func (export "__vfaas_evaluate") (param i32 i32) (result i64)
    i64.const 11)
  (data (i32.const 0) "\01\06\00\00\00no fun"))
"#;

/// Policy whose evaluate export traps immediately.
const TRAPPING_POLICY_WAT: &str = r#"
(module
  (memory (export "memory") 1)
  (global $next (mut i32) (i32.const 1024))
  (func (export "alloc") (param $len i32) (result i32)
    (local $ptr i32)
    global.get $next
    local.set $ptr
    global.get $next
    local.get $len
    i32.add
    global.set $next
    local.get $ptr)
  (func (export "__vfaas_evaluate") (param i32 i32) (result i64)
    unreachable))
"#;

/// Program that echoes its input: returns the packed (ptr, len) it was
/// handed.
const ECHO_PROGRAM_WAT: &str = r#"
(module
  (memory (export "memory") 1)
  (global $next (mut i32) (i32.const 1024))
  (func (export "alloc") (param $len i32) (result i32)
    (local $ptr i32)
    global.get $next
    local.set $ptr
    global.get $next
    local.get $len
    i32.add
    global.set $next
    local.get $ptr)
  (func (export "__vfaas_execute") (param $ptr i32) (param $len i32) (result i64)
    local.get $ptr
    i64.extend_i32_u
    i64.const 32
    i64.shl
    local.get $len
    i64.extend_i32_u
    i64.or))
"#;

/// Program whose execute export traps immediately.
const TRAPPING_PROGRAM_WAT: &str = r#"
(module
  (memory (export "memory") 1)
  (global $next (mut i32) (i32.const 1024))
  (func (export "alloc") (param $len i32) (result i32)
    (local $ptr i32)
    global.get $next
    local.set $ptr
    global.get $next
    local.get $len
    i32.add
    global.set $next
    local.get $ptr)
  (func (export "__vfaas_execute") (param i32 i32) (result i64)
    unreachable))
"#;

/// Program that burns ~18M fuel in a counting loop, then returns the single
/// data-segment byte. `{marker}` varies the wasm hash between registrations
/// so the same logic can be registered under different fuel budgets.
fn fuel_hungry_program_wat(marker: &str) -> String {
	format!(
		r#"
(module
  (memory (export "memory") 1)
  (global $next (mut i32) (i32.const 1024))
  (func (export "alloc") (param $len i32) (result i32)
    (local $ptr i32)
    global.get $next
    local.set $ptr
    global.get $next
    local.get $len
    i32.add
    global.set $next
    local.get $ptr)
  (func (export "__vfaas_execute") (param i32 i32) (result i64)
    (local $i i32)
    (local.set $i (i32.const 3000000))
    (block $done
      (loop $l
        local.get $i
        i32.eqz
        br_if $done
        local.get $i
        i32.const 1
        i32.sub
        local.set $i
        br $l))
    i64.const 1)
  (data (i32.const 0) "{marker}"))
"#
	)
}

struct TestQuorum {
	pairs: Vec<P256Pair>,
	members: Vec<QuorumMember>,
	set: ManifestSet,
}

impl TestQuorum {
	fn generate() -> Self {
		let pairs: Vec<P256Pair> =
			(0..3).map(|_| P256Pair::generate().unwrap()).collect();
		let members: Vec<QuorumMember> = pairs
			.iter()
			.enumerate()
			.map(|(i, pair)| QuorumMember {
				alias: format!("user{i}"),
				pub_key: pair.public_key().to_bytes(),
			})
			.collect();
		let set = ManifestSet { threshold: 2, members: members.clone() };
		Self { pairs, members, set }
	}

	fn approval(&self, artifact: &Artifact, index: usize) -> Approval {
		approve_artifact(
			artifact,
			&self.pairs[index],
			self.members[index].clone(),
		)
	}

	/// A 2-of-3 approved envelope for `wasm`.
	fn envelope(
		&self,
		kind: ArtifactKind,
		name: &str,
		wasm: &[u8],
		fuel_budget: Option<u64>,
	) -> ArtifactEnvelope {
		let artifact =
			Artifact::new(kind, name, "0.1.0", wasm, b"test", fuel_budget);
		ArtifactEnvelope {
			artifact: artifact.clone(),
			approvals: vec![
				self.approval(&artifact, 0),
				self.approval(&artifact, 1),
			],
		}
	}

	fn ruleset_approval(&self, ruleset: &Ruleset, index: usize) -> Approval {
		approve_ruleset(
			ruleset,
			&self.pairs[index],
			self.members[index].clone(),
		)
	}

	/// A 2-of-3 approved program→policy binding.
	fn ruleset_envelope(
		&self,
		program: [u8; 32],
		policy: [u8; 32],
	) -> RulesetEnvelope {
		let ruleset = Ruleset {
			program: ProgramHash::new(program),
			policy: PolicyHash::new(policy),
		};
		RulesetEnvelope {
			ruleset,
			approvals: vec![
				self.ruleset_approval(&ruleset, 0),
				self.ruleset_approval(&ruleset, 1),
			],
		}
	}
}

/// Boot a pivot on `socket` with a fresh quorum. Returns handles that clean
/// everything up on drop.
struct TestPivot {
	quorum: TestQuorum,
	client: SocketClient,
	_pivot: ChildWrapper,
	_socket: PathWrapper<String>,
	_manifest: PathWrapper<String>,
	_ephemeral: PathWrapper<String>,
}

impl TestPivot {
	async fn boot(tag: &str) -> Self {
		let quorum = TestQuorum::generate();
		let quorum_bytes = borsh::to_vec(&quorum.set).unwrap();
		Self::boot_inner(tag, "--manifest-set", quorum_bytes, quorum).await
	}

	/// Boot from the TVC layout: the artifact quorum arrives inside the
	/// enclave's own JSON manifest envelope (`/qos.manifest`, written with
	/// `to_storage_vec`) rather than as a bare Borsh `ManifestSet`.
	async fn boot_from_manifest_envelope(tag: &str) -> Self {
		let quorum = TestQuorum::generate();
		let manifest = Manifest {
			manifest_set: quorum.set.clone(),
			..Manifest::default()
		};
		let envelope = ManifestEnvelope {
			manifest,
			manifest_set_approvals: vec![],
			share_set_approvals: vec![],
		};
		let quorum_bytes = VersionedManifestEnvelope::V1(envelope)
			.to_storage_vec()
			.expect("manifest envelope serializes");
		Self::boot_inner(tag, "--manifest-envelope", quorum_bytes, quorum)
			.await
	}

	async fn boot_inner(
		tag: &str,
		quorum_flag: &str,
		quorum_bytes: Vec<u8>,
		quorum: TestQuorum,
	) -> Self {
		let socket = format!("/tmp/vfaas_test_{tag}.sock");
		let manifest_path = format!("/tmp/vfaas_test_{tag}.manifest");
		let ephemeral_path = format!("/tmp/vfaas_test_{tag}.eph");

		std::fs::write(&manifest_path, quorum_bytes).unwrap();
		P256Pair::generate().unwrap().to_hex_file(&ephemeral_path).unwrap();

		// `--port 0`: each test pivot takes an OS-assigned HTTP port so
		// parallel tests never collide; these tests speak the usock side.
		let pivot: ChildWrapper = Command::new(PIVOT_VFAAS_PATH)
			.args(["--usock", &socket])
			.args([quorum_flag, &manifest_path])
			.args(["--ephemeral-key", &ephemeral_path])
			.args(["--port", "0"])
			.spawn()
			.unwrap()
			.into();
		wait_for_usock(&socket).await;

		let pool =
			StreamPool::single(SocketAddress::new_unix(&socket)).unwrap();
		let client = SocketClient::new(pool.shared(), Duration::from_secs(10));

		Self {
			quorum,
			client,
			_pivot: pivot,
			_socket: socket.into(),
			_manifest: manifest_path.into(),
			_ephemeral: ephemeral_path.into(),
		}
	}

	async fn call(&self, msg: &VfaasMsg) -> VfaasMsg {
		let bytes =
			self.client.call(&borsh::to_vec(msg).unwrap()).await.unwrap();
		VfaasMsg::try_from_slice(&bytes).unwrap()
	}

	async fn register(
		&self,
		kind: ArtifactKind,
		name: &str,
		wasm: Vec<u8>,
		fuel_budget: Option<u64>,
		ruleset: Option<RulesetEnvelope>,
	) -> [u8; 32] {
		let envelope = self.quorum.envelope(kind, name, &wasm, fuel_budget);
		let hash = envelope.artifact.wasm_hash;
		let response = self
			.call(&VfaasMsg::RegisterArtifactRequest {
				envelope,
				wasm,
				ruleset,
			})
			.await;
		match response {
			VfaasMsg::RegisterArtifactResponse { artifact } => {
				assert_eq!(artifact.wasm_hash, hash);
				hash
			}
			other => panic!("register {name} failed: {other:?}"),
		}
	}

	async fn register_policy(&self, name: &str, wasm: Vec<u8>) -> [u8; 32] {
		self.register(ArtifactKind::Policy, name, wasm, None, None).await
	}

	/// Register a program bound to `policy`. Registering the same wasm again
	/// with a different ruleset is how a quorum rotates a program's policy.
	async fn register_program(
		&self,
		name: &str,
		wasm: Vec<u8>,
		fuel_budget: Option<u64>,
		policy: [u8; 32],
	) -> [u8; 32] {
		let ruleset = self.quorum.ruleset_envelope(sha_256(&wasm), policy);
		self.register(
			ArtifactKind::Function,
			name,
			wasm,
			fuel_budget,
			Some(ruleset),
		)
		.await
	}

	async fn execute(&self, program: [u8; 32], input: Vec<u8>) -> VfaasMsg {
		self.call(&VfaasMsg::ExecuteRequest {
			program: ProgramHash::new(program),
			input,
		})
		.await
	}
}

/// Expect an `ExecuteResponse`, verify its attestation cryptographically,
/// and sanity-check the payload's identity fields.
fn verified(
	response: VfaasMsg,
	program: [u8; 32],
	policy: [u8; 32],
	input: &[u8],
) -> (Option<Vec<u8>>, ExecutionAttestation) {
	let VfaasMsg::ExecuteResponse { output, attestation } = response else {
		panic!("expected ExecuteResponse, got {response:?}");
	};
	verify_execution_attestation(&attestation)
		.expect("attestation must verify");
	assert_eq!(attestation.payload.engine_id, engine_id());
	assert_eq!(attestation.payload.abi_version, VFAAS_ABI_VERSION);
	assert_eq!(attestation.payload.program_hash, ProgramHash::new(program));
	assert_eq!(attestation.payload.policy_hash, PolicyHash::new(policy));
	assert_eq!(attestation.payload.input_hash, sha_256(input));
	(output, attestation)
}

fn wasm(wat_text: &str) -> Vec<u8> {
	wat::parse_str(wat_text).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn vfaas_register_rejections() {
	let pivot = TestPivot::boot("reg").await;
	let echo = wasm(ECHO_PROGRAM_WAT);
	let allow_all =
		pivot.register_policy("allow-all", wasm(ALLOW_ALL_POLICY_WAT)).await;

	// A well-formed 2-of-3 envelope with a well-formed binding registers.
	let echo_hash =
		pivot.register_program("echo", echo.clone(), None, allow_all).await;
	let echo_ruleset = || pivot.quorum.ruleset_envelope(echo_hash, allow_all);

	// Tampered blob: envelope approves `echo`, different bytes arrive.
	let envelope =
		pivot.quorum.envelope(ArtifactKind::Function, "echo", &echo, None);
	let response = pivot
		.call(&VfaasMsg::RegisterArtifactRequest {
			envelope,
			wasm: wasm(TRAPPING_PROGRAM_WAT),
			ruleset: Some(echo_ruleset()),
		})
		.await;
	let VfaasMsg::Error(reason) = response else {
		panic!("tampered blob must be rejected, got {response:?}");
	};
	assert!(reason.contains("hash mismatch"), "{reason}");

	// Insufficient approvals: 1 signature against a threshold of 2.
	let artifact = Artifact::new(
		ArtifactKind::Function,
		"echo",
		"0.1.0",
		&echo,
		b"test",
		None,
	);
	let envelope = ArtifactEnvelope {
		artifact: artifact.clone(),
		approvals: vec![pivot.quorum.approval(&artifact, 0)],
	};
	let response = pivot
		.call(&VfaasMsg::RegisterArtifactRequest {
			envelope,
			wasm: echo.clone(),
			ruleset: Some(echo_ruleset()),
		})
		.await;
	let VfaasMsg::Error(reason) = response else {
		panic!("underapproved envelope must be rejected, got {response:?}");
	};
	assert!(reason.contains("not enough"), "{reason}");

	// Duplicate approver: the same member twice does not reach 2-of-3.
	let envelope = ArtifactEnvelope {
		artifact: artifact.clone(),
		approvals: vec![
			pivot.quorum.approval(&artifact, 0),
			pivot.quorum.approval(&artifact, 0),
		],
	};
	let response = pivot
		.call(&VfaasMsg::RegisterArtifactRequest {
			envelope,
			wasm: echo.clone(),
			ruleset: Some(echo_ruleset()),
		})
		.await;
	let VfaasMsg::Error(reason) = response else {
		panic!("duplicate approver must be rejected, got {response:?}");
	};
	assert!(reason.contains("duplicate"), "{reason}");

	// Non-member approval.
	let outsider = P256Pair::generate().unwrap();
	let envelope = ArtifactEnvelope {
		artifact: artifact.clone(),
		approvals: vec![
			pivot.quorum.approval(&artifact, 0),
			approve_artifact(
				&artifact,
				&outsider,
				QuorumMember {
					alias: "mallory".into(),
					pub_key: outsider.public_key().to_bytes(),
				},
			),
		],
	};
	let response = pivot
		.call(&VfaasMsg::RegisterArtifactRequest {
			envelope,
			wasm: echo.clone(),
			ruleset: Some(echo_ruleset()),
		})
		.await;
	let VfaasMsg::Error(reason) = response else {
		panic!("non-member approval must be rejected, got {response:?}");
	};
	assert!(reason.contains("non-member"), "{reason}");

	// A program without a ruleset cannot register, no matter how well its
	// own envelope is approved.
	let envelope =
		pivot.quorum.envelope(ArtifactKind::Function, "echo", &echo, None);
	let response = pivot
		.call(&VfaasMsg::RegisterArtifactRequest {
			envelope,
			wasm: echo.clone(),
			ruleset: None,
		})
		.await;
	let VfaasMsg::Error(reason) = response else {
		panic!("unbound program must be rejected, got {response:?}");
	};
	assert!(reason.contains("without a quorum-approved policy"), "{reason}");

	// A policy cannot carry a ruleset; bindings gate programs.
	let deny_wasm = wasm(DENY_ALL_POLICY_WAT);
	let envelope = pivot.quorum.envelope(
		ArtifactKind::Policy,
		"deny-all",
		&deny_wasm,
		None,
	);
	let response = pivot
		.call(&VfaasMsg::RegisterArtifactRequest {
			envelope,
			wasm: deny_wasm,
			ruleset: Some(echo_ruleset()),
		})
		.await;
	let VfaasMsg::Error(reason) = response else {
		panic!("policy with ruleset must be rejected, got {response:?}");
	};
	assert!(reason.contains("cannot carry a ruleset"), "{reason}");

	// The ruleset must bind the program being registered, not another one.
	let trapping = wasm(TRAPPING_PROGRAM_WAT);
	let envelope =
		pivot.quorum.envelope(ArtifactKind::Function, "trap", &trapping, None);
	let response = pivot
		.call(&VfaasMsg::RegisterArtifactRequest {
			envelope,
			wasm: trapping.clone(),
			ruleset: Some(echo_ruleset()),
		})
		.await;
	let VfaasMsg::Error(reason) = response else {
		panic!("mismatched ruleset must be rejected, got {response:?}");
	};
	assert!(reason.contains("ruleset binds program"), "{reason}");

	// The ruleset itself needs threshold approvals: 1-of-2 is refused.
	let ruleset = Ruleset {
		program: ProgramHash::new(sha_256(&trapping)),
		policy: PolicyHash::new(allow_all),
	};
	let underapproved = RulesetEnvelope {
		ruleset,
		approvals: vec![pivot.quorum.ruleset_approval(&ruleset, 0)],
	};
	let envelope =
		pivot.quorum.envelope(ArtifactKind::Function, "trap", &trapping, None);
	let response = pivot
		.call(&VfaasMsg::RegisterArtifactRequest {
			envelope,
			wasm: trapping.clone(),
			ruleset: Some(underapproved),
		})
		.await;
	let VfaasMsg::Error(reason) = response else {
		panic!("underapproved ruleset must be rejected, got {response:?}");
	};
	assert!(
		reason.contains("ruleset approval") && reason.contains("not enough"),
		"{reason}"
	);

	// The bound policy must already be registered...
	let envelope =
		pivot.quorum.envelope(ArtifactKind::Function, "trap", &trapping, None);
	let unregistered_policy =
		pivot.quorum.ruleset_envelope(sha_256(&trapping), [7u8; 32]);
	let response = pivot
		.call(&VfaasMsg::RegisterArtifactRequest {
			envelope,
			wasm: trapping.clone(),
			ruleset: Some(unregistered_policy),
		})
		.await;
	let VfaasMsg::Error(reason) = response else {
		panic!("unknown bound policy must be rejected, got {response:?}");
	};
	assert!(reason.contains("not registered"), "{reason}");

	// ...and must actually be a policy, not another program.
	let envelope =
		pivot.quorum.envelope(ArtifactKind::Function, "trap", &trapping, None);
	let bound_to_program =
		pivot.quorum.ruleset_envelope(sha_256(&trapping), echo_hash);
	let response = pivot
		.call(&VfaasMsg::RegisterArtifactRequest {
			envelope,
			wasm: trapping,
			ruleset: Some(bound_to_program),
		})
		.await;
	let VfaasMsg::Error(reason) = response else {
		panic!("function-as-policy binding must be rejected, got {response:?}");
	};
	assert!(reason.contains("expected a Policy"), "{reason}");

	// Garbage blob with a fully valid quorum envelope and binding: rejected
	// at registration (module compilation), never at execute time.
	let garbage = b"definitely not wasm".to_vec();
	let envelope = pivot.quorum.envelope(
		ArtifactKind::Function,
		"garbage",
		&garbage,
		None,
	);
	let ruleset = pivot.quorum.ruleset_envelope(sha_256(&garbage), allow_all);
	let response = pivot
		.call(&VfaasMsg::RegisterArtifactRequest {
			envelope,
			wasm: garbage,
			ruleset: Some(ruleset),
		})
		.await;
	let VfaasMsg::Error(reason) = response else {
		panic!("garbage blob must be rejected, got {response:?}");
	};
	assert!(reason.contains("not valid wasm"), "{reason}");

	// ABI version mismatch: quorum-approved descriptor for a future ABI.
	let mut artifact = Artifact::new(
		ArtifactKind::Function,
		"echo-v999",
		"0.1.0",
		&echo,
		b"test",
		None,
	);
	artifact.abi_version = 999;
	let envelope = ArtifactEnvelope {
		artifact: artifact.clone(),
		approvals: vec![
			pivot.quorum.approval(&artifact, 0),
			pivot.quorum.approval(&artifact, 1),
		],
	};
	let response = pivot
		.call(&VfaasMsg::RegisterArtifactRequest {
			envelope,
			wasm: echo,
			ruleset: Some(echo_ruleset()),
		})
		.await;
	let VfaasMsg::Error(reason) = response else {
		panic!("future-ABI artifact must be rejected, got {response:?}");
	};
	assert!(reason.contains("ABI"), "{reason}");
}

#[tokio::test(flavor = "multi_thread")]
async fn vfaas_execute_flows() {
	let pivot = TestPivot::boot("exec").await;

	let allow_all =
		pivot.register_policy("allow-all", wasm(ALLOW_ALL_POLICY_WAT)).await;
	let deny_all =
		pivot.register_policy("deny-all", wasm(DENY_ALL_POLICY_WAT)).await;
	let trapping_policy =
		pivot.register_policy("trap-policy", wasm(TRAPPING_POLICY_WAT)).await;

	let echo_wasm = wasm(ECHO_PROGRAM_WAT);
	let echo = pivot
		.register_program("echo", echo_wasm.clone(), None, allow_all)
		.await;
	let trapping_program = pivot
		.register_program("trap", wasm(TRAPPING_PROGRAM_WAT), None, allow_all)
		.await;

	// Allow path: the bound policy passes, program echoes, output hash is
	// bound. The caller names only the program.
	let input = b"attest me".to_vec();
	let response = pivot.execute(echo, input.clone()).await;
	let (output, attestation) = verified(response, echo, allow_all, &input);
	assert_eq!(output, Some(input.clone()));
	assert_eq!(
		attestation.payload.outcome,
		ExecutionOutcome::Allowed { output_hash: sha_256(&input) }
	);
	let first_request_id = attestation.payload.request_id;

	// Deny path via rebinding: a fresh quorum-approved ruleset rotates
	// echo's policy to deny-all — same program bytes, new binding — and the
	// attestation now names the new policy. No output, and the denial
	// itself is signed.
	pivot.register_program("echo", echo_wasm.clone(), None, deny_all).await;
	let response = pivot.execute(echo, input.clone()).await;
	let (output, attestation) = verified(response, echo, deny_all, &input);
	assert_eq!(output, None);
	assert_eq!(
		attestation.payload.outcome,
		ExecutionOutcome::Denied { reason: "no fun".into() }
	);
	assert!(attestation.payload.request_id > first_request_id);

	// Failed path, policy stage (rebind again): the trap is attested as
	// Failed, not misreported as a denial.
	pivot
		.register_program("echo", echo_wasm.clone(), None, trapping_policy)
		.await;
	let response = pivot.execute(echo, input.clone()).await;
	let (output, attestation) =
		verified(response, echo, trapping_policy, &input);
	assert_eq!(output, None);
	let ExecutionOutcome::Failed { stage: Stage::Policy, reason } =
		attestation.payload.outcome
	else {
		panic!("expected Failed at Policy, got {:?}", attestation.payload);
	};
	assert!(reason.contains("trap"), "{reason}");

	// Failed path, program stage: policy allowed, program trapped.
	let response = pivot.execute(trapping_program, input.clone()).await;
	let (output, attestation) =
		verified(response, trapping_program, allow_all, &input);
	assert_eq!(output, None);
	let ExecutionOutcome::Failed { stage: Stage::Program, reason } =
		attestation.payload.outcome
	else {
		panic!("expected Failed at Program, got {:?}", attestation.payload);
	};
	assert!(reason.contains("trap"), "{reason}");

	// Fuel: under the default budget the hungry program starves...
	let hungry_default = pivot
		.register_program(
			"hungry-default",
			wasm(&fuel_hungry_program_wat("\\2a")),
			None,
			allow_all,
		)
		.await;
	let response = pivot.execute(hungry_default, input.clone()).await;
	let (output, attestation) =
		verified(response, hungry_default, allow_all, &input);
	assert_eq!(output, None);
	let ExecutionOutcome::Failed { stage: Stage::Program, reason } =
		attestation.payload.outcome
	else {
		panic!("expected fuel exhaustion, got {:?}", attestation.payload);
	};
	assert!(reason.contains("fuel"), "{reason}");

	// ...but a quorum-approved per-artifact budget lets it finish.
	const HUNGRY_FUEL_BUDGET: u64 = 100_000_000;
	const { assert!(DEFAULT_FUEL_PER_CALL < HUNGRY_FUEL_BUDGET) };
	let hungry_budgeted = pivot
		.register_program(
			"hungry-budgeted",
			wasm(&fuel_hungry_program_wat("\\2b")),
			Some(HUNGRY_FUEL_BUDGET),
			allow_all,
		)
		.await;
	let response = pivot.execute(hungry_budgeted, input.clone()).await;
	let (output, attestation) =
		verified(response, hungry_budgeted, allow_all, &input);
	assert_eq!(output, Some(vec![0x2b]));
	assert!(matches!(
		attestation.payload.outcome,
		ExecutionOutcome::Allowed { .. }
	));

	// List reflects every registration: approval counts, and the binding —
	// functions carry their (current) bound policy, policies carry none.
	let response = pivot.call(&VfaasMsg::ListArtifactsRequest).await;
	let VfaasMsg::ListArtifactsResponse { artifacts } = response else {
		panic!("expected ListArtifactsResponse, got {response:?}");
	};
	assert_eq!(artifacts.len(), 7);
	assert!(artifacts.iter().all(|a| a.approval_count == 2));
	let bound = |hash: [u8; 32]| {
		artifacts
			.iter()
			.find(|a| a.artifact.wasm_hash == hash)
			.expect("artifact is listed")
			.bound_policy
	};
	// The list shows echo's binding as rotated by the last ruleset.
	assert_eq!(bound(echo), Some(PolicyHash::new(trapping_policy)));
	assert_eq!(bound(trapping_program), Some(PolicyHash::new(allow_all)));
	assert_eq!(bound(allow_all), None);

	// Kind confusion is a request error: a policy can't run as a program.
	let response = pivot.execute(allow_all, input.clone()).await;
	let VfaasMsg::Error(reason) = response else {
		panic!("kind confusion must error, got {response:?}");
	};
	assert!(reason.contains("expected a Function"), "{reason}");

	// Unknown artifacts are request errors too — nothing to attest.
	let response = pivot.execute([9u8; 32], input).await;
	let VfaasMsg::Error(reason) = response else {
		panic!("unknown program must error, got {response:?}");
	};
	assert!(reason.contains("not registered"), "{reason}");
}

/// The TVC deployment hands the pivot `/qos.manifest` (a JSON
/// `VersionedManifestEnvelope`), not a bare Borsh `ManifestSet`. Prove the
/// quorum extracted from the envelope verifies registrations and gates
/// execution exactly like the bare-set path.
#[tokio::test(flavor = "multi_thread")]
async fn vfaas_boots_from_manifest_envelope() {
	let pivot = TestPivot::boot_from_manifest_envelope("envelope").await;

	let allow_all = pivot
		.register_policy("allow-all", wasm(ALLOW_ALL_POLICY_WAT))
		.await;
	let echo = pivot
		.register_program("echo", wasm(ECHO_PROGRAM_WAT), None, allow_all)
		.await;

	let input = b"tvc layout".to_vec();
	let response = pivot.execute(echo, input.clone()).await;
	let (output, attestation) = verified(response, echo, allow_all, &input);
	assert_eq!(output, Some(input.clone()));
	assert_eq!(
		attestation.payload.outcome,
		ExecutionOutcome::Allowed { output_hash: sha_256(&input) }
	);
}

/// Bind an ephemeral port and release it for the pivot to take.
fn free_port() -> u16 {
	std::net::TcpListener::bind("127.0.0.1:0")
		.unwrap()
		.local_addr()
		.unwrap()
		.port()
}

fn wait_for_http_health(base: &str) -> http::Health {
	for _ in 0..100 {
		if let Ok(response) = ureq::get(&format!("{base}/health")).call() {
			return response.into_json().expect("health is json");
		}
		std::thread::sleep(Duration::from_millis(100));
	}
	panic!("pivot HTTP front never became healthy at {base}");
}

/// Smoke test for the HTTP front: health, registration, content-addressed
/// execution, attestation verification from the JSON encoding, and the
/// 404/400 request-error mappings.
#[test]
fn vfaas_http_front() {
	let port = free_port();
	let manifest_path = "/tmp/vfaas_test_http.manifest".to_string();
	let ephemeral_path = "/tmp/vfaas_test_http.eph".to_string();

	let quorum = TestQuorum::generate();
	std::fs::write(&manifest_path, borsh::to_vec(&quorum.set).unwrap())
		.unwrap();
	P256Pair::generate().unwrap().to_hex_file(&ephemeral_path).unwrap();
	let _manifest_guard: PathWrapper<String> = manifest_path.clone().into();
	let _ephemeral_guard: PathWrapper<String> = ephemeral_path.clone().into();

	let _pivot: ChildWrapper = Command::new(PIVOT_VFAAS_PATH)
		.args(["--host", "127.0.0.1", "--port", &port.to_string()])
		.args(["--manifest-set", &manifest_path])
		.args(["--ephemeral-key", &ephemeral_path])
		.spawn()
		.unwrap()
		.into();

	let base = format!("http://127.0.0.1:{port}");
	let health = wait_for_http_health(&base);
	assert_eq!(health.status, "healthy");
	let replica = health.replica.expect("ephemeral key is readable");
	assert_eq!(replica.len(), 8, "replica is the first 8 hex chars");

	// Register a policy, then a function bound to it. Signed governance
	// blobs travel as hex Borsh — the exact bytes the quorum approved.
	let allow_all_wasm = wasm(ALLOW_ALL_POLICY_WAT);
	let policy_envelope = quorum.envelope(
		ArtifactKind::Policy,
		"allow-all",
		&allow_all_wasm,
		None,
	);
	let allow_all = policy_envelope.artifact.wasm_hash;
	let registered: http::Registered =
		ureq::post(&format!("{base}/artifacts"))
			.send_json(http::RegisterRequest {
				envelope: qos_hex::encode(
					&borsh::to_vec(&policy_envelope).unwrap(),
				),
				wasm: qos_hex::encode(&allow_all_wasm),
				ruleset: None,
			})
			.expect("policy registers over http")
			.into_json()
			.unwrap();
	assert_eq!(registered.wasm_hash, qos_hex::encode(&allow_all));
	assert_eq!(registered.replica, Some(replica));

	let echo_wasm = wasm(ECHO_PROGRAM_WAT);
	let echo_envelope =
		quorum.envelope(ArtifactKind::Function, "echo", &echo_wasm, None);
	let echo = echo_envelope.artifact.wasm_hash;
	let ruleset = quorum.ruleset_envelope(echo, allow_all);
	let _: http::Registered = ureq::post(&format!("{base}/artifacts"))
		.send_json(http::RegisterRequest {
			envelope: qos_hex::encode(&borsh::to_vec(&echo_envelope).unwrap()),
			wasm: qos_hex::encode(&echo_wasm),
			ruleset: Some(qos_hex::encode(&borsh::to_vec(&ruleset).unwrap())),
		})
		.expect("function registers over http")
		.into_json()
		.unwrap();

	// The listing shows both artifacts and the function's binding.
	let listing: http::Artifacts = ureq::get(&format!("{base}/artifacts"))
		.call()
		.expect("artifacts listing")
		.into_json()
		.unwrap();
	assert_eq!(listing.artifacts.len(), 2);
	let echo_summary =
		listing.artifacts.iter().find(|a| a.name == "echo").unwrap();
	assert_eq!(echo_summary.kind, "function");
	assert_eq!(echo_summary.bound_policy, Some(qos_hex::encode(&allow_all)));

	// Content-addressed execution: POST /f/<program hash>.
	let input = b"http attest".to_vec();
	let execution: http::Execution =
		ureq::post(&format!("{base}/f/{}", qos_hex::encode(&echo)))
			.send_json(http::ExecuteRequest {
				input: qos_hex::encode(&input),
			})
			.expect("execution succeeds")
			.into_json()
			.unwrap();
	assert_eq!(execution.output, Some(qos_hex::encode(&input)));

	// `payload_borsh` is the exact signed byte string: reconstruct the
	// attestation from it and verify without trusting the decoded view.
	let att = &execution.attestation;
	let payload_bytes = qos_hex::decode(&att.payload_borsh).unwrap();
	let signed = ExecutionAttestation {
		payload: ExecutionAttestationPayload::try_from_slice(&payload_bytes)
			.unwrap(),
		signature: qos_hex::decode(&att.signature).unwrap(),
		ephemeral_public_key: qos_hex::decode(&att.ephemeral_public_key)
			.unwrap(),
	};
	verify_execution_attestation(&signed).expect("attestation verifies");
	assert_eq!(signed.payload.program_hash, ProgramHash::new(echo));
	assert_eq!(signed.payload.policy_hash, PolicyHash::new(allow_all));
	assert_eq!(
		signed.payload.outcome,
		ExecutionOutcome::Allowed { output_hash: sha_256(&input) }
	);
	// ...and the decoded JSON view agrees with the signed bytes.
	assert_eq!(att.payload.request_id, signed.payload.request_id);
	assert!(matches!(
		&att.payload.outcome,
		http::Outcome::Allowed { output_hash }
			if *output_hash == qos_hex::encode(&sha_256(&input))
	));

	// Unknown content address: 404, nothing attested.
	let miss = ureq::post(&format!("{base}/f/{}", "9".repeat(64)))
		.send_json(http::ExecuteRequest { input: qos_hex::encode(&input) });
	assert!(matches!(miss, Err(ureq::Error::Status(404, _))), "{miss:?}");

	// Malformed registration: 400 before anything reaches the processor.
	let bad = ureq::post(&format!("{base}/artifacts")).send_json(
		http::RegisterRequest {
			envelope: "not-hex".to_string(),
			wasm: String::new(),
			ruleset: None,
		},
	);
	assert!(matches!(bad, Err(ureq::Error::Status(400, _))), "{bad:?}");
}
