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
			Artifact, ArtifactEnvelope, ArtifactKind, approve_artifact,
		},
		verify_execution_attestation,
	},
	wait_for_usock,
};
use qos_core::{
	client::SocketClient,
	io::{SocketAddress, StreamPool},
	protocol::services::boot::{Approval, ManifestSet, QuorumMember},
};
use qos_crypto::sha_256;
use qos_p256::P256Pair;
use qos_test_primitives::{ChildWrapper, PathWrapper};
use vfaas_abi::{
	ExecutionAttestation, ExecutionOutcome, PolicyHash, ProgramHash, Stage,
	VFAAS_ABI_VERSION,
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
		let socket = format!("/tmp/vfaas_test_{tag}.sock");
		let manifest_path = format!("/tmp/vfaas_test_{tag}.manifest");
		let ephemeral_path = format!("/tmp/vfaas_test_{tag}.eph");

		let quorum = TestQuorum::generate();
		std::fs::write(&manifest_path, borsh::to_vec(&quorum.set).unwrap())
			.unwrap();
		P256Pair::generate().unwrap().to_hex_file(&ephemeral_path).unwrap();

		let pivot: ChildWrapper = Command::new(PIVOT_VFAAS_PATH)
			.arg(&socket)
			.arg(&manifest_path)
			.arg(&ephemeral_path)
			.spawn()
			.unwrap()
			.into();
		wait_for_usock(&socket).await;

		let pool =
			StreamPool::single(SocketAddress::new_unix(&socket)).unwrap();
		let client =
			SocketClient::new(pool.shared(), Duration::from_secs(10));

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
		let bytes = self.client.call(&borsh::to_vec(msg).unwrap()).await.unwrap();
		VfaasMsg::try_from_slice(&bytes).unwrap()
	}

	async fn register(
		&self,
		kind: ArtifactKind,
		name: &str,
		wasm: Vec<u8>,
		fuel_budget: Option<u64>,
	) -> [u8; 32] {
		let envelope = self.quorum.envelope(kind, name, &wasm, fuel_budget);
		let hash = envelope.artifact.wasm_hash;
		let response = self
			.call(&VfaasMsg::RegisterArtifactRequest { envelope, wasm })
			.await;
		match response {
			VfaasMsg::RegisterArtifactResponse { artifact } => {
				assert_eq!(artifact.wasm_hash, hash);
				hash
			}
			other => panic!("register {name} failed: {other:?}"),
		}
	}

	async fn execute(
		&self,
		program: [u8; 32],
		policy: [u8; 32],
		input: Vec<u8>,
	) -> VfaasMsg {
		self.call(&VfaasMsg::ExecuteRequest {
			program: ProgramHash::new(program),
			policy: PolicyHash::new(policy),
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

	// A well-formed 2-of-3 envelope registers.
	pivot
		.register(ArtifactKind::Function, "echo", echo.clone(), None)
		.await;

	// Tampered blob: envelope approves `echo`, different bytes arrive.
	let envelope = pivot.quorum.envelope(
		ArtifactKind::Function,
		"echo",
		&echo,
		None,
	);
	let response = pivot
		.call(&VfaasMsg::RegisterArtifactRequest {
			envelope,
			wasm: wasm(TRAPPING_PROGRAM_WAT),
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
		})
		.await;
	let VfaasMsg::Error(reason) = response else {
		panic!("non-member approval must be rejected, got {response:?}");
	};
	assert!(reason.contains("non-member"), "{reason}");

	// Garbage blob with a fully valid quorum envelope: rejected at
	// registration (module compilation), never at execute time.
	let garbage = b"definitely not wasm".to_vec();
	let envelope = pivot.quorum.envelope(
		ArtifactKind::Function,
		"garbage",
		&garbage,
		None,
	);
	let response = pivot
		.call(&VfaasMsg::RegisterArtifactRequest { envelope, wasm: garbage })
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
		.call(&VfaasMsg::RegisterArtifactRequest { envelope, wasm: echo })
		.await;
	let VfaasMsg::Error(reason) = response else {
		panic!("future-ABI artifact must be rejected, got {response:?}");
	};
	assert!(reason.contains("ABI"), "{reason}");
}

#[tokio::test(flavor = "multi_thread")]
async fn vfaas_execute_flows() {
	let pivot = TestPivot::boot("exec").await;

	let echo = pivot
		.register(
			ArtifactKind::Function,
			"echo",
			wasm(ECHO_PROGRAM_WAT),
			None,
		)
		.await;
	let trapping_program = pivot
		.register(
			ArtifactKind::Function,
			"trap",
			wasm(TRAPPING_PROGRAM_WAT),
			None,
		)
		.await;
	let allow_all = pivot
		.register(
			ArtifactKind::Policy,
			"allow-all",
			wasm(ALLOW_ALL_POLICY_WAT),
			None,
		)
		.await;
	let deny_all = pivot
		.register(
			ArtifactKind::Policy,
			"deny-all",
			wasm(DENY_ALL_POLICY_WAT),
			None,
		)
		.await;
	let trapping_policy = pivot
		.register(
			ArtifactKind::Policy,
			"trap-policy",
			wasm(TRAPPING_POLICY_WAT),
			None,
		)
		.await;

	// List reflects every registration with its approval count.
	let response = pivot.call(&VfaasMsg::ListArtifactsRequest).await;
	let VfaasMsg::ListArtifactsResponse { artifacts } = response else {
		panic!("expected ListArtifactsResponse, got {response:?}");
	};
	assert_eq!(artifacts.len(), 5);
	assert!(artifacts.iter().all(|a| a.approval_count == 2));

	// Allow path: policy passes, program echoes, output hash is bound.
	let input = b"attest me".to_vec();
	let response = pivot.execute(echo, allow_all, input.clone()).await;
	let (output, attestation) = verified(response, echo, allow_all, &input);
	assert_eq!(output, Some(input.clone()));
	assert_eq!(
		attestation.payload.outcome,
		ExecutionOutcome::Allowed { output_hash: sha_256(&input) }
	);
	let first_request_id = attestation.payload.request_id;

	// Deny path: no output, and the denial itself is signed.
	let response = pivot.execute(echo, deny_all, input.clone()).await;
	let (output, attestation) = verified(response, echo, deny_all, &input);
	assert_eq!(output, None);
	assert_eq!(
		attestation.payload.outcome,
		ExecutionOutcome::Denied { reason: "no fun".into() }
	);
	assert!(attestation.payload.request_id > first_request_id);

	// Failed path, policy stage: the trap is attested as Failed, not
	// misreported as a denial.
	let response = pivot.execute(echo, trapping_policy, input.clone()).await;
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
	let response =
		pivot.execute(trapping_program, allow_all, input.clone()).await;
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
		.register(
			ArtifactKind::Function,
			"hungry-default",
			wasm(&fuel_hungry_program_wat("\\2a")),
			None,
		)
		.await;
	let response =
		pivot.execute(hungry_default, allow_all, input.clone()).await;
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
		.register(
			ArtifactKind::Function,
			"hungry-budgeted",
			wasm(&fuel_hungry_program_wat("\\2b")),
			Some(HUNGRY_FUEL_BUDGET),
		)
		.await;
	let response =
		pivot.execute(hungry_budgeted, allow_all, input.clone()).await;
	let (output, attestation) =
		verified(response, hungry_budgeted, allow_all, &input);
	assert_eq!(output, Some(vec![0x2b]));
	assert!(matches!(
		attestation.payload.outcome,
		ExecutionOutcome::Allowed { .. }
	));

	// Kind confusion is a request error: a policy can't run as a program.
	let response = pivot.execute(allow_all, allow_all, input.clone()).await;
	let VfaasMsg::Error(reason) = response else {
		panic!("kind confusion must error, got {response:?}");
	};
	assert!(reason.contains("expected a Function"), "{reason}");

	// Unknown artifacts are request errors too — nothing to attest.
	let response = pivot.execute([9u8; 32], allow_all, input).await;
	let VfaasMsg::Error(reason) = response else {
		panic!("unknown program must error, got {response:?}");
	};
	assert!(reason.contains("not registered"), "{reason}");
}
