//! Shared ABI types for vfaas ("Verifiable Functions as a Service").
//!
//! This crate is the single source of truth for every type that crosses the
//! host/guest or host/client boundary: the guest SDK, the `pivot_vfaas`
//! host, and client tooling all depend on it by path, so the wire layout
//! cannot silently drift between them.
//!
//! Dependency policy: `borsh` only. That keeps the crate compiling for both
//! the enclave host and `wasm32-unknown-unknown` guests.

use core::fmt;

use borsh::{BorshDeserialize, BorshSerialize};

/// Version of the vfaas guest ABI.
///
/// Baked into every artifact descriptor at approval time and into every
/// [`ExecutionAttestationPayload`], so a verifier can tell exactly which
/// contract an execution was performed under.
pub const VFAAS_ABI_VERSION: u32 = 1;

macro_rules! hash_newtype {
	($(#[$meta:meta])* $name:ident) => {
		$(#[$meta])*
		#[derive(BorshDeserialize, BorshSerialize, Clone, Copy, PartialEq, Eq, Hash)]
		pub struct $name([u8; 32]);

		impl $name {
			/// Wrap a raw SHA-256 digest.
			#[must_use]
			pub const fn new(digest: [u8; 32]) -> Self {
				Self(digest)
			}

			/// The raw digest bytes.
			#[must_use]
			pub const fn as_bytes(&self) -> &[u8; 32] {
				&self.0
			}
		}

		impl From<[u8; 32]> for $name {
			fn from(digest: [u8; 32]) -> Self {
				Self(digest)
			}
		}

		impl fmt::Display for $name {
			fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
				for byte in &self.0 {
					write!(f, "{byte:02x}")?;
				}
				Ok(())
			}
		}

		impl fmt::Debug for $name {
			fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
				write!(f, concat!(stringify!($name), "({})"), self)
			}
		}
	};
}

hash_newtype! {
	/// SHA-256 of a registered program's WASM bytes.
	///
	/// A distinct type from [`PolicyHash`] so a program hash and a policy
	/// hash can never be swapped positionally without a compile error.
	ProgramHash
}

hash_newtype! {
	/// SHA-256 of a registered policy's WASM bytes.
	///
	/// See [`ProgramHash`] for why this is not a bare `[u8; 32]`.
	PolicyHash
}

/// Verdict returned by a policy evaluation.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, PartialEq, Eq)]
pub enum Decision {
	/// Permit program execution.
	Allow,
	/// Refuse program execution, with a human-readable reason.
	Deny(String),
}

/// Which stage of an execution attempt failed.
#[derive(BorshDeserialize, BorshSerialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
	/// The policy evaluation stage.
	Policy,
	/// The program execution stage (only reached after an Allow).
	Program,
}

/// The three-state outcome of one execution attempt.
///
/// `Denied` and `Failed` are deliberately distinct: `Denied` means the
/// policy ran to completion and said no, while `Failed` means a stage
/// crashed, trapped, ran out of fuel, or produced undecodable bytes and no
/// verdict (or no output) was ever reached. Collapsing the two would let a
/// verifier mistake an engine malfunction for a governed denial.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, PartialEq, Eq)]
pub enum ExecutionOutcome {
	/// The policy allowed execution and the program ran to completion.
	Allowed {
		/// SHA-256 of the produced output bytes.
		output_hash: [u8; 32],
	},
	/// The policy evaluated successfully and denied execution.
	Denied {
		/// The policy's stated reason.
		reason: String,
	},
	/// The named stage failed before producing a verdict or output.
	Failed {
		/// Which stage failed.
		stage: Stage,
		/// Human-readable failure description.
		reason: String,
	},
}

/// What a policy receives on every evaluation.
///
/// The host Borsh-encodes this struct and passes the bytes as the single
/// argument to the policy's `__vfaas_evaluate` export.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, PartialEq, Eq)]
pub struct PolicyRequest {
	/// SHA-256 of the program WASM about to run, precomputed by the host so
	/// hash-based policies do not burn fuel hashing multi-megabyte modules.
	pub program_hash: ProgramHash,
	/// SHA-256 of `input`, precomputed by the host.
	pub input_hash: [u8; 32],
	/// The input bytes the program will receive.
	pub input: Vec<u8>,
	/// Full program WASM bytes. Always `Some` in ABI v1; optional so a
	/// future host can elide the (potentially large) module bytes without a
	/// breaking layout change.
	pub program: Option<Vec<u8>>,
}

/// The statement the enclave signs about one execution attempt.
///
/// Signed on *every* attempt — allowed, denied, or failed — so denials and
/// crashes are just as auditable as successes.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, PartialEq, Eq)]
pub struct ExecutionAttestationPayload {
	/// Identity of the executing engine build.
	pub engine_id: [u8; 32],
	/// ABI version the engine spoke ([`VFAAS_ABI_VERSION`]).
	pub abi_version: u32,
	/// SHA-256 of the program WASM.
	pub program_hash: ProgramHash,
	/// SHA-256 of the policy WASM.
	pub policy_hash: PolicyHash,
	/// SHA-256 of the input bytes.
	pub input_hash: [u8; 32],
	/// What happened.
	pub outcome: ExecutionOutcome,
	/// Monotonic per-pivot counter ordering execution attempts.
	pub request_id: u64,
}

/// An [`ExecutionAttestationPayload`] signed by the enclave's ephemeral key.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, PartialEq, Eq)]
pub struct ExecutionAttestation {
	/// The signed statement.
	pub payload: ExecutionAttestationPayload,
	/// P-256 signature over `borsh::to_vec(&payload)`.
	pub signature: Vec<u8>,
	/// Ephemeral public key bytes (SEC1, `encrypt_public || sign_public`).
	pub ephemeral_public_key: Vec<u8>,
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn hash_newtype_displays_as_hex() {
		let mut digest = [0u8; 32];
		digest[0] = 0xab;
		digest[31] = 0x01;
		let hash = ProgramHash::new(digest);
		let hex = hash.to_string();
		assert_eq!(hex.len(), 64);
		assert!(hex.starts_with("ab"));
		assert!(hex.ends_with("01"));
		assert_eq!(format!("{hash:?}"), format!("ProgramHash({hex})"));
	}

	#[test]
	fn hash_newtype_borsh_layout_is_raw_digest() {
		// The newtype must serialize as exactly the 32 digest bytes so the
		// wire layout matches a bare `[u8; 32]`.
		let digest = [7u8; 32];
		let bytes = borsh::to_vec(&PolicyHash::new(digest)).unwrap();
		assert_eq!(bytes, digest.to_vec());
		let back = PolicyHash::try_from_slice(&bytes).unwrap();
		assert_eq!(back, PolicyHash::from(digest));
	}

	#[test]
	fn outcome_round_trips() {
		let outcomes = [
			ExecutionOutcome::Allowed { output_hash: [9u8; 32] },
			ExecutionOutcome::Denied { reason: "nope".into() },
			ExecutionOutcome::Failed {
				stage: Stage::Program,
				reason: "trap".into(),
			},
		];
		for outcome in outcomes {
			let bytes = borsh::to_vec(&outcome).unwrap();
			let back = ExecutionOutcome::try_from_slice(&bytes).unwrap();
			assert_eq!(back, outcome);
		}
	}

	#[test]
	fn attestation_round_trips() {
		let payload = ExecutionAttestationPayload {
			engine_id: [1u8; 32],
			abi_version: VFAAS_ABI_VERSION,
			program_hash: ProgramHash::new([2u8; 32]),
			policy_hash: PolicyHash::new([3u8; 32]),
			input_hash: [4u8; 32],
			outcome: ExecutionOutcome::Denied { reason: "why".into() },
			request_id: 42,
		};
		let signed = ExecutionAttestation {
			payload,
			signature: vec![5u8; 64],
			ephemeral_public_key: vec![6u8; 130],
		};
		let bytes = borsh::to_vec(&signed).unwrap();
		let back = ExecutionAttestation::try_from_slice(&bytes).unwrap();
		assert_eq!(back, signed);
	}

	#[test]
	fn policy_request_round_trips() {
		let request = PolicyRequest {
			program_hash: ProgramHash::new([8u8; 32]),
			input_hash: [9u8; 32],
			input: b"hello".to_vec(),
			program: Some(b"\0asm".to_vec()),
		};
		let bytes = borsh::to_vec(&request).unwrap();
		let back = PolicyRequest::try_from_slice(&bytes).unwrap();
		assert_eq!(back, request);
	}
}
