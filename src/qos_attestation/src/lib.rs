//! Self-attestation for QOS pivots.
//!
//! A pivot can ask the NSM for an attestation document over its own
//! manifest and ephemeral key, verify that document before trusting it, and
//! cache it so requests don't each pay for an NSM call. The layers can be
//! used on their own:
//!
//! - [`inputs`]: load the ephemeral key and manifest a document must bind
//!   to.
//! - [`verify`]: attest once and verify the chain, the signature and the
//!   binding to our inputs, under an explicit PCR18 policy.
//! - `cache` (feature `cache`): a single-flight cache with background
//!   refresh and a lock-free snapshot for request paths.
//!
//! The library never logs or exits. It reports what happened through typed
//! errors and stats, and the pivot decides what to do.
//!
//! Boot-proof manifest bytes come from
//! `VersionedManifestEnvelope::boot_proof_manifest_bytes` in `qos_core`.
//! They are public, and they include the pivot args and, for v2 manifests,
//! the pivot environment, so never put secrets there.
//!
//! Verification that skips the certificate chain exists only with the
//! non-default `unsafe-verifier` feature, for emulated NSMs that don't sign.
//! Default constructors and functions always verify the full chain.
#![cfg_attr(
	not(feature = "unsafe-verifier"),
	doc = "```compile_fail\nlet _ = qos_attestation::unsafe_verify_self_attestation_skip_chain;\n```"
)]

mod error;
pub mod inputs;
pub mod verify;

#[cfg(feature = "cache")]
pub mod cache;

#[cfg(test)]
mod test_support;

pub use error::Error;
pub use inputs::{
	AttestationInputs, MAX_MANIFEST_BYTES, read_manifest_envelope,
};
#[cfg(feature = "unsafe-verifier")]
pub use verify::unsafe_verify_self_attestation_skip_chain;
pub use verify::{
	ManifestOnlyCommitment, VerifiedAttestation, VerifyPolicy, attest_self,
	verify_self_attestation,
};
