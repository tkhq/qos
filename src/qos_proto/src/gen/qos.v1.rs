/// Enclave configuration specific to AWS Nitro.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NitroConfig {
    /// Hash of the enclave image file (PCR0)
    #[prost(bytes = "vec", tag = "1")]
    #[serde(with = "qos_hex::serde")]
    pub pcr0: ::prost::alloc::vec::Vec<u8>,
    /// Hash of the Linux kernel and bootstrap (PCR1)
    #[prost(bytes = "vec", tag = "2")]
    #[serde(with = "qos_hex::serde")]
    pub pcr1: ::prost::alloc::vec::Vec<u8>,
    /// Hash of the application (PCR2)
    #[prost(bytes = "vec", tag = "3")]
    #[serde(with = "qos_hex::serde")]
    pub pcr2: ::prost::alloc::vec::Vec<u8>,
    /// Hash of the IAM role ARN (PCR3)
    #[prost(bytes = "vec", tag = "4")]
    #[serde(with = "qos_hex::serde")]
    pub pcr3: ::prost::alloc::vec::Vec<u8>,
    /// DER encoded X509 AWS root certificate
    #[prost(bytes = "vec", tag = "5")]
    #[serde(with = "qos_hex::serde")]
    pub aws_root_certificate: ::prost::alloc::vec::Vec<u8>,
    /// Reference to the commit QOS was built off of
    #[prost(string, tag = "6")]
    pub qos_commit: ::prost::alloc::string::String,
}
/// Pivot binary configuration
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PivotConfig {
    /// SHA-256 hash of the pivot binary
    #[prost(bytes = "vec", tag = "1")]
    #[serde(with = "qos_hex::serde")]
    pub hash: ::prost::alloc::vec::Vec<u8>,
    /// Restart policy for running the pivot binary
    #[prost(enumeration = "RestartPolicy", tag = "2")]
    pub restart: i32,
    /// Arguments to invoke the binary with
    #[prost(string, repeated, tag = "3")]
    pub args: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}
/// A quorum member's alias and public key.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QuorumMember {
    /// Human readable alias to identify the member
    #[prost(string, tag = "1")]
    pub alias: ::prost::alloc::string::String,
    /// P256 public key bytes
    #[prost(bytes = "vec", tag = "2")]
    #[serde(with = "qos_hex::serde")]
    pub pub_key: ::prost::alloc::vec::Vec<u8>,
}
/// A member of a quorum set identified solely by their public key.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MemberPubKey {
    /// P256 public key bytes
    #[prost(bytes = "vec", tag = "1")]
    #[serde(with = "qos_hex::serde")]
    pub pub_key: ::prost::alloc::vec::Vec<u8>,
}
/// The Manifest Set - members who can approve manifests.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ManifestSet {
    /// Threshold K of signatures necessary for quorum
    #[prost(uint32, tag = "1")]
    pub threshold: u32,
    /// Members composing the set (N >= K)
    #[prost(message, repeated, tag = "2")]
    pub members: ::prost::alloc::vec::Vec<QuorumMember>,
}
/// The Share Set - members who hold key shares.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ShareSet {
    /// Threshold K of signatures necessary for quorum
    #[prost(uint32, tag = "1")]
    pub threshold: u32,
    /// Members composing the set (N >= K)
    #[prost(message, repeated, tag = "2")]
    pub members: ::prost::alloc::vec::Vec<QuorumMember>,
}
/// The Patch Set - members who can approve patches.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PatchSet {
    /// Threshold K of signatures necessary for quorum
    #[prost(uint32, tag = "1")]
    pub threshold: u32,
    /// Public keys of members (N >= K)
    #[prost(message, repeated, tag = "2")]
    pub members: ::prost::alloc::vec::Vec<MemberPubKey>,
}
/// A Namespace and its relative nonce.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Namespace {
    /// Unique namespace name
    #[prost(string, tag = "1")]
    pub name: ::prost::alloc::string::String,
    /// Monotonically increasing nonce to prevent downgrade attacks
    #[prost(uint32, tag = "2")]
    pub nonce: u32,
    /// P256 quorum key public bytes
    #[prost(bytes = "vec", tag = "3")]
    #[serde(with = "qos_hex::serde")]
    pub quorum_key: ::prost::alloc::vec::Vec<u8>,
}
/// The Manifest for the enclave.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Manifest {
    /// Namespace this manifest belongs to
    #[prost(message, optional, tag = "1")]
    pub namespace: ::core::option::Option<Namespace>,
    /// Pivot binary configuration
    #[prost(message, optional, tag = "2")]
    pub pivot: ::core::option::Option<PivotConfig>,
    /// Manifest Set members and threshold
    #[prost(message, optional, tag = "3")]
    pub manifest_set: ::core::option::Option<ManifestSet>,
    /// Share Set members and threshold
    #[prost(message, optional, tag = "4")]
    pub share_set: ::core::option::Option<ShareSet>,
    /// Enclave hardware configuration
    #[prost(message, optional, tag = "5")]
    pub enclave: ::core::option::Option<NitroConfig>,
    /// Patch set members and threshold
    #[prost(message, optional, tag = "6")]
    pub patch_set: ::core::option::Option<PatchSet>,
    /// Client timeout for calls via the VSOCK/USOCK (optional, defaults to 5s)
    #[prost(uint32, optional, tag = "7")]
    pub client_timeout_ms: ::core::option::Option<u32>,
    /// Pool size for socket pipes (optional, defaults to 1)
    #[prost(uint32, optional, tag = "8")]
    pub pool_size: ::core::option::Option<u32>,
}
/// An approval by a Quorum Member.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Approval {
    /// P256 ECDSA signature over the manifest hash
    #[prost(bytes = "vec", tag = "1")]
    #[serde(with = "qos_hex::serde")]
    pub signature: ::prost::alloc::vec::Vec<u8>,
    /// The quorum member who signed
    #[prost(message, optional, tag = "2")]
    pub member: ::core::option::Option<QuorumMember>,
}
/// Manifest with accompanying Approvals.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ManifestEnvelope {
    /// Encapsulated manifest
    #[prost(message, optional, tag = "1")]
    pub manifest: ::core::option::Option<Manifest>,
    /// Approvals from the manifest set
    #[prost(message, repeated, tag = "2")]
    pub manifest_set_approvals: ::prost::alloc::vec::Vec<Approval>,
    /// Approvals from the share set (for audit)
    #[prost(message, repeated, tag = "3")]
    pub share_set_approvals: ::prost::alloc::vec::Vec<Approval>,
}
/// Policy for restarting the pivot binary.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum RestartPolicy {
    /// Unspecified restart policy
    Unspecified = 0,
    /// Never restart the pivot binary after it exits
    Never = 1,
    /// Always restart the pivot binary after it exits
    Always = 2,
}
impl RestartPolicy {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            RestartPolicy::Unspecified => "RESTART_POLICY_UNSPECIFIED",
            RestartPolicy::Never => "RESTART_POLICY_NEVER",
            RestartPolicy::Always => "RESTART_POLICY_ALWAYS",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "RESTART_POLICY_UNSPECIFIED" => Some(Self::Unspecified),
            "RESTART_POLICY_NEVER" => Some(Self::Never),
            "RESTART_POLICY_ALWAYS" => Some(Self::Always),
            _ => None,
        }
    }
}
/// Configuration for sharding a Quorum Key created in the Genesis flow.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GenesisSet {
    /// Share Set Members whose keys will be used to encrypt outputs
    #[prost(message, repeated, tag = "1")]
    pub members: ::prost::alloc::vec::Vec<QuorumMember>,
    /// Threshold for successful reconstitution of the Quorum Key shards
    #[prost(uint32, tag = "2")]
    pub threshold: u32,
}
/// A member shard - internal type for recovery permutations.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MemberShard {
    /// Member of the Setup Set
    #[prost(message, optional, tag = "1")]
    pub member: ::core::option::Option<QuorumMember>,
    /// Shard encrypted to the member's key
    #[prost(bytes = "vec", tag = "2")]
    #[serde(with = "qos_hex::serde")]
    pub shard: ::prost::alloc::vec::Vec<u8>,
}
/// A set of member shards used to successfully recover the quorum key.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RecoveredPermutation {
    /// The shards that were used for recovery
    #[prost(message, repeated, tag = "1")]
    pub shards: ::prost::alloc::vec::Vec<MemberShard>,
}
/// Genesis output per Setup Member.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GenesisMemberOutput {
    /// The Quorum Member whose Setup Key was used
    #[prost(message, optional, tag = "1")]
    pub share_set_member: ::core::option::Option<QuorumMember>,
    /// Quorum Key Share encrypted to the member's Personal Key
    #[prost(bytes = "vec", tag = "2")]
    #[serde(with = "qos_hex::serde")]
    pub encrypted_quorum_key_share: ::prost::alloc::vec::Vec<u8>,
    /// SHA-512 hash of the plaintext quorum key share (for verification)
    #[prost(bytes = "vec", tag = "3")]
    #[serde(with = "qos_hex::serde")]
    pub share_hash: ::prost::alloc::vec::Vec<u8>,
}
/// Output from running Genesis Boot.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GenesisOutput {
    /// Public Quorum Key, DER encoded
    #[prost(bytes = "vec", tag = "1")]
    #[serde(with = "qos_hex::serde")]
    pub quorum_key: ::prost::alloc::vec::Vec<u8>,
    /// Quorum Member specific outputs from the genesis ceremony
    #[prost(message, repeated, tag = "2")]
    pub member_outputs: ::prost::alloc::vec::Vec<GenesisMemberOutput>,
    /// All successfully recovered permutations during genesis
    #[prost(message, repeated, tag = "3")]
    pub recovery_permutations: ::prost::alloc::vec::Vec<RecoveredPermutation>,
    /// The threshold K used to generate the shards
    #[prost(uint32, tag = "4")]
    pub threshold: u32,
    /// The quorum key encrypted to the DR key (if DR key was provided)
    #[prost(bytes = "vec", optional, tag = "5")]
    #[serde(with = "qos_hex::serde_option")]
    pub dr_key_wrapped_quorum_key: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
    /// SHA-512 hash of the quorum key secret
    #[prost(bytes = "vec", tag = "6")]
    #[serde(with = "qos_hex::serde")]
    pub quorum_key_hash: ::prost::alloc::vec::Vec<u8>,
    /// Test message encrypted to the quorum public key
    #[prost(bytes = "vec", tag = "7")]
    #[serde(with = "qos_hex::serde")]
    pub test_message_ciphertext: ::prost::alloc::vec::Vec<u8>,
    /// Signature over the test message by the quorum key
    #[prost(bytes = "vec", tag = "8")]
    #[serde(with = "qos_hex::serde")]
    pub test_message_signature: ::prost::alloc::vec::Vec<u8>,
    /// The message used for the test signature and ciphertext
    #[prost(bytes = "vec", tag = "9")]
    #[serde(with = "qos_hex::serde")]
    pub test_message: ::prost::alloc::vec::Vec<u8>,
}
/// Request type for the Nitro Secure Module API.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NsmRequest {
    /// The specific NSM request variant
    #[prost(oneof = "nsm_request::Request", tags = "1, 2, 3, 4, 5, 6, 7")]
    pub request: ::core::option::Option<nsm_request::Request>,
}
/// Nested message and enum types in `NsmRequest`.
pub mod nsm_request {
    /// The specific NSM request variant
    #[derive(serde::Serialize, serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Request {
        /// Request to describe a PCR
        #[prost(message, tag = "1")]
        DescribePcr(super::DescribePcrRequest),
        /// Request to extend a PCR
        #[prost(message, tag = "2")]
        ExtendPcr(super::ExtendPcrRequest),
        /// Request to lock a single PCR
        #[prost(message, tag = "3")]
        LockPcr(super::LockPcrRequest),
        /// Request to lock a range of PCRs
        #[prost(message, tag = "4")]
        LockPcrs(super::LockPcrsRequest),
        /// Request to describe NSM capabilities
        #[prost(message, tag = "5")]
        DescribeNsm(super::DescribeNsmRequest),
        /// Request for an attestation document
        #[prost(message, tag = "6")]
        Attestation(super::AttestationRequest),
        /// Request for random bytes
        #[prost(message, tag = "7")]
        GetRandom(super::GetRandomRequest),
    }
}
/// Request to describe a specific PCR.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DescribePcrRequest {
    /// PCR index to describe (0-15)
    #[prost(uint32, tag = "1")]
    pub index: u32,
}
/// Request to extend a PCR with additional data.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ExtendPcrRequest {
    /// PCR index to extend (0-15)
    #[prost(uint32, tag = "1")]
    pub index: u32,
    /// Data to extend into the PCR
    #[prost(bytes = "vec", tag = "2")]
    #[serde(with = "qos_hex::serde")]
    pub data: ::prost::alloc::vec::Vec<u8>,
}
/// Request to lock a specific PCR.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct LockPcrRequest {
    /// PCR index to lock (0-15)
    #[prost(uint32, tag = "1")]
    pub index: u32,
}
/// Request to lock a range of PCRs.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct LockPcrsRequest {
    /// Number of PCRs to lock starting from index 0
    #[prost(uint32, tag = "1")]
    pub range: u32,
}
/// Request to describe NSM capabilities.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DescribeNsmRequest {}
/// Request for an attestation document.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AttestationRequest {
    /// Optional user data to include in attestation (max 512 bytes)
    #[prost(bytes = "vec", optional, tag = "1")]
    #[serde(with = "qos_hex::serde_option")]
    pub user_data: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
    /// Optional nonce for freshness (max 512 bytes)
    #[prost(bytes = "vec", optional, tag = "2")]
    #[serde(with = "qos_hex::serde_option")]
    pub nonce: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
    /// Optional public key to include in attestation (max 1024 bytes)
    #[prost(bytes = "vec", optional, tag = "3")]
    #[serde(with = "qos_hex::serde_option")]
    pub public_key: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
}
/// Request for random bytes from the NSM.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetRandomRequest {}
/// Response type for the Nitro Secure Module API.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NsmResponse {
    /// The specific NSM response variant
    #[prost(oneof = "nsm_response::Response", tags = "1, 2, 3, 4, 5, 6, 7, 8")]
    pub response: ::core::option::Option<nsm_response::Response>,
}
/// Nested message and enum types in `NsmResponse`.
pub mod nsm_response {
    /// The specific NSM response variant
    #[derive(serde::Serialize, serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Response {
        /// Response describing a PCR
        #[prost(message, tag = "1")]
        DescribePcr(super::DescribePcrResponse),
        /// Response from extending a PCR
        #[prost(message, tag = "2")]
        ExtendPcr(super::ExtendPcrResponse),
        /// Response from locking a PCR
        #[prost(message, tag = "3")]
        LockPcr(super::LockPcrResponse),
        /// Response from locking PCRs
        #[prost(message, tag = "4")]
        LockPcrs(super::LockPcrsResponse),
        /// Response describing NSM capabilities
        #[prost(message, tag = "5")]
        DescribeNsm(super::DescribeNsmResponse),
        /// Response containing attestation document
        #[prost(message, tag = "6")]
        Attestation(super::AttestationResponse),
        /// Response containing random bytes
        #[prost(message, tag = "7")]
        GetRandom(super::GetRandomResponse),
        /// Error response
        #[prost(message, tag = "8")]
        Error(super::NsmErrorResponse),
    }
}
/// Response describing a PCR.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DescribePcrResponse {
    /// Whether the PCR is locked
    #[prost(bool, tag = "1")]
    pub lock: bool,
    /// Current PCR value
    #[prost(bytes = "vec", tag = "2")]
    #[serde(with = "qos_hex::serde")]
    pub data: ::prost::alloc::vec::Vec<u8>,
}
/// Response from extending a PCR.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ExtendPcrResponse {
    /// New PCR value after extension
    #[prost(bytes = "vec", tag = "1")]
    #[serde(with = "qos_hex::serde")]
    pub data: ::prost::alloc::vec::Vec<u8>,
}
/// Response from locking a PCR.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct LockPcrResponse {}
/// Response from locking PCRs.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct LockPcrsResponse {}
/// Response describing NSM capabilities.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DescribeNsmResponse {
    /// NSM major version number
    #[prost(uint32, tag = "1")]
    pub version_major: u32,
    /// NSM minor version number
    #[prost(uint32, tag = "2")]
    pub version_minor: u32,
    /// NSM patch version number
    #[prost(uint32, tag = "3")]
    pub version_patch: u32,
    /// Unique module identifier
    #[prost(string, tag = "4")]
    pub module_id: ::prost::alloc::string::String,
    /// Maximum number of PCRs supported
    #[prost(uint32, tag = "5")]
    pub max_pcrs: u32,
    /// Indices of currently locked PCRs (repeated instead of set for deterministic ordering)
    #[prost(uint32, repeated, tag = "6")]
    pub locked_pcrs: ::prost::alloc::vec::Vec<u32>,
    /// Hash digest algorithm used by the NSM
    #[prost(enumeration = "NsmDigest", tag = "7")]
    pub digest: i32,
}
/// Response containing an attestation document.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AttestationResponse {
    /// COSE Sign1 structure containing CBOR-encoded AttestationDocument
    #[prost(bytes = "vec", tag = "1")]
    #[serde(with = "qos_hex::serde")]
    pub document: ::prost::alloc::vec::Vec<u8>,
}
/// Response containing random bytes.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetRandomResponse {
    /// Random bytes from the NSM hardware RNG
    #[prost(bytes = "vec", tag = "1")]
    #[serde(with = "qos_hex::serde")]
    pub random: ::prost::alloc::vec::Vec<u8>,
}
/// Error response from NSM.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NsmErrorResponse {
    /// The error code indicating what went wrong
    #[prost(enumeration = "NsmErrorCode", tag = "1")]
    pub code: i32,
}
/// Possible error codes from the Nitro Secure Module API.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum NsmErrorCode {
    /// Success - no error occurred
    Success = 0,
    /// Invalid argument was provided
    InvalidArgument = 1,
    /// Invalid PCR index was specified
    InvalidIndex = 2,
    /// Response from NSM was invalid
    InvalidResponse = 3,
    /// Attempted to modify a read-only PCR index
    ReadOnlyIndex = 4,
    /// Operation is not valid in current state
    InvalidOperation = 5,
    /// Provided buffer was too small for the response
    BufferTooSmall = 6,
    /// Input data exceeded maximum allowed size
    InputTooLarge = 7,
    /// Internal NSM error occurred
    InternalError = 8,
}
impl NsmErrorCode {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            NsmErrorCode::Success => "NSM_ERROR_CODE_SUCCESS",
            NsmErrorCode::InvalidArgument => "NSM_ERROR_CODE_INVALID_ARGUMENT",
            NsmErrorCode::InvalidIndex => "NSM_ERROR_CODE_INVALID_INDEX",
            NsmErrorCode::InvalidResponse => "NSM_ERROR_CODE_INVALID_RESPONSE",
            NsmErrorCode::ReadOnlyIndex => "NSM_ERROR_CODE_READ_ONLY_INDEX",
            NsmErrorCode::InvalidOperation => "NSM_ERROR_CODE_INVALID_OPERATION",
            NsmErrorCode::BufferTooSmall => "NSM_ERROR_CODE_BUFFER_TOO_SMALL",
            NsmErrorCode::InputTooLarge => "NSM_ERROR_CODE_INPUT_TOO_LARGE",
            NsmErrorCode::InternalError => "NSM_ERROR_CODE_INTERNAL_ERROR",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "NSM_ERROR_CODE_SUCCESS" => Some(Self::Success),
            "NSM_ERROR_CODE_INVALID_ARGUMENT" => Some(Self::InvalidArgument),
            "NSM_ERROR_CODE_INVALID_INDEX" => Some(Self::InvalidIndex),
            "NSM_ERROR_CODE_INVALID_RESPONSE" => Some(Self::InvalidResponse),
            "NSM_ERROR_CODE_READ_ONLY_INDEX" => Some(Self::ReadOnlyIndex),
            "NSM_ERROR_CODE_INVALID_OPERATION" => Some(Self::InvalidOperation),
            "NSM_ERROR_CODE_BUFFER_TOO_SMALL" => Some(Self::BufferTooSmall),
            "NSM_ERROR_CODE_INPUT_TOO_LARGE" => Some(Self::InputTooLarge),
            "NSM_ERROR_CODE_INTERNAL_ERROR" => Some(Self::InternalError),
            _ => None,
        }
    }
}
/// Possible hash digests for the Nitro Secure Module API.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum NsmDigest {
    /// Unspecified digest type
    Unspecified = 0,
    /// SHA-256 digest (256 bits)
    Sha256 = 1,
    /// SHA-384 digest (384 bits)
    Sha384 = 2,
    /// SHA-512 digest (512 bits)
    Sha512 = 3,
}
impl NsmDigest {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            NsmDigest::Unspecified => "NSM_DIGEST_UNSPECIFIED",
            NsmDigest::Sha256 => "NSM_DIGEST_SHA256",
            NsmDigest::Sha384 => "NSM_DIGEST_SHA384",
            NsmDigest::Sha512 => "NSM_DIGEST_SHA512",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "NSM_DIGEST_UNSPECIFIED" => Some(Self::Unspecified),
            "NSM_DIGEST_SHA256" => Some(Self::Sha256),
            "NSM_DIGEST_SHA384" => Some(Self::Sha384),
            "NSM_DIGEST_SHA512" => Some(Self::Sha512),
            _ => None,
        }
    }
}
/// Protocol message - the main RPC type for client-enclave communication.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ProtocolMsg {
    /// The specific message variant
    #[prost(
        oneof = "protocol_msg::Msg",
        tags = "1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21"
    )]
    pub msg: ::core::option::Option<protocol_msg::Msg>,
}
/// Nested message and enum types in `ProtocolMsg`.
pub mod protocol_msg {
    /// The specific message variant
    #[derive(serde::Serialize, serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Msg {
        /// Error response from enclave
        #[prost(message, tag = "1")]
        ErrorResponse(super::ProtocolError),
        /// Request enclave status
        #[prost(message, tag = "2")]
        StatusRequest(super::StatusRequest),
        /// Enclave status response
        #[prost(message, tag = "3")]
        StatusResponse(super::StatusResponse),
        /// Request standard boot
        #[prost(message, tag = "4")]
        BootStandardRequest(super::BootStandardRequest),
        /// Standard boot response
        #[prost(message, tag = "5")]
        BootStandardResponse(super::BootStandardResponse),
        /// Request genesis boot
        #[prost(message, tag = "6")]
        BootGenesisRequest(super::BootGenesisRequest),
        /// Genesis boot response
        #[prost(message, tag = "7")]
        BootGenesisResponse(super::BootGenesisResponse),
        /// Request key forward boot
        #[prost(message, tag = "8")]
        BootKeyForwardRequest(super::BootKeyForwardRequest),
        /// Key forward boot response
        #[prost(message, tag = "9")]
        BootKeyForwardResponse(super::BootKeyForwardResponse),
        /// Post a Shamir share of the quorum key
        #[prost(message, tag = "10")]
        ProvisionRequest(super::ProvisionRequest),
        /// Provision response
        #[prost(message, tag = "11")]
        ProvisionResponse(super::ProvisionResponse),
        /// Request to proxy data to pivot
        #[prost(message, tag = "12")]
        ProxyRequest(super::ProxyRequest),
        /// Proxy response from pivot
        #[prost(message, tag = "13")]
        ProxyResponse(super::ProxyResponse),
        /// Request live attestation document
        #[prost(message, tag = "14")]
        LiveAttestationDocRequest(super::LiveAttestationDocRequest),
        /// Live attestation document response
        #[prost(message, tag = "15")]
        LiveAttestationDocResponse(super::LiveAttestationDocResponse),
        /// Request to export the quorum key
        #[prost(message, tag = "16")]
        ExportKeyRequest(super::ExportKeyRequest),
        /// Export key response
        #[prost(message, tag = "17")]
        ExportKeyResponse(super::ExportKeyResponse),
        /// Request to inject a quorum key
        #[prost(message, tag = "18")]
        InjectKeyRequest(super::InjectKeyRequest),
        /// Inject key response
        #[prost(message, tag = "19")]
        InjectKeyResponse(super::InjectKeyResponse),
        /// Request manifest envelope
        #[prost(message, tag = "20")]
        ManifestEnvelopeRequest(super::ManifestEnvelopeRequest),
        /// Manifest envelope response
        #[prost(message, tag = "21")]
        ManifestEnvelopeResponse(super::ManifestEnvelopeResponse),
    }
}
/// Request for enclave status.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StatusRequest {}
/// Response containing enclave status.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StatusResponse {
    /// Current protocol execution phase
    #[prost(enumeration = "ProtocolPhase", tag = "1")]
    pub phase: i32,
}
/// Request to boot the enclave in standard mode.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BootStandardRequest {
    /// Manifest envelope with approvals
    #[prost(message, optional, tag = "1")]
    pub manifest_envelope: ::core::option::Option<ManifestEnvelope>,
    /// Pivot binary bytes
    #[prost(bytes = "vec", tag = "2")]
    #[serde(with = "qos_hex::serde")]
    pub pivot: ::prost::alloc::vec::Vec<u8>,
}
/// Response from standard boot.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BootStandardResponse {
    /// NSM attestation response
    #[prost(message, optional, tag = "1")]
    pub nsm_response: ::core::option::Option<NsmResponse>,
}
/// Request to boot the enclave in genesis mode.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BootGenesisRequest {
    /// Genesis set configuration for key sharding
    #[prost(message, optional, tag = "1")]
    pub set: ::core::option::Option<GenesisSet>,
    /// Optional disaster recovery P256 public key (DER encoded)
    #[prost(bytes = "vec", optional, tag = "2")]
    #[serde(with = "qos_hex::serde_option")]
    pub dr_key: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
}
/// Response from genesis boot.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BootGenesisResponse {
    /// NSM attestation response
    #[prost(message, optional, tag = "1")]
    pub nsm_response: ::core::option::Option<NsmResponse>,
    /// Genesis ceremony output
    #[prost(message, optional, tag = "2")]
    pub genesis_output: ::core::option::Option<GenesisOutput>,
}
/// Request to boot the enclave in key forward mode.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BootKeyForwardRequest {
    /// Manifest envelope with approvals
    #[prost(message, optional, tag = "1")]
    pub manifest_envelope: ::core::option::Option<ManifestEnvelope>,
    /// Pivot binary bytes
    #[prost(bytes = "vec", tag = "2")]
    #[serde(with = "qos_hex::serde")]
    pub pivot: ::prost::alloc::vec::Vec<u8>,
}
/// Response from key forward boot.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BootKeyForwardResponse {
    /// NSM attestation response
    #[prost(message, optional, tag = "1")]
    pub nsm_response: ::core::option::Option<NsmResponse>,
}
/// Request to post a Shamir share of the quorum key.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ProvisionRequest {
    /// Quorum key share encrypted to the Ephemeral Key
    #[prost(bytes = "vec", tag = "1")]
    #[serde(with = "qos_hex::serde")]
    pub share: ::prost::alloc::vec::Vec<u8>,
    /// Approval of the manifest from a share set member
    #[prost(message, optional, tag = "2")]
    pub approval: ::core::option::Option<Approval>,
}
/// Response from posting a Shamir share.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ProvisionResponse {
    /// True if the quorum key was successfully reconstructed
    #[prost(bool, tag = "1")]
    pub reconstructed: bool,
}
/// Request to proxy data to the pivot application.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ProxyRequest {
    /// Data to forward to the pivot
    #[prost(bytes = "vec", tag = "1")]
    #[serde(with = "qos_hex::serde")]
    pub data: ::prost::alloc::vec::Vec<u8>,
}
/// Response from the pivot application.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ProxyResponse {
    /// Data returned from the pivot
    #[prost(bytes = "vec", tag = "1")]
    #[serde(with = "qos_hex::serde")]
    pub data: ::prost::alloc::vec::Vec<u8>,
}
/// Request for a live attestation document.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct LiveAttestationDocRequest {}
/// Response containing a live attestation document.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct LiveAttestationDocResponse {
    /// NSM attestation response
    #[prost(message, optional, tag = "1")]
    pub nsm_response: ::core::option::Option<NsmResponse>,
    /// Current manifest envelope (if available)
    #[prost(message, optional, tag = "2")]
    pub manifest_envelope: ::core::option::Option<ManifestEnvelope>,
}
/// Request to export the quorum key to another enclave.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ExportKeyRequest {
    /// Manifest envelope of the requesting enclave
    #[prost(message, optional, tag = "1")]
    pub manifest_envelope: ::core::option::Option<ManifestEnvelope>,
    /// COSE Sign1 attestation document from the requesting enclave
    #[prost(bytes = "vec", tag = "2")]
    #[serde(with = "qos_hex::serde")]
    pub cose_sign1_attestation_doc: ::prost::alloc::vec::Vec<u8>,
}
/// Response containing the exported quorum key.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ExportKeyResponse {
    /// Quorum key encrypted to the requesting enclave's Ephemeral Key
    #[prost(bytes = "vec", tag = "1")]
    #[serde(with = "qos_hex::serde")]
    pub encrypted_quorum_key: ::prost::alloc::vec::Vec<u8>,
    /// Signature over the encrypted quorum key
    #[prost(bytes = "vec", tag = "2")]
    #[serde(with = "qos_hex::serde")]
    pub signature: ::prost::alloc::vec::Vec<u8>,
}
/// Request to inject a quorum key into this enclave.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InjectKeyRequest {
    /// Quorum key encrypted to this enclave's Ephemeral Key
    #[prost(bytes = "vec", tag = "1")]
    #[serde(with = "qos_hex::serde")]
    pub encrypted_quorum_key: ::prost::alloc::vec::Vec<u8>,
    /// Signature over the encrypted quorum key
    #[prost(bytes = "vec", tag = "2")]
    #[serde(with = "qos_hex::serde")]
    pub signature: ::prost::alloc::vec::Vec<u8>,
}
/// Response from injecting a quorum key.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InjectKeyResponse {}
/// Request for the current manifest envelope.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ManifestEnvelopeRequest {}
/// Response containing the manifest envelope.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ManifestEnvelopeResponse {
    /// Current manifest envelope (if available)
    #[prost(message, optional, tag = "1")]
    pub manifest_envelope: ::core::option::Option<ManifestEnvelope>,
}
/// Protocol error with code and message.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ProtocolError {
    /// Error code indicating the type of error
    #[prost(enumeration = "ProtocolErrorCode", tag = "1")]
    pub code: i32,
    /// Human-readable error message with details interpolated
    #[prost(string, optional, tag = "2")]
    pub message: ::core::option::Option<::prost::alloc::string::String>,
}
/// Protocol execution phase.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum ProtocolPhase {
    /// Phase is not specified
    Unspecified = 0,
    /// Enclave encountered an unrecoverable error
    UnrecoverableError = 1,
    /// Enclave is waiting for boot instruction
    WaitingForBootInstruction = 2,
    /// Enclave has completed genesis boot
    GenesisBooted = 3,
    /// Enclave is waiting for quorum key shards
    WaitingForQuorumShards = 4,
    /// Quorum key has been provisioned
    QuorumKeyProvisioned = 5,
    /// Enclave is waiting for a forwarded key
    WaitingForForwardedKey = 6,
}
impl ProtocolPhase {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            ProtocolPhase::Unspecified => "PROTOCOL_PHASE_UNSPECIFIED",
            ProtocolPhase::UnrecoverableError => "PROTOCOL_PHASE_UNRECOVERABLE_ERROR",
            ProtocolPhase::WaitingForBootInstruction => {
                "PROTOCOL_PHASE_WAITING_FOR_BOOT_INSTRUCTION"
            }
            ProtocolPhase::GenesisBooted => "PROTOCOL_PHASE_GENESIS_BOOTED",
            ProtocolPhase::WaitingForQuorumShards => {
                "PROTOCOL_PHASE_WAITING_FOR_QUORUM_SHARDS"
            }
            ProtocolPhase::QuorumKeyProvisioned => {
                "PROTOCOL_PHASE_QUORUM_KEY_PROVISIONED"
            }
            ProtocolPhase::WaitingForForwardedKey => {
                "PROTOCOL_PHASE_WAITING_FOR_FORWARDED_KEY"
            }
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "PROTOCOL_PHASE_UNSPECIFIED" => Some(Self::Unspecified),
            "PROTOCOL_PHASE_UNRECOVERABLE_ERROR" => Some(Self::UnrecoverableError),
            "PROTOCOL_PHASE_WAITING_FOR_BOOT_INSTRUCTION" => {
                Some(Self::WaitingForBootInstruction)
            }
            "PROTOCOL_PHASE_GENESIS_BOOTED" => Some(Self::GenesisBooted),
            "PROTOCOL_PHASE_WAITING_FOR_QUORUM_SHARDS" => {
                Some(Self::WaitingForQuorumShards)
            }
            "PROTOCOL_PHASE_QUORUM_KEY_PROVISIONED" => Some(Self::QuorumKeyProvisioned),
            "PROTOCOL_PHASE_WAITING_FOR_FORWARDED_KEY" => {
                Some(Self::WaitingForForwardedKey)
            }
            _ => None,
        }
    }
}
/// Protocol error codes.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum ProtocolErrorCode {
    /// Unspecified error
    Unspecified = 0,
    /// Invalid share format or content
    InvalidShare = 1,
    /// Reconstruction failed: secret was empty
    ReconstructionErrorEmptySecret = 2,
    /// Reconstruction failed: public key mismatch
    ReconstructionErrorIncorrectPubKey = 3,
    /// I/O error occurred
    IoError = 4,
    /// Manifest approval signature is invalid
    InvalidManifestApproval = 5,
    /// Insufficient approvals for quorum
    NotEnoughApprovals = 6,
    /// No matching route for request
    NoMatchingRoute = 7,
    /// Pivot hash does not match manifest
    InvalidPivotHash = 8,
    /// Message exceeds maximum size
    OversizeMsg = 9,
    /// Message format is invalid
    InvalidMsg = 10,
    /// Enclave client error
    EnclaveClient = 11,
    /// Decryption operation failed
    DecryptionFailed = 12,
    /// Private key format is invalid
    InvalidPrivateKey = 13,
    /// Failed to parse value from string
    FailedToParseFromString = 14,
    /// Ephemeral key path is invalid
    BadEphemeralKeyPath = 15,
    /// Cannot modify static data after pivot started
    CannotModifyPostPivotStatic = 16,
    /// Failed to retrieve ephemeral key
    FailedToGetEphemeralKey = 17,
    /// Failed to store ephemeral key
    FailedToPutEphemeralKey = 18,
    /// Cannot rotate non-existent ephemeral key
    CannotRotateNonExistentEphemeralKey = 19,
    /// Cannot delete ephemeral key
    CannotDeleteEphemeralKey = 20,
    /// Failed to retrieve quorum key
    FailedToGetQuorumKey = 21,
    /// Failed to store quorum key
    FailedToPutQuorumKey = 22,
    /// Failed to retrieve manifest envelope
    FailedToGetManifestEnvelope = 23,
    /// Failed to store manifest envelope
    FailedToPutManifestEnvelope = 24,
    /// Failed to store pivot binary
    FailedToPutPivot = 25,
    /// App client receive timed out
    AppClientRecvTimeout = 26,
    /// App client receive was interrupted
    AppClientRecvInterrupted = 27,
    /// App client connection was closed
    AppClientRecvConnectionClosed = 28,
    /// App client failed to connect
    AppClientConnectError = 29,
    /// App client failed to send
    AppClientSendError = 30,
    /// General app client error
    AppClientError = 31,
    /// Payload exceeds size limit
    OversizedPayload = 32,
    /// Failed to deserialize protocol message
    ProtocolMsgDeserialization = 33,
    /// Share set approvals are invalid
    BadShareSetApprovals = 34,
    /// Could not verify approval signature
    CouldNotVerifyApproval = 35,
    /// Signer is not a share set member
    NotShareSetMember = 36,
    /// Signer is not a manifest set member
    NotManifestSetMember = 37,
    /// P256 cryptographic error
    P256Error = 38,
    /// Disaster recovery key is not valid P256
    InvalidP256DrKey = 39,
    /// Secret length is incorrect
    IncorrectSecretLen = 40,
    /// Attestation verification failed
    QosAttestError = 41,
    /// Quorum key does not match expected
    DifferentQuorumKey = 42,
    /// Manifest set does not match expected
    DifferentManifestSet = 43,
    /// Namespace name does not match expected
    DifferentNamespaceName = 44,
    /// Nonce is lower than current value
    LowNonce = 45,
    /// PCR0 does not match expected
    DifferentPcr0 = 46,
    /// PCR1 does not match expected
    DifferentPcr1 = 47,
    /// PCR2 does not match expected
    DifferentPcr2 = 48,
    /// PCR3 does not match expected
    DifferentPcr3 = 49,
    /// Ephemeral key is missing
    MissingEphemeralKey = 50,
    /// Ephemeral key is invalid
    InvalidEphemeralKey = 51,
    /// Signature over encrypted quorum key is invalid
    InvalidEncryptedQuorumKeySignature = 52,
    /// Encrypted quorum key has invalid length
    EncryptedQuorumKeyInvalidLen = 53,
    /// Quorum secret is invalid
    InvalidQuorumSecret = 54,
    /// Quorum key does not match expected public key
    WrongQuorumKey = 55,
    /// Invalid state transition attempted
    InvalidStateTransition = 56,
    /// Duplicate approval from same member
    DuplicateApproval = 57,
    /// Manifest does not match expected
    DifferentManifest = 58,
    /// QOS cryptographic operation failed
    QosCrypto = 59,
    /// Failed to expand connection pool
    PoolExpandError = 60,
}
impl ProtocolErrorCode {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            ProtocolErrorCode::Unspecified => "PROTOCOL_ERROR_CODE_UNSPECIFIED",
            ProtocolErrorCode::InvalidShare => "PROTOCOL_ERROR_CODE_INVALID_SHARE",
            ProtocolErrorCode::ReconstructionErrorEmptySecret => {
                "PROTOCOL_ERROR_CODE_RECONSTRUCTION_ERROR_EMPTY_SECRET"
            }
            ProtocolErrorCode::ReconstructionErrorIncorrectPubKey => {
                "PROTOCOL_ERROR_CODE_RECONSTRUCTION_ERROR_INCORRECT_PUB_KEY"
            }
            ProtocolErrorCode::IoError => "PROTOCOL_ERROR_CODE_IO_ERROR",
            ProtocolErrorCode::InvalidManifestApproval => {
                "PROTOCOL_ERROR_CODE_INVALID_MANIFEST_APPROVAL"
            }
            ProtocolErrorCode::NotEnoughApprovals => {
                "PROTOCOL_ERROR_CODE_NOT_ENOUGH_APPROVALS"
            }
            ProtocolErrorCode::NoMatchingRoute => "PROTOCOL_ERROR_CODE_NO_MATCHING_ROUTE",
            ProtocolErrorCode::InvalidPivotHash => {
                "PROTOCOL_ERROR_CODE_INVALID_PIVOT_HASH"
            }
            ProtocolErrorCode::OversizeMsg => "PROTOCOL_ERROR_CODE_OVERSIZE_MSG",
            ProtocolErrorCode::InvalidMsg => "PROTOCOL_ERROR_CODE_INVALID_MSG",
            ProtocolErrorCode::EnclaveClient => "PROTOCOL_ERROR_CODE_ENCLAVE_CLIENT",
            ProtocolErrorCode::DecryptionFailed => {
                "PROTOCOL_ERROR_CODE_DECRYPTION_FAILED"
            }
            ProtocolErrorCode::InvalidPrivateKey => {
                "PROTOCOL_ERROR_CODE_INVALID_PRIVATE_KEY"
            }
            ProtocolErrorCode::FailedToParseFromString => {
                "PROTOCOL_ERROR_CODE_FAILED_TO_PARSE_FROM_STRING"
            }
            ProtocolErrorCode::BadEphemeralKeyPath => {
                "PROTOCOL_ERROR_CODE_BAD_EPHEMERAL_KEY_PATH"
            }
            ProtocolErrorCode::CannotModifyPostPivotStatic => {
                "PROTOCOL_ERROR_CODE_CANNOT_MODIFY_POST_PIVOT_STATIC"
            }
            ProtocolErrorCode::FailedToGetEphemeralKey => {
                "PROTOCOL_ERROR_CODE_FAILED_TO_GET_EPHEMERAL_KEY"
            }
            ProtocolErrorCode::FailedToPutEphemeralKey => {
                "PROTOCOL_ERROR_CODE_FAILED_TO_PUT_EPHEMERAL_KEY"
            }
            ProtocolErrorCode::CannotRotateNonExistentEphemeralKey => {
                "PROTOCOL_ERROR_CODE_CANNOT_ROTATE_NON_EXISTENT_EPHEMERAL_KEY"
            }
            ProtocolErrorCode::CannotDeleteEphemeralKey => {
                "PROTOCOL_ERROR_CODE_CANNOT_DELETE_EPHEMERAL_KEY"
            }
            ProtocolErrorCode::FailedToGetQuorumKey => {
                "PROTOCOL_ERROR_CODE_FAILED_TO_GET_QUORUM_KEY"
            }
            ProtocolErrorCode::FailedToPutQuorumKey => {
                "PROTOCOL_ERROR_CODE_FAILED_TO_PUT_QUORUM_KEY"
            }
            ProtocolErrorCode::FailedToGetManifestEnvelope => {
                "PROTOCOL_ERROR_CODE_FAILED_TO_GET_MANIFEST_ENVELOPE"
            }
            ProtocolErrorCode::FailedToPutManifestEnvelope => {
                "PROTOCOL_ERROR_CODE_FAILED_TO_PUT_MANIFEST_ENVELOPE"
            }
            ProtocolErrorCode::FailedToPutPivot => {
                "PROTOCOL_ERROR_CODE_FAILED_TO_PUT_PIVOT"
            }
            ProtocolErrorCode::AppClientRecvTimeout => {
                "PROTOCOL_ERROR_CODE_APP_CLIENT_RECV_TIMEOUT"
            }
            ProtocolErrorCode::AppClientRecvInterrupted => {
                "PROTOCOL_ERROR_CODE_APP_CLIENT_RECV_INTERRUPTED"
            }
            ProtocolErrorCode::AppClientRecvConnectionClosed => {
                "PROTOCOL_ERROR_CODE_APP_CLIENT_RECV_CONNECTION_CLOSED"
            }
            ProtocolErrorCode::AppClientConnectError => {
                "PROTOCOL_ERROR_CODE_APP_CLIENT_CONNECT_ERROR"
            }
            ProtocolErrorCode::AppClientSendError => {
                "PROTOCOL_ERROR_CODE_APP_CLIENT_SEND_ERROR"
            }
            ProtocolErrorCode::AppClientError => "PROTOCOL_ERROR_CODE_APP_CLIENT_ERROR",
            ProtocolErrorCode::OversizedPayload => {
                "PROTOCOL_ERROR_CODE_OVERSIZED_PAYLOAD"
            }
            ProtocolErrorCode::ProtocolMsgDeserialization => {
                "PROTOCOL_ERROR_CODE_PROTOCOL_MSG_DESERIALIZATION"
            }
            ProtocolErrorCode::BadShareSetApprovals => {
                "PROTOCOL_ERROR_CODE_BAD_SHARE_SET_APPROVALS"
            }
            ProtocolErrorCode::CouldNotVerifyApproval => {
                "PROTOCOL_ERROR_CODE_COULD_NOT_VERIFY_APPROVAL"
            }
            ProtocolErrorCode::NotShareSetMember => {
                "PROTOCOL_ERROR_CODE_NOT_SHARE_SET_MEMBER"
            }
            ProtocolErrorCode::NotManifestSetMember => {
                "PROTOCOL_ERROR_CODE_NOT_MANIFEST_SET_MEMBER"
            }
            ProtocolErrorCode::P256Error => "PROTOCOL_ERROR_CODE_P256_ERROR",
            ProtocolErrorCode::InvalidP256DrKey => {
                "PROTOCOL_ERROR_CODE_INVALID_P256_DR_KEY"
            }
            ProtocolErrorCode::IncorrectSecretLen => {
                "PROTOCOL_ERROR_CODE_INCORRECT_SECRET_LEN"
            }
            ProtocolErrorCode::QosAttestError => "PROTOCOL_ERROR_CODE_QOS_ATTEST_ERROR",
            ProtocolErrorCode::DifferentQuorumKey => {
                "PROTOCOL_ERROR_CODE_DIFFERENT_QUORUM_KEY"
            }
            ProtocolErrorCode::DifferentManifestSet => {
                "PROTOCOL_ERROR_CODE_DIFFERENT_MANIFEST_SET"
            }
            ProtocolErrorCode::DifferentNamespaceName => {
                "PROTOCOL_ERROR_CODE_DIFFERENT_NAMESPACE_NAME"
            }
            ProtocolErrorCode::LowNonce => "PROTOCOL_ERROR_CODE_LOW_NONCE",
            ProtocolErrorCode::DifferentPcr0 => "PROTOCOL_ERROR_CODE_DIFFERENT_PCR0",
            ProtocolErrorCode::DifferentPcr1 => "PROTOCOL_ERROR_CODE_DIFFERENT_PCR1",
            ProtocolErrorCode::DifferentPcr2 => "PROTOCOL_ERROR_CODE_DIFFERENT_PCR2",
            ProtocolErrorCode::DifferentPcr3 => "PROTOCOL_ERROR_CODE_DIFFERENT_PCR3",
            ProtocolErrorCode::MissingEphemeralKey => {
                "PROTOCOL_ERROR_CODE_MISSING_EPHEMERAL_KEY"
            }
            ProtocolErrorCode::InvalidEphemeralKey => {
                "PROTOCOL_ERROR_CODE_INVALID_EPHEMERAL_KEY"
            }
            ProtocolErrorCode::InvalidEncryptedQuorumKeySignature => {
                "PROTOCOL_ERROR_CODE_INVALID_ENCRYPTED_QUORUM_KEY_SIGNATURE"
            }
            ProtocolErrorCode::EncryptedQuorumKeyInvalidLen => {
                "PROTOCOL_ERROR_CODE_ENCRYPTED_QUORUM_KEY_INVALID_LEN"
            }
            ProtocolErrorCode::InvalidQuorumSecret => {
                "PROTOCOL_ERROR_CODE_INVALID_QUORUM_SECRET"
            }
            ProtocolErrorCode::WrongQuorumKey => "PROTOCOL_ERROR_CODE_WRONG_QUORUM_KEY",
            ProtocolErrorCode::InvalidStateTransition => {
                "PROTOCOL_ERROR_CODE_INVALID_STATE_TRANSITION"
            }
            ProtocolErrorCode::DuplicateApproval => {
                "PROTOCOL_ERROR_CODE_DUPLICATE_APPROVAL"
            }
            ProtocolErrorCode::DifferentManifest => {
                "PROTOCOL_ERROR_CODE_DIFFERENT_MANIFEST"
            }
            ProtocolErrorCode::QosCrypto => "PROTOCOL_ERROR_CODE_QOS_CRYPTO",
            ProtocolErrorCode::PoolExpandError => "PROTOCOL_ERROR_CODE_POOL_EXPAND_ERROR",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "PROTOCOL_ERROR_CODE_UNSPECIFIED" => Some(Self::Unspecified),
            "PROTOCOL_ERROR_CODE_INVALID_SHARE" => Some(Self::InvalidShare),
            "PROTOCOL_ERROR_CODE_RECONSTRUCTION_ERROR_EMPTY_SECRET" => {
                Some(Self::ReconstructionErrorEmptySecret)
            }
            "PROTOCOL_ERROR_CODE_RECONSTRUCTION_ERROR_INCORRECT_PUB_KEY" => {
                Some(Self::ReconstructionErrorIncorrectPubKey)
            }
            "PROTOCOL_ERROR_CODE_IO_ERROR" => Some(Self::IoError),
            "PROTOCOL_ERROR_CODE_INVALID_MANIFEST_APPROVAL" => {
                Some(Self::InvalidManifestApproval)
            }
            "PROTOCOL_ERROR_CODE_NOT_ENOUGH_APPROVALS" => Some(Self::NotEnoughApprovals),
            "PROTOCOL_ERROR_CODE_NO_MATCHING_ROUTE" => Some(Self::NoMatchingRoute),
            "PROTOCOL_ERROR_CODE_INVALID_PIVOT_HASH" => Some(Self::InvalidPivotHash),
            "PROTOCOL_ERROR_CODE_OVERSIZE_MSG" => Some(Self::OversizeMsg),
            "PROTOCOL_ERROR_CODE_INVALID_MSG" => Some(Self::InvalidMsg),
            "PROTOCOL_ERROR_CODE_ENCLAVE_CLIENT" => Some(Self::EnclaveClient),
            "PROTOCOL_ERROR_CODE_DECRYPTION_FAILED" => Some(Self::DecryptionFailed),
            "PROTOCOL_ERROR_CODE_INVALID_PRIVATE_KEY" => Some(Self::InvalidPrivateKey),
            "PROTOCOL_ERROR_CODE_FAILED_TO_PARSE_FROM_STRING" => {
                Some(Self::FailedToParseFromString)
            }
            "PROTOCOL_ERROR_CODE_BAD_EPHEMERAL_KEY_PATH" => {
                Some(Self::BadEphemeralKeyPath)
            }
            "PROTOCOL_ERROR_CODE_CANNOT_MODIFY_POST_PIVOT_STATIC" => {
                Some(Self::CannotModifyPostPivotStatic)
            }
            "PROTOCOL_ERROR_CODE_FAILED_TO_GET_EPHEMERAL_KEY" => {
                Some(Self::FailedToGetEphemeralKey)
            }
            "PROTOCOL_ERROR_CODE_FAILED_TO_PUT_EPHEMERAL_KEY" => {
                Some(Self::FailedToPutEphemeralKey)
            }
            "PROTOCOL_ERROR_CODE_CANNOT_ROTATE_NON_EXISTENT_EPHEMERAL_KEY" => {
                Some(Self::CannotRotateNonExistentEphemeralKey)
            }
            "PROTOCOL_ERROR_CODE_CANNOT_DELETE_EPHEMERAL_KEY" => {
                Some(Self::CannotDeleteEphemeralKey)
            }
            "PROTOCOL_ERROR_CODE_FAILED_TO_GET_QUORUM_KEY" => {
                Some(Self::FailedToGetQuorumKey)
            }
            "PROTOCOL_ERROR_CODE_FAILED_TO_PUT_QUORUM_KEY" => {
                Some(Self::FailedToPutQuorumKey)
            }
            "PROTOCOL_ERROR_CODE_FAILED_TO_GET_MANIFEST_ENVELOPE" => {
                Some(Self::FailedToGetManifestEnvelope)
            }
            "PROTOCOL_ERROR_CODE_FAILED_TO_PUT_MANIFEST_ENVELOPE" => {
                Some(Self::FailedToPutManifestEnvelope)
            }
            "PROTOCOL_ERROR_CODE_FAILED_TO_PUT_PIVOT" => Some(Self::FailedToPutPivot),
            "PROTOCOL_ERROR_CODE_APP_CLIENT_RECV_TIMEOUT" => {
                Some(Self::AppClientRecvTimeout)
            }
            "PROTOCOL_ERROR_CODE_APP_CLIENT_RECV_INTERRUPTED" => {
                Some(Self::AppClientRecvInterrupted)
            }
            "PROTOCOL_ERROR_CODE_APP_CLIENT_RECV_CONNECTION_CLOSED" => {
                Some(Self::AppClientRecvConnectionClosed)
            }
            "PROTOCOL_ERROR_CODE_APP_CLIENT_CONNECT_ERROR" => {
                Some(Self::AppClientConnectError)
            }
            "PROTOCOL_ERROR_CODE_APP_CLIENT_SEND_ERROR" => Some(Self::AppClientSendError),
            "PROTOCOL_ERROR_CODE_APP_CLIENT_ERROR" => Some(Self::AppClientError),
            "PROTOCOL_ERROR_CODE_OVERSIZED_PAYLOAD" => Some(Self::OversizedPayload),
            "PROTOCOL_ERROR_CODE_PROTOCOL_MSG_DESERIALIZATION" => {
                Some(Self::ProtocolMsgDeserialization)
            }
            "PROTOCOL_ERROR_CODE_BAD_SHARE_SET_APPROVALS" => {
                Some(Self::BadShareSetApprovals)
            }
            "PROTOCOL_ERROR_CODE_COULD_NOT_VERIFY_APPROVAL" => {
                Some(Self::CouldNotVerifyApproval)
            }
            "PROTOCOL_ERROR_CODE_NOT_SHARE_SET_MEMBER" => Some(Self::NotShareSetMember),
            "PROTOCOL_ERROR_CODE_NOT_MANIFEST_SET_MEMBER" => {
                Some(Self::NotManifestSetMember)
            }
            "PROTOCOL_ERROR_CODE_P256_ERROR" => Some(Self::P256Error),
            "PROTOCOL_ERROR_CODE_INVALID_P256_DR_KEY" => Some(Self::InvalidP256DrKey),
            "PROTOCOL_ERROR_CODE_INCORRECT_SECRET_LEN" => Some(Self::IncorrectSecretLen),
            "PROTOCOL_ERROR_CODE_QOS_ATTEST_ERROR" => Some(Self::QosAttestError),
            "PROTOCOL_ERROR_CODE_DIFFERENT_QUORUM_KEY" => Some(Self::DifferentQuorumKey),
            "PROTOCOL_ERROR_CODE_DIFFERENT_MANIFEST_SET" => {
                Some(Self::DifferentManifestSet)
            }
            "PROTOCOL_ERROR_CODE_DIFFERENT_NAMESPACE_NAME" => {
                Some(Self::DifferentNamespaceName)
            }
            "PROTOCOL_ERROR_CODE_LOW_NONCE" => Some(Self::LowNonce),
            "PROTOCOL_ERROR_CODE_DIFFERENT_PCR0" => Some(Self::DifferentPcr0),
            "PROTOCOL_ERROR_CODE_DIFFERENT_PCR1" => Some(Self::DifferentPcr1),
            "PROTOCOL_ERROR_CODE_DIFFERENT_PCR2" => Some(Self::DifferentPcr2),
            "PROTOCOL_ERROR_CODE_DIFFERENT_PCR3" => Some(Self::DifferentPcr3),
            "PROTOCOL_ERROR_CODE_MISSING_EPHEMERAL_KEY" => {
                Some(Self::MissingEphemeralKey)
            }
            "PROTOCOL_ERROR_CODE_INVALID_EPHEMERAL_KEY" => {
                Some(Self::InvalidEphemeralKey)
            }
            "PROTOCOL_ERROR_CODE_INVALID_ENCRYPTED_QUORUM_KEY_SIGNATURE" => {
                Some(Self::InvalidEncryptedQuorumKeySignature)
            }
            "PROTOCOL_ERROR_CODE_ENCRYPTED_QUORUM_KEY_INVALID_LEN" => {
                Some(Self::EncryptedQuorumKeyInvalidLen)
            }
            "PROTOCOL_ERROR_CODE_INVALID_QUORUM_SECRET" => {
                Some(Self::InvalidQuorumSecret)
            }
            "PROTOCOL_ERROR_CODE_WRONG_QUORUM_KEY" => Some(Self::WrongQuorumKey),
            "PROTOCOL_ERROR_CODE_INVALID_STATE_TRANSITION" => {
                Some(Self::InvalidStateTransition)
            }
            "PROTOCOL_ERROR_CODE_DUPLICATE_APPROVAL" => Some(Self::DuplicateApproval),
            "PROTOCOL_ERROR_CODE_DIFFERENT_MANIFEST" => Some(Self::DifferentManifest),
            "PROTOCOL_ERROR_CODE_QOS_CRYPTO" => Some(Self::QosCrypto),
            "PROTOCOL_ERROR_CODE_POOL_EXPAND_ERROR" => Some(Self::PoolExpandError),
            _ => None,
        }
    }
}
