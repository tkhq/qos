//! Proto generation tool for QOS types.
//!
//! Usage:
//!   cd src/qos_proto/proto_gen && cargo run

use std::path::PathBuf;

/// Serde attribute for hex encoding bytes fields in JSON.
const HEX_SERDE: &str = "#[serde(with = \"qos_hex::serde\")]";

/// Serde attribute for hex encoding optional bytes fields in JSON.
const HEX_SERDE_OPTION: &str = "#[serde(with = \"qos_hex::serde_option\")]";

/// Non-optional bytes fields in the proto definitions.
const BYTES_FIELDS: &[&str] = &[
    // manifest.proto
    ".qos.v1.NitroConfig.pcr0",
    ".qos.v1.NitroConfig.pcr1",
    ".qos.v1.NitroConfig.pcr2",
    ".qos.v1.NitroConfig.pcr3",
    ".qos.v1.NitroConfig.aws_root_certificate",
    ".qos.v1.PivotConfig.hash",
    ".qos.v1.QuorumMember.pub_key",
    ".qos.v1.MemberPubKey.pub_key",
    ".qos.v1.Namespace.quorum_key",
    ".qos.v1.Approval.signature",
    // genesis.proto
    ".qos.v1.MemberShard.shard",
    ".qos.v1.GenesisMemberOutput.encrypted_quorum_key_share",
    ".qos.v1.GenesisMemberOutput.share_hash",
    ".qos.v1.GenesisOutput.quorum_key",
    ".qos.v1.GenesisOutput.quorum_key_hash",
    ".qos.v1.GenesisOutput.test_message_ciphertext",
    ".qos.v1.GenesisOutput.test_message_signature",
    ".qos.v1.GenesisOutput.test_message",
    // protocol.proto
    ".qos.v1.BootStandardRequest.pivot",
    ".qos.v1.BootKeyForwardRequest.pivot",
    ".qos.v1.ProvisionRequest.share",
    ".qos.v1.ProxyRequest.data",
    ".qos.v1.ProxyResponse.data",
    ".qos.v1.ExportKeyRequest.cose_sign1_attestation_doc",
    ".qos.v1.ExportKeyResponse.encrypted_quorum_key",
    ".qos.v1.ExportKeyResponse.signature",
    ".qos.v1.InjectKeyRequest.encrypted_quorum_key",
    ".qos.v1.InjectKeyRequest.signature",
    // nsm.proto
    ".qos.v1.ExtendPcrRequest.data",
    ".qos.v1.DescribePcrResponse.data",
    ".qos.v1.ExtendPcrResponse.data",
    ".qos.v1.AttestationResponse.document",
    ".qos.v1.GetRandomResponse.random",
];

/// Optional bytes fields in the proto definitions.
const OPTIONAL_BYTES_FIELDS: &[&str] = &[
    // genesis.proto
    ".qos.v1.GenesisOutput.dr_key_wrapped_quorum_key",
    // protocol.proto
    ".qos.v1.BootGenesisRequest.dr_key",
    // nsm.proto
    ".qos.v1.AttestationRequest.user_data",
    ".qos.v1.AttestationRequest.nonce",
    ".qos.v1.AttestationRequest.public_key",
];

fn main() {
    // Use protoc from protobuf-src for consistent versioning
    std::env::set_var("PROTOC", protobuf_src::protoc());

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let proto_dir = manifest_dir.join("../../../proto");
    let out_dir = manifest_dir.join("../src/gen");

    println!("Proto directory: {}", proto_dir.display());
    println!("Output directory: {}", out_dir.display());

    let mut config = tonic_build::configure()
        .out_dir(&out_dir)
        .type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]")
        .type_attribute(".", "#[serde(rename_all = \"camelCase\")]")
        .build_server(false)
        .build_client(false)
        .protoc_arg("--experimental_allow_proto3_optional");

    // Add hex serde attribute to all bytes fields
    for field in BYTES_FIELDS {
        config = config.field_attribute(field, HEX_SERDE);
    }

    // Add hex serde attribute to optional bytes fields
    for field in OPTIONAL_BYTES_FIELDS {
        config = config.field_attribute(field, HEX_SERDE_OPTION);
    }

    config
        .compile(
            &[
                proto_dir.join("qos/v1/manifest.proto"),
                proto_dir.join("qos/v1/protocol.proto"),
                proto_dir.join("qos/v1/genesis.proto"),
                proto_dir.join("qos/v1/nsm.proto"),
            ],
            &[&proto_dir],
        )
        .expect("Proto compilation failed");

    println!("Proto generation complete!");
    println!("Generated files in: {}", out_dir.display());
}
