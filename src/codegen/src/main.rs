//! This is a script for generating rust types from proto definitions.
//! Generated types are written to the `generated` crate.
//!
//! This build script is not part of the workspace because it needs to be
//! able to run even if the workspace cannot compile

const PROTO_INCLUDE_PATH: &str = "../proto";
const GEN_DIR: &str = "./generated/src/generated";
const INCLUDE_FILE: &str = "_include.rs";
const DESCRIPTOR_PATH: &str = "./generated/src/generated/descriptor.bin";

const SERDE_DERIVE: &str = "#[cfg_attr(feature = \"serde_derive\", derive(::serde::Serialize, ::serde::Deserialize), serde(rename_all = \"camelCase\"))]";
const SERDE_ENUM_DERIVE: &str =
	"#[cfg_attr(feature = \"serde_derive\", serde(untagged))]";
const BORSH_ENUM_DISC_ATTR: &str = "#[borsh(use_discriminant=true)]";
const TONIC_FEATURE_GATE: &str = "#[cfg(feature = \"tonic_types\")]";
const BORSH_DERIVE: &str =
	"#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]";

fn main() -> Result<(), Box<dyn std::error::Error>> {
	// Compile protoc from source so we get consistent versions
	//std::env::set_var("PROTOC", protobuf_src::protoc());

	tonic_build::configure()
		.out_dir(GEN_DIR)
		// JSON - Used for user requests -- TODO: needed?
		.type_attribute(".parser", SERDE_DERIVE)
		.enum_attribute(".", SERDE_ENUM_DERIVE)
		// BORSH - Used for QOS sha256 checks
		.type_attribute(".parser.ParsedTransactionPayload", BORSH_DERIVE)
		.enum_attribute(
			".parser.ParsedTransactionPayload",
			BORSH_ENUM_DISC_ATTR,
		)
		.type_attribute(".parser.Metadata", BORSH_DERIVE)
		.enum_attribute(".parser.Metadata", BORSH_ENUM_DISC_ATTR)
		.client_mod_attribute(".", TONIC_FEATURE_GATE)
		.server_mod_attribute(".", TONIC_FEATURE_GATE)
		.file_descriptor_set_path(DESCRIPTOR_PATH)
		.include_file(INCLUDE_FILE)
		.protoc_arg("--experimental_allow_proto3_optional")
		.compile(
			&[
				"../proto/health/rpc.proto",
				"../proto/grpc/health/v1/health.proto",
				"../proto/vendor/google/rpc/status.proto",
				"../proto/vendor/google/rpc/code.proto",
			],
			&[PROTO_INCLUDE_PATH],
		)?;

	Ok(())
}
