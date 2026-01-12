//! Proto generation tool for QOS types.
//!
//! Usage:
//!   cd src/qos_proto/proto_gen && cargo run

use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let proto_dir = manifest_dir.join("../../../proto");
    let out_dir = manifest_dir.join("../src/gen");

    println!("Proto directory: {}", proto_dir.display());
    println!("Output directory: {}", out_dir.display());

    // Proto files to compile
    let proto_files = [
        "qos/v1/manifest.proto",
        "qos/v1/protocol.proto",
        "qos/v1/genesis.proto",
        "qos/v1/nsm.proto",
    ];

    // Check that all proto files exist
    for proto_file in &proto_files {
        let full_path = proto_dir.join(proto_file);
        if !full_path.exists() {
            panic!("Proto file not found: {}", full_path.display());
        }
    }

    // Use protox to compile protos (pure Rust, no protoc needed)
    let file_descriptor_set = protox::compile(&proto_files, &[proto_dir.clone()])
        .expect("Failed to compile protos with protox");

    // Configure prost-build
    let mut config = prost_build::Config::new();

    // Add serde derives for JSON compatibility
    config.type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]");
    config.type_attribute(".", "#[serde(rename_all = \"camelCase\")]");

    // Set output directory
    config.out_dir(&out_dir);

    // Generate Rust code from the file descriptor set
    config
        .compile_fds(file_descriptor_set)
        .expect("Failed to generate Rust code from protos");

    println!("Proto generation complete!");
    println!("Generated files in: {}", out_dir.display());
}
