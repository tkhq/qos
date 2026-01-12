//! Proto generation tool for QOS types.
//!
//! Usage:
//!   cd src/qos_proto/proto_gen && cargo run

use std::path::PathBuf;

fn main() {
    // Use protoc from protobuf-src for consistent versioning (same as mono)
    std::env::set_var("PROTOC", protobuf_src::protoc());

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let proto_dir = manifest_dir.join("../../../proto");
    let out_dir = manifest_dir.join("../src/gen");

    println!("Proto directory: {}", proto_dir.display());
    println!("Output directory: {}", out_dir.display());

    tonic_build::configure()
        .out_dir(&out_dir)
        .type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]")
        .type_attribute(".", "#[serde(rename_all = \"camelCase\")]")
        .build_server(false)
        .build_client(false)
        .protoc_arg("--experimental_allow_proto3_optional")
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
