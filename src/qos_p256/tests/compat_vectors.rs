//! Byte-exact vectors pinning `qos_p256` key derivation, signatures and
//! encryption formats.
//!
//! Enclaves, clients and the SDKs exchange keys, signatures and ciphertexts
//! produced by this crate, so a dependency upgrade must not change a single
//! byte of output. These vectors were generated with p256 0.13, sha2 0.10,
//! hmac 0.12, hkdf 0.12 and aes-gcm 0.10 from a fixed master seed. If one of
//! these tests fails after an upgrade, the upgrade breaks interoperability:
//! do not regenerate the vectors.

use qos_p256::{
	AES_GCM_256_PATH, MASTER_SEED_LEN, P256_ENCRYPT_DERIVE_PATH,
	P256_SIGN_DERIVE_PATH, P256Pair, P256Public, derive_secret,
	encrypt::P256EncryptPublic,
};
use zeroize::Zeroizing;

const MESSAGE: &[u8] = b"qos_p256 compatibility vector";
const SEED: &str =
	"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const DERIVED_ENCRYPT: &str =
	"0087112241d8fb432464e36d7c218461a58bfe880d05a801b4248af5cdf9cbcf";
const DERIVED_SIGN: &str =
	"85dbbc5f768e18d03fdf4417bfbc48a7e7a3452f17f3915439cd75d6ff38a71e";
const DERIVED_AES_GCM: &str =
	"b4b64de4ed5e6fe74e0b1ef44ac39478a15743e334fb5752cf31b63bcedc6e5f";
const PUBLIC_KEY: &str = "046eae4d17a1a7aea6f2adc6baad7cba061d20e263aa27783c8d77af2af6301f30f493367756b8eb3141f87d5ac3c163c8eb3e116ebc2dd016dd3719f6cf09ea0b047516371d03733b46d880508616d359e38d86812d2c2a360bef997a9a7f88449a97ac341074043cdd3572cbc73cc2cee9338b294a32115413a054c6b8be6b133a";
const SIGNATURE: &str = "e02550bec15d71ed0cfcf5b754c70b176fc6dcc15dd473b8097867cbb5c223f71a6b2d6a0835119b0b489e3891952ae77dfb2410340942e2ac7a72eebafe7e35";
const ASYMMETRIC_ENVELOPE: &str = "6c5b9e8dc472bcce5ccfdd54041e7bbce75f2ca2c46069ab003ccc0028cf7cd4f2f2d18903fbf4f15a9f73647bf9cd6cc5172263738aebbaaf021ccdd8e4954f6889744121fdbdb4656b0d85352d000000b784a7c4708550201eff5c456f9706b62ed53d374c06df6c14242cf1c0901a1b5220bb5115017c1abc74ae46ad";
const SHARED_SECRET: &str =
	"82e645a583d838632bbee723b29ef59db7129a874fb4f359e8bd0923fc7c3b0c";
const SYMMETRIC_ENVELOPE: &str = "024631e549546fac848c4a932d000000068e5eb67a54a3ecbc4a6570367c473a47a9ef81c1a1e29437fb7c838bee5e3de5372e4506b60416286946142e";

fn seed() -> Zeroizing<[u8; MASTER_SEED_LEN]> {
	let mut seed = Zeroizing::new([0u8; MASTER_SEED_LEN]);
	qos_hex::decode_to_buf(SEED, &mut *seed).unwrap();
	seed
}

fn pair() -> P256Pair {
	P256Pair::from_master_seed(&seed()).unwrap()
}

fn hex(bytes: &[u8]) -> String {
	qos_hex::encode(bytes)
}

#[test]
fn derived_secrets_match() {
	let seed = seed();
	for (path, expected) in [
		(P256_ENCRYPT_DERIVE_PATH, DERIVED_ENCRYPT),
		(P256_SIGN_DERIVE_PATH, DERIVED_SIGN),
		(AES_GCM_256_PATH, DERIVED_AES_GCM),
	] {
		assert_eq!(hex(&derive_secret(&seed, path).unwrap()[..]), expected);
	}
}

#[test]
fn public_key_from_seed_matches() {
	assert_eq!(hex(&pair().public_key().to_bytes()), PUBLIC_KEY);
}

#[test]
fn signature_matches() {
	assert_eq!(hex(&pair().sign(MESSAGE).unwrap()), SIGNATURE);
}

#[test]
fn recorded_signature_verifies() {
	let public =
		P256Public::from_bytes(&qos_hex::decode(PUBLIC_KEY).unwrap()).unwrap();
	public.verify(MESSAGE, &qos_hex::decode(SIGNATURE).unwrap()).unwrap();
}

#[test]
fn recorded_asymmetric_envelope_decrypts() {
	let plaintext =
		pair().decrypt(&qos_hex::decode(ASYMMETRIC_ENVELOPE).unwrap()).unwrap();
	assert_eq!(&plaintext[..], MESSAGE);
}

#[test]
fn recorded_asymmetric_envelope_decrypts_from_shared_secret() {
	let public_key = qos_hex::decode(PUBLIC_KEY).unwrap();
	let receiver = P256EncryptPublic::from_bytes(&public_key[..65]).unwrap();
	let plaintext = receiver
		.decrypt_from_shared_secret(
			&qos_hex::decode(ASYMMETRIC_ENVELOPE).unwrap(),
			&qos_hex::decode(SHARED_SECRET).unwrap(),
		)
		.unwrap();
	assert_eq!(&plaintext[..], MESSAGE);
}

#[test]
fn recorded_symmetric_envelope_decrypts() {
	let plaintext = pair()
		.aes_gcm_256_decrypt(&qos_hex::decode(SYMMETRIC_ENVELOPE).unwrap())
		.unwrap();
	assert_eq!(&plaintext[..], MESSAGE);
}
