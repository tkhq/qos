#!/usr/bin/env python3
"""Generate the static mock NSM PKI fixtures.

DO NOT USE IN PRODUCTION - ONLY FOR TESTS.

Generates a P-384 certificate chain (root CA -> intermediate CA -> leaf)
that mirrors the shape of the AWS Nitro attestation PKI. `MockNsm` signs
mock attestation documents with the leaf key, and verifiers that trust
`MOCK_ROOT_CERT_DER` can validate those documents with the exact same code
path used against the real AWS Nitro root.

The validity window is intentionally huge (2020-01-01 through 2120-01-01)
so the chain validates both at `MOCK_SECONDS_SINCE_EPOCH` (the fixed mock
clock) and at wall-clock time (the `mock_realtime` feature).

Requires the `cryptography` package. Run from this directory:

    python3 generate.py
"""

import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

NOT_BEFORE = datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc)
NOT_AFTER = datetime.datetime(2120, 1, 1, tzinfo=datetime.timezone.utc)


def name(common_name: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "QOS Mock NSM"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )


def ca_key_usage() -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=True,
        crl_sign=True,
        encipher_only=False,
        decipher_only=False,
    )


def leaf_key_usage() -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )


def base_builder(
    subject: x509.Name, issuer: x509.Name, public_key
) -> x509.CertificateBuilder:
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
    )


def main() -> None:
    root_key = ec.generate_private_key(ec.SECP384R1())
    intermediate_key = ec.generate_private_key(ec.SECP384R1())
    leaf_key = ec.generate_private_key(ec.SECP384R1())

    root_name = name("QOS Mock NSM Root CA")
    intermediate_name = name("QOS Mock NSM Intermediate CA")
    leaf_name = name("mock-nsm.qos.test")

    root_cert = (
        base_builder(root_name, root_name, root_key.public_key())
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(ca_key_usage(), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()),
            critical=False,
        )
        .sign(root_key, hashes.SHA384())
    )

    intermediate_cert = (
        base_builder(intermediate_name, root_name, intermediate_key.public_key())
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(ca_key_usage(), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(intermediate_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),
            critical=False,
        )
        .sign(root_key, hashes.SHA384())
    )

    leaf_cert = (
        base_builder(leaf_name, intermediate_name, leaf_key.public_key())
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(leaf_key_usage(), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("mock-nsm.qos.test")]),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                intermediate_key.public_key()
            ),
            critical=False,
        )
        .sign(intermediate_key, hashes.SHA384())
    )

    for file_name, cert in [
        ("root.der", root_cert),
        ("intermediate.der", intermediate_cert),
        ("leaf.der", leaf_cert),
    ]:
        with open(file_name, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.DER))

    # The raw P-384 scalar, zero padded to 48 bytes, hex encoded.
    scalar = leaf_key.private_numbers().private_value
    with open("leaf_p384_secret.hex", "w") as f:
        f.write(f"{scalar:096x}\n")


if __name__ == "__main__":
    main()
