## Goal

Boot new QOS nodes without manually posting shards. Instead, a new QOS node should be able to provision a quorum key from another, already provisioned node. The new QOS nodes should be in the same namespace as the ones they are requesting the Quorum Key from.

## New terms

**New Node**: The un-provisioned node, requesting a quorum key.
**Original Node**: The fully provisioned node that the quorum key is requested from.
**Client**: An entity that can make arbitrary requests to QOS nodes. For the sake of having a concrete mental model in the below descriptions, we can think of the client as a script that takes as inputs a manifest and the IP address of the new node + old node, and makes the necessary request to complete key forwarding process.
**New Manifest**: The manifest used to boot the New Node.
**Local Manifest**: The manifest used to boot the Original Node. It is local relative to the Original Node.

## Other relevant terms

**Nonce**: A strictly monotonically increasing counter used to track the latest manifest of a Namespace. Concretely, anytime a new manifest is created for a Namespace, we expect it to have a Nonce 1 greater then the previous most recent manifest.

## Routine

The details for how QOS nodes communicate with each other can vary, but for the sake of this example we assume that all request will be made from a client and nodes do not communicate directly with each other.

1) The New Node gets a `BootKeyForwardingAttestationRequest` from Client.

    ```rust
    struct PreBootKeyForwardAttestationRequest {
      manifest_envelope: ManifestEnvelope
    }
    ```

2) The New Node processes the request by
    1) Check signatures over the manifest envelope.
    1) Generate an Ephemeral Key.
    1) Make an attestation request, placing the manifest hash in the `user_data` field and the Ephemeral Key public key in the `public_key` field.
    1) Return the COSE Sign1 encoded attestation document.

        ```rust
        struct PreBootKeyForwardAttestationResponse {
          cose_sign1_attestation_document: Vec<u8>
        }
        ```

3) The Original Node gets a `BootKeyForwardingRequest` from the the Client.

    ```rust
    struct BootKeyForwardRequest {
      manifest_envelope: ManifestEnvelope,
      cose_sign1_attestation_document: Vec<u8>
    }
    ```

4) The Original Node processes the request by
    1) Check the basic validity of the attestation doc (cert chain etc). Ensures that the attestation document is actually from an AWS controlled NSM module and was recent.
    1) Check the signatures over the New Manifest. Ensures that K Manifest Set Members approved the New Manifest.
    1) Check that the Quorum Key of the Local Manifest matches the Quorum Key of the New Manifest. This ensures the request is for the correct Quorum Key.
    1) Check that the Manifest Set of the New Manifest matches the Manifest Set of the Local Manifest. Ensures that the signatures are from a trusted Manifest Set. Note that there is still a vulnerability here if we have try to retire a Manifest Set because a critical threshold of it was compromised - that malicious Manifest Set could boot off of an Original Node - thus it's important to retire all Original Nodes ASAP that use compromised Manifest Sets.
    1) Check that the Namespace of the Local Manifest matches the namespace of the New Manifest. Namespaces are a social construct, but we only want to allow forwarding a Quorum Key to Nodes in the same Namespace to help ensure that the nonce is not abused.
    1) Check that the nonce of the New Manifest is greater then or equal to the nonce of the Local Manifest. If they have the same nonce, we check that the Local Manifest has the same hash as an extra measure. Note that while the nonce is verified programmatically in this routine, its maintenance relative to other manifests in the namespace is a social coordination problem and is meant to be solved by the Manifest Set Members approving the manifest. In other words, we rely on the Manifest Set Members to correctly increment the nonce when any change is made to the latest manifest for a namespace.
    1) Check that PCR0, PCR1, PCR2, and PCR3 in the New Manifest match the PCRs in the attestation document. This ensures the New Manifest was used against a Nitro enclave booted with the intended version of QOS. Note that we assume the values for PCR{0, 1 , 2} correspond to a desired version of QOS because the Manifest Set Members had K approvals.
    1) Check that PCR3 in the New Manifest is in the Local Manifests. PCR3 is the IAM role assigned to the EC2 host of the enclave. An IAM role contains an AWS organization's unique ID. By only using approved PCR3 values we ensure that we only ever send the Quorum Key to an enclave that is controlled by the operator, not an enclave that some malicious entity runs that otherwise configured identically to one of the operator's enclaves.
    1) Check that the PCR3 allowlist in the New Manifest is a sub set of the PCR3 allowlist in the Local Manifest. This is not strictly necessary, but since adding a value for PCR3 could lead to a non-operator controlled entity gaining access to a Quorum Key, we want to force human intervention (with standard boot) to add a new value to the allowlist.
    1) Return the Quorum Key encrypted to the New Node's Ephemeral Key extracted from the attestation document.

        ```rust
          struct BootKeyForwardResponse {
            encrypted_quorum_key: Vec<u8>
          }
        ```

5) The Client takes the encrypted Quorum Key and constructs.

    ```rust
      struct InjectBootKeyForwardRequest {
        encrypted_quorum_key: Vec<u8>
      }
    ```

6) The New Node processes the request by
    1) Decrypt the encrypted Quorum Key in the request with the Ephemeral Key.
    1) Check that the decrypted Quorum Key public key matches the one specified in the New Manifest.
    1) Writes the Quorum Key to file system, at which point QOS will automatically pivot to running the Pivot Binary.
    1) Return `InjectBootKeyForwardResponse { }` , an empty struct signify that it was successful.
