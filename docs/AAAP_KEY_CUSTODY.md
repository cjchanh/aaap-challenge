# AAAP Key Custody — Operational Claim and Limits

The production identity `aaap-id-2f28c662cb4b30c1` is reported by the operator
as stored in the macOS user Keychain under service `cds-aaap-identity`, account
`production`. The public key is safe to publish. The private-key storage claim
is not proven by an AAAP packet or signature.

## Current Stage 1 implementation

`keychain:production` invokes the macOS `security` CLI, retrieves the PEM into
the signing process, parses it as Ed25519, signs, and discards the in-process
object. Retrieval failure is fail-closed. The implementation does not write the
PEM to a filesystem path.

What this improves:

- no persistent raw-key file in the normal signing path;
- Keychain at-rest protection and configured access controls;
- removal of the retired Stage 0 file identity from current trust.

What it does not prove or prevent:

- a process already authorized by the unlocked user Keychain can retrieve or
  use the key;
- same-user malware, prompt spoofing, host compromise, process-memory capture,
  backup/snapshot history, or a signing-oracle relay may still defeat custody;
- a packet cannot distinguish Keychain signing from the same key used elsewhere;
- the statement that the production private key never existed as a raw file is
  an operational assertion, not a cryptographic fact.

## Stronger stages

- **Stage 2:** non-exportable hardware key with PIN/touch policy. This protects
  key material but still permits a signing-oracle attack while unlocked.
- **Stage 3:** audited HSM/quorum service and external transparency witness.

No custody stage proves world truth or signature time. It only changes who can
use the signing key and what evidence exists around that use.
