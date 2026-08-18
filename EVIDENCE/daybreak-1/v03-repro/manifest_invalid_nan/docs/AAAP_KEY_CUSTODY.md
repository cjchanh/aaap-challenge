# AAAP Key Custody Roadmap — Threat Model and Deployment Recommendation

Scope: the persistent Ed25519 signing identity (`aaap-id-*`) used for packet
seals and capture-time signatures. This is a roadmap document — only Stage 0
is implemented today, and it says so.

## Stages

### Stage 0 — Permission-enforced file (CURRENT)

`~/.config/cds/aaap-identity/aaap-signing-key.pem`, 0600, loader refuses
looser permissions (tested). Private key read into memory only during runs.

- Catches: accidental leak via group/world read, careless copies.
- Does not catch: same-user malware reading the file, disk imaging,
  backup exfiltration. Any code running as this user can sign.

### Stage 1 — macOS Keychain (recommended next)

Key stored as a Keychain item (no ACL bypass prompt-free access for
non-interactive agents without explicit provisioning); signing via
`security` CLI retrieval or a small helper that requests the key and signs
in-process without ever exposing PEM bytes.

- Catches: same-user malware WITHOUT user interaction (Keyguard prompt /
  access ACL), opportunistic backup scraping (key never on disk raw).
- Does not catch: user-approved exfiltration, compromised host with
  keychain autorization, malware that induces the user to click Allow.
- Cost: macOS-only; CI/automation needs a provisioning profile or a
  dedicated interactive unlock policy. Cross-platform story splits.

### Stage 2 — Hardware key (YubiKey-class, OpenPGP/PIV with Ed25519)

Private key generated ON the device, never exportable; every signature is a
physical-token act. Ed25519 support exists on current YubiKey firmware via
the OpenPGP application; signing goes through gpg or a PIV session.

- Catches: ALL software exfiltration of the key material — the key cannot
  leave the token. A signing oracle still exists if the token is plugged in
  and unlocked, so PIN/touch policy matters.
- Does not catch: an attacker who possesses the unlocked token, or a
  compromised host that relays signing requests (the oracle problem).
- Cost: one signature = one token interaction policy; batch packet builds
  need a deliberate unlock window; token loss requires a pre-registered
  backup/rotation path.

### Stage 3 — HSM / Enclave (organizational)

Cloud HSM or on-prem HSM with quorum key custody; macOS Secure Enclave is
NOT an Ed25519 target (it is P-256-centric) — an enclave path means
switching or dual algorithms, which is a schema change, not a drop-in.

- Catches: single-actor key use without quorum; audit-logged signing.
- Cost: infrastructure, availability, and a key-ceremony process.

## Threat-model summary

| Adversary | S0 file | S1 Keychain | S2 hardware | S3 HSM |
|---|---|---|---|---|
| Accidental permission leak | stopped | n/a | n/a | n/a |
| Same-user malware, no interaction | NOT stopped | stopped (ACL) | stopped | stopped |
| User-prompted approval attack | NOT stopped | partial | stopped (touch/PIN) | quorum-gated |
| Stolen laptop powered off | disk image exposes key | Keychain-at-rest protection | useless without PIN/token PIN | useless |
| Signing-oracle relay from compromised host | exposed | exposed | policy-dependent | audit + quorum |
| Physical token theft | n/a | n/a | PIN + touch policy | n/a |

## Deployment recommendation

- **Now (Stage 0)**: acceptable for demos and challenge artifacts because
  the demo threat model assumes no targeted same-user compromise; keep the
  0600 enforcement and the refusal-to-sign-loose-keys behavior.
- **At public launch (Stage 1)**: move to Keychain before publishing the
  production identity anchor; publish the anchor AFTER migration so the
  public identity never existed as a raw file.
- **Before accepting third-party evidence (Stage 2)**: hardware key for the
  signing identity; this is the line where "we assert our packets" becomes
  "an attacker must physically possess our token to forge our identity."
- Stage 3 is organizational future work; do not block public launch on it.

Residual truth: no custody stage makes signing proofs of world-truth. The
key signs records; it does not sign reality.
