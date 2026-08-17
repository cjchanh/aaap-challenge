# What an AAAP Packet Proves — and Does Not

These claims apply to an AAAP v0.4 packet that passes the hardened verifier.
Identity claims additionally require an exact head/pubkey pair obtained through
a trusted channel, or two independently obtained, byte-identical anchor files
whose selected identity is active.

## Proves

1. **Byte integrity for sealed payloads.** Every artifact file and every
   derived file named by the v2 manifest has the signed SHA-256 value.
2. **Canonical chain integrity.** Each parsed envelope has the signed canonical
   meaning, links to its predecessor, and ends at the attested head. JSON
   whitespace is not sealed; duplicate keys and non-finite numbers are rejected.
3. **Ordering integrity.** Envelope insertion, deletion, reordering, and tail
   truncation change the attested head or break a link.
4. **Authenticated verification policy.** The v2 manifest signature covers the
   schema, complete derived-file allowlist, key model, operator id, public key,
   and the entire live-ledger verification policy, including an explicit null
   when no live ledger exists.
5. **Signature validity.** The key matching the packet public key signed the
   attested chain head, manifest control body, and each present live signature.
   `verify.json` names the engine set that verified every checked signature.
6. **Exact packet identity when anchored.** A paired expected head and public
   key select this packet. Registry mode additionally rejects disagreement,
   revoked identities, duplicate identities, and validity-window violations
   present in the supplied registry bytes.

## Does not prove

1. **World truth or product quality.** A signed false record remains false.
2. **When a signature was made.** Per-entry signatures bind index and entry
   hash. They are consistent with the documented capture path but cannot
   cryptographically distinguish immediate signing from later signing by the
   same key holder.
3. **Key custody.** A signature proves key use, not whether the key lived in a
   Keychain, file, hardware token, or hostile signing oracle.
4. **Operator identity by itself.** The operator label is signed by the key;
   ownership of that key is an external anchor-publication trust decision.
5. **Immunity to a full re-forge.** A fresh key can produce a self-consistent
   packet. Only a trusted exact anchor detects substitution.
6. **A benign verifier or host.** Running shipped Python executes producer code.
   Audit it or use a disposable least-privilege environment. A subverted Python,
   crypto library, OpenSSL binary, kernel, or filesystem can lie.
7. **A continuously immutable directory.** Verification assumes the packet
   directory is stable for the verification call. Preserve the commit/archive
   hash and reverify before relying on later reads.
8. **Independent origin from the current mirrors.** `cjchanh/aaap-challenge`
   and `cjchanh/aaap-anchors` are separate Git repositories under one GitHub
   account. They provide two histories, not independent account custody.
9. **Registry freshness.** Two byte-identical old registries can agree while
   omitting a later revocation. The verifier has no trusted clocked update
   channel; reviewers must establish registry freshness out of band.
10. **Availability under hostile resource use.** The verifier streams artifact
    hashing but does not promise a packet-size or CPU bound. Sandbox untrusted
    verification with OS resource limits.

AAAP replaces an unauditable summary with a bounded cryptographic statement.
It does not remove the need to trust acquisition, verifier code, key custody,
or the system that recorded the events.
