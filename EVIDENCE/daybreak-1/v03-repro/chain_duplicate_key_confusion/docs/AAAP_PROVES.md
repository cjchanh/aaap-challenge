# What an AAAP Packet Proves — and Does Not

Written for a skeptical reviewer. If a claim is not on the left side, the
packet does not make it.

## Proves (verification passing establishes)

1. **Record integrity.** Every sealed byte of the run record — campaign
   contract, ledgers, evidence manifest, run receipt, evidence artifacts —
   is byte-identical to what was sealed at build time, or verification
   fails and names the broken check.
2. **Ordering integrity.** The envelope sequence was not reordered, and no
   entry was inserted or deleted anywhere in the chain, including the tail.
3. **Derived-layer integrity.** The human-readable report, the envelope
   spec, this README, and the verifier itself cannot be edited after build
   without breaking the manifest seal.
4. **Signature validity.** An Ed25519 private key that existed at build
   time signed exactly this chain head and this derived-file map. Verified
   by two independent implementations when both are available.
5. **Verifier identity.** The verifier you run is the verifier that was
   sealed (hash-pinned in the manifest), so its PASS is reproducible.
6. **What the governed layer recorded.** Which steps ran, which guard
   checks failed, what was refused, what evidence was drift-checked — as
   recorded at capture time by the governance rails, not reconstructed
   later.

## Does not prove

1. **Authorship / identity.** The signing key is ephemeral and in-memory.
   It proves a build-time key existed, not which operator or machine ran it.
2. **Truth of the world.** If the governed run recorded a false statement
   at capture time, sealing preserves the false statement. The packet is a
   flight data recorder, not a lie detector — catch-at-capture is the
   governance layer's job upstream.
3. **Immunity to full re-forge.** Anyone can build a new packet with a new
   key. Detecting that requires comparing chain head + pubkey against an
   out-of-band published copy — which the demo package does.
4. **Time.** Timestamps are producer-claimed ordering hints, never attested.
5. **Product quality.** Guard green/red is structural completeness. A
   packet can verify perfectly around a run that honestly recorded failure —
   the demo packet does exactly that.
6. **Model behavior.** Nothing here replays or attests the model's internal
   reasoning; verification is evidence-level recompute, not model replay.

## Why the split matters

Agent vendors ask you to trust summaries. AAAP removes the summary from the
trust path: the record verifies itself, states its boundaries in its own
sealed files, and fails loudly the moment any byte moves. The question a
reviewer gets to ask changes from "do we believe your write-up?" to "does
the packet verify?" — a question a machine answers in seconds, identically,
everywhere.
