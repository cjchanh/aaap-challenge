# AAAP Architecture — v0.1

## Build path (producer side, private key lives only here)

```
governed campaign run (Builder Foundry)
        │  .builder-foundry/ contract, ledgers, evidence manifest,
        │  run_receipt.json (guard results, engine telemetry, stop reason)
        ▼
┌──────────────────────┐   copy + hash        ┌──────────────────────────┐
│  evidence_packet.py  │ ───────────────────► │ artifacts/ (raw bytes)   │
│       (builder)      │                      └──────────────────────────┘
│                      │   seal each source
│                      │ ───────────────────► chain.jsonl
│                      │                      one EVIDENCE_ENVELOPE v1.0
│                      │                      per source; envelope i seals
│                      │                      envelope i-1 (hash chain)
│                      │
│  ephemeral Ed25519   │   sign chain head ─► attestation.json
│  (in-memory only,    │   sign derived-map ─► manifest.json
│   destroyed at exit) │                      (report/replay/spec/verifier)
└──────────────────────┘
        │  derived layer (sealed by manifest, never self-asserted)
        ├──► report.md      human after-action summary
        ├──► replay.json    recomputation + run summary (scope stated)
        ├──► ENVELOPE.md    field spec: producer + recompute per field
        ├──► PACKET.md      what this is / is not
        └──► verify_packet.py  standalone verifier (own hash sealed)
        │
        ▼  final self-verification runs the SHIPPED verifier as a fresh
           process; build fails unless it exits 0
```

## Verify path (third party, packet + Python only)

```
verify_packet.py <packet>
        │
        1. structure: chain + attestation + manifest + artifacts/ present
        2. per envelope: receipt_hash recompute (v1.0 canonicalization)
        3. per envelope: chain_prev link to prior envelope
        4. per envelope: artifact copy hashes to sealed sha256
        5. completeness: artifacts/ == referenced set (nothing smuggled)
        6. attestation: Ed25519 over RECOMPUTED chain head
           ├── engine 1: python cryptography
           └── engine 2: openssl CLI (fail-closed on disagreement)
        7. manifest: every derived file hashes to its entry;
           signature over the digest map
        ▼
   exit 0 + verify.json (every check listed)   |   exit 1 + named broken check
```

## Trust anchors

- One ephemeral key signs exactly two things: the chain head and the
  derived-file digest map. It exists for the duration of one build.
- The verifier is shipped in-packet AND hash-pinned by the manifest, so it
  can be diffed against an independently published copy.
- Verification is recompute-only: the verifier reads nothing from the
  producer at run time and writes only verify.json.
- The only claims the packet makes about the world are the sealed bytes;
  meaning-level claims live in the report and are labeled as derived.
