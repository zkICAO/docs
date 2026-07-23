# zkICAO docs

Protocol specification and design notes for zkICAO: zero-knowledge circuits and tooling for ICAO 9303 electronic identity documents (ePassports and national eID cards), universal across issuing states.

Rule: any change to a binding value, leaf format, salt convention or policy must update the matching document in the same pull request as the circuit change.

## Documents (landing in phase P1a)

| Document | Contents |
|---|---|
| architecture.md | circuit inventory, variant dimensions, verification models (off-chain, on-chain recursive) |
| binding.md | cross-circuit binding values, packing per hash length, invariants I1..I7 |
| profiles.md | document profiles (mrz-td3, mrz-td1, dg13-vn), field types and normalization rules |
| nullifier-policies.md | policy registry (doc-number, mrz-stable, national-id), guarantees and limits |
| registry.md | trust registry: leaf and tree specification, sources (ICAO Master List, national master lists, PKD) |
| threat-model.md | assumptions, known limitations, non-goals |

## License

MIT
