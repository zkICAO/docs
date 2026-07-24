# zkICAO docs

Protocol specification and design notes for zkICAO: zero-knowledge circuits and tooling for electronic identity documents. The first target is ICAO Doc 9303 (Machine Readable Travel Documents).

Status: no specification document has been published yet. This repository currently holds only this README. The documents listed below are the intended contents, not existing material.

This repository is the reference for values shared across repositories: binding values, leaf formats, salt conventions and nullifier policies. Implementations elsewhere follow it rather than defining their own.

Changing a shared value takes two steps, in this order: publish the revised specification here, then update the implementations against it, each referencing the specification commit it implements. A change that lands in an implementation before it is specified here has no reference to review against.

## Planned documents

| Document | Intended contents |
|---|---|
| architecture.md | circuit inventory, variant dimensions, verification models |
| binding.md | cross-circuit binding values, packing per hash length, invariants |
| profiles.md | document profiles, field types and normalization rules |
| nullifier-policies.md | policy registry, the uniqueness each policy provides, and what it does not |
| registry.md | trust registry: leaf and tree specification, and data sources |
| threat-model.md | assumptions, known limitations, non-goals |

## Trademarks and affiliation

zkICAO is an independent open source project, not affiliated with, endorsed by, or approved by the International Civil Aviation Organization (ICAO) or the United Nations. See [TRADEMARKS.md](https://github.com/zkICAO/circuits/blob/main/TRADEMARKS.md).

## License

MIT
