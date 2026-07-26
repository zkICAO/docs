# Trust registry

## Status

Mode one is implemented. Mode two is not.

This document was checked against the circuits working tree at commit `ae0a9c8` and the prover repository at `204d352`. The tree is moving quickly, so treat every count and every measurement below as a snapshot rather than a standing fact, and re-check before relying on one.

`circuits/bin` holds ten circuit packages at that commit: two Passive Authentication variants (`sod/ecdsa_p256_sha256_ec512` and `sod/rsa2048_v15_sha256_ec512`), data group extraction, two attribute profiles, three predicates, one nullifier and one anchor. The workspace `Nargo.toml` lists `lib/anchor` and `bin/anchor/dsc_inclusion` among its members.

`circuits/lib/anchor/src/lib.nr` defines `prove_signer_is_trusted`, which derives a key hash, walks a Merkle path against a root and returns a `dsc_commitment`. `bin/anchor/dsc_inclusion/src/main.nr` wraps it, adds the scoping asserts and publishes the commitment. Both were committed in `613231b`, "feat: trust anchor by inclusion in a published set of signers". Running `nargo test` during this review passed the library's four tests and the circuit's three.

Both stale claims this section used to flag, a README saying no circuit existed and a toolchain note saying RSA was unimplemented, have since been corrected in the circuits repository.

Work on the chain mode was in the working tree, uncommitted, while this review ran: an `lib/x509` package, certificate fixtures in `lib/testdata`, a `commit::modulus_hash`, and a `prove_signer_is_certified` in `lib/anchor`. None of it is committed, none of it has a circuit package, and none of it is described below as existing. It is mentioned once, in the open questions, because it changes what the remaining gaps are.

Names, leaf layout, public input order and the choice of modes can still change.

## Why a Document Signer needs an anchor

`bin/sod/ecdsa_p256_sha256_ec512` proves three things, through `sod::link` and `sig::verify_ecdsa_p256`: the Security Object hashes to a digest, that digest is the messageDigest signed attribute located by `cms::message_digest_sha256`, and an ECDSA P-256 signature over the signed attributes verifies under a public key. `bin/sod/rsa2048_v15_sha256_ec512` proves the same chain with `rsa::verify_pkcs1_v15_sha256` in place of the curve check.

In both, the public key is a private input, and the circuit checks nothing about whose key it is. Anyone can generate a key pair, build a Security Object over data groups of their choosing, sign the attributes and produce a proof that verifies. The repository's own fixture generator does exactly this: `circuits/fixtures/generator` calls openssl to produce `dsc{index}.pem` and `dsc-rsa.pem`, signs synthetic Doc 9303 material with them, and the resulting documents pass both Passive Authentication variants. On its own, a Passive Authentication proof shows that a document is internally consistent and signed by some key. It does not show that a state issued it.

Neither variant publishes the key. `sod::outputs` publishes `dsc_commitment(pubkey_hash(pubkey_x, pubkey_y), dsc_salt)`. That output exists so a second proof can say something about the same key without revealing it, and the trust registry is what the second proof reads.

## The chain

A state runs a Country Signing Certification Authority. The CSCA certificate is self signed, so there is nothing above it to verify against and trusting it is a decision made outside any circuit. The CSCA signs Document Signer Certificates; that signature covers the DSC tbsCertificate, which carries the Document Signer public key in its subjectPublicKeyInfo. The Document Signer private key signs the CMS SignedData whose signed attributes carry the digest of the Security Object. The Security Object lists one hash per data group, and `lds::dg_entry_sha256` reads one entry out. A data group hashes to that value.

zkICAO covers the lower part of the chain today: signed attributes to Security Object to data group hash to data group content, plus membership of the signer key in a published set. The part it does not cover is the CSCA to the Document Signer, and that is the only part that connects the structure to a state without a list builder in the middle.

## Binding an anchor proof to a Passive Authentication proof

The two proofs are joined by the commitment. `commit::dsc_commitment` is `Poseidon2::hash([TAG_DSC, dsc_pubkey_hash, salt], 3)` and `commit::pubkey_hash` is `Poseidon2::hash([TAG_DSC_KEY, ...four packed field elements], 5)`. Two proofs publishing the same commitment therefore used the same key hash and the same salt, under collision resistance of Poseidon2.

A verifier checks the following per session. `verify_bundle` in `prover/src/verify.rs` implements this list, so an integration calls it rather than reimplementing the rules.

1. The Passive Authentication proof verifies against a verification key the policy accepts. `verify_bundle` rejects an unlisted key with `UntrustedVerificationKey` before it verifies anything, which is what stops an algorithm downgrade.
2. The anchor proof verifies against a verification key the policy accepts.
3. The `dsc_commitment` output of the anchor proof equals the `dsc_commitment` output of the Passive Authentication proof. `verify_bundle` reports `AnchorForAnotherSigner` when it does not.
4. Both proofs carry the same `domain` and the same `context`, and the `context` is the value the verifier issued for this session. Both circuits reject a zero `context` in circuit, with `sod: context must be set` and `anchor: context must be set`, and the anchor circuit additionally asserts `anchor: domain must be set`. `verify_bundle` rejects a zero context at the policy level and compares both values across every proof in the bundle.
5. The registry root in the anchor proof is a root the verifier published and has not retired. `Policy::require_anchor(registry_root)` sets both the requirement and the root, and a mismatch is `AnchorAgainstAnotherRegistry`. Note that the root is compared only when the policy names one: a `Policy` with `require_trust_anchor` set by hand and `registry_root` left `None` accepts an anchor proof against any root and merely reports which.

The salt rule is stated in the library and enforced nowhere. The comment above `dsc_commitment` in `lib/commit` gives the convention: a zero salt is the public registry case where the verifier compares the commitment against a precomputed table, and a random salt is required when an anchor circuit proves trust in zero knowledge. `dsc_commitment` itself does not reject zero, unlike `entropy_seed` ("commit: session salt must be non-zero") and `nullifier` ("commit: nullifier secret must be non-zero"), which both assert a non zero input. Neither Passive Authentication variant constrains `dsc_salt`, and `bin/anchor/dsc_inclusion` does not constrain `salt` either. With a zero or guessable salt an observer computes `dsc_commitment(pubkey_hash(k), 0)` for every published key and learns which signer produced the document, and so the issuing state and the issuing batch. Three things would close this: an assert in the anchor circuit, an assert in the Passive Authentication variants, and witness preparation that draws the salt fresh per session and uses the same value in both witnesses. None of the three exists. The prover repository has no witness preparation at all; its `src` holds `field.rs`, `layout.rs` and `verify.rs`.

## What the shipped inclusion circuit does

`bin/anchor/dsc_inclusion` takes 32 byte key coordinates, a salt, a leaf index and sixteen siblings as private inputs, and a registry root, a domain and a context as public inputs. It asserts the domain and context are non zero, derives `commit::pubkey_hash` over the coordinates, uses that hash directly as the Merkle leaf, walks the path with `commit::walk_path`, requires the result to equal the root ("anchor: signer key is not in the published set"), and returns `commit::dsc_commitment` over the key hash and the salt.

The leaf is the bare key hash. It carries no issuing state and no validity window, so the format proposed in the next section is a proposal and not a description of the circuit. Depth is fixed at sixteen and the coordinate width at 32 bytes, so the shipped circuit covers P-256 signers only, against a set of up to 65536 keys.

`prover/layout.manifest` records the public input order as `anchor_dsc_inclusion registry_root domain context return[0]`, generated from the compiled ABI and checked by the prover's tests, which is what stops the two repositories drifting apart silently.

## Proposed leaf and tree format

This section is a proposal. The shipped circuit does not implement it.

The registry is a full binary Merkle tree over Poseidon2, walked by `commit::walk_path`, with leaves built by `commit::set_entry`. Both functions exist and both are already used this way by `predicate::member`.

`set_entry` takes exactly four field elements and hashes `[TAG_SET_ENTRY, data[0], data[1], data[2], data[3]]` at width five. The four slots for a signer entry are proposed as follows. These slot names are descriptive, not identifiers in the code.

| Slot | Content |
|---|---|
| 0 | `commit::pubkey_hash` over the signer public key coordinates |
| 1 | the three letter issuing state code, packed by `normalize::pack_alpha3` |
| 2 | certificate validity start, as a YYYYMMDD integer |
| 3 | certificate validity end, as a YYYYMMDD integer |

Slot 1 uses the same packing the attribute circuits apply to `FIELD_ISSUING_STATE` and `FIELD_NATIONALITY`, so a future circuit could compare a signer's country against the document's without a second encoding. Slots 2 and 3 use the same integer date form that `mrz::birth_date_to_int` and `mrz::expiry_date_to_int` produce and `predicate::compare` consumes.

Internal nodes are `commit::hash_pair`, which is Poseidon2 at width two and deliberately untagged. Every tagged value in `lib/commit` is at least three wide, which is what stops a leaf being presented as an internal node.

`walk_path` is generic over depth `D`, asserts `D < 32` ("commit: path depth out of range"), and asserts the index is below `2^D` ("commit: leaf index out of range"). It takes one direction bit per level from the index: bit `l` of the index selects the pairing at level `l`, and a zero bit places the current node on the left. Siblings are ordered from the leaf upward, so `siblings[0]` is the sibling at leaf level. Unused slots are padded with the field element zero. A prover cannot occupy a padding slot, because they supply the key coordinates and the circuit derives the leaf itself, so using a padding slot means finding a key whose leaf derivation returns zero.

Depth is fixed at compile time because `D` is a generic constant, which makes it a variant dimension like the buffer sizes in the Passive Authentication circuits. A depth change is a new circuit and a new verification key, so pick depth with headroom rather than sizing it to the current snapshot. The shipped circuit picks sixteen.

Two things need stating before anyone builds this.

`pubkey_hash` cannot encode an RSA key, and `modulus_hash` is the helper that does. It calls an internal packing helper, `pack_pair`, whose signature takes two arrays of the same generic length and which asserts that the length is even ("commit: length must be even") and that half of it is at most 31 bytes ("commit: half does not fit a field element"). Elliptic curve coordinate pairs up to 62 bytes per coordinate fit, which covers P-256 at 32 bytes and P-384 and Brainpool P-384r1 at 48 bytes, all three of which `lib/sig` supports. An RSA modulus does not fit, and no leaf derivation for one exists in `lib/commit` at the committed state. `bin/sod/rsa2048_v15_sha256_ec512` uses `commit::modulus_hash`, which folds every limb and finishes with a three wide hash carrying the role tag and the limb count, so the value identifies the whole modulus and a narrower key cannot collide with a wider one padded with zeros. What is still missing is an anchor circuit that consumes it: `anchor/dsc_inclusion` takes 32 byte coordinates, so a registry of RSA signer keys has leaves it can build but no circuit to prove membership in.

The shipped `prove_signer_is_trusted` uses the bare `pubkey_hash` as the Merkle leaf rather than `set_entry`, so it carries no issuing state and no validity window. Moving to the format above is a change to the library, the circuit, the depth and the verification key.

## Root granularity, revocation and validity

The root is a public input, so the set it names is the anonymity set. A single root covering every accepted signer of every participating state hides the issuing state. A per state root reveals the state to the verifier before any predicate proof runs, which gives away exactly what the salted commitment was protecting. A verifier that wants to restrict which states it accepts should do that with `bin/predicate/member` over `FIELD_ISSUING_STATE` against a published country set, not by narrowing the registry root.

`walk_path` proves inclusion only. There is no non membership proof anywhere in `lib/commit`, so removing a compromised signer means republishing the root, and that invalidates every path anyone holds. Snapshots should carry an epoch identifier published next to the root. Each additional root a verifier accepts at once widens the window in which a removed signer is still accepted, which makes the accepted root set a policy decision with a stated cost.

Validity dates are not in the shipped leaf, so nothing in the circuit checks them. If slots 2 and 3 are added, they can be checked against a verifier supplied `current_yyyymmdd`, the same public input the attribute circuits already take for two digit year resolution. That would prove the certificate is valid at the time the verifier states. It would not prove the certificate was valid when the document was signed: `sod::link` reads only the messageDigest attribute through `cms::message_digest_sha256`, so no signing time is available in circuit.

## Mode one: inclusion against a published signer set

`bin/anchor/dsc_inclusion`, package `anchor_dsc_inclusion`, listed as `anchor/dsc-inclusion` in `circuits/README.md`. Implemented and committed.

| Input | Visibility | Meaning |
|---|---|---|
| `pubkey_x`, `pubkey_y`, 32 bytes each | private | the Document Signer public key |
| `salt` | private | must be identical to the Passive Authentication witness; nothing constrains it |
| `index`, `siblings: [Field; 16]` | private | position in the registry snapshot |
| `registry_root` | public | the snapshot the verifier accepts |
| `domain` | public | application scoping, asserted non zero |
| `context` | public | session scoping, asserted non zero |
| return value | public | the `dsc_commitment`, which must equal the Passive Authentication output |

What it assumes is the whole point of the mode: whoever built the tree verified each Document Signer Certificate against its CSCA, checked validity, and applied whatever revocation data the state publishes. The circuit proves membership in a list. It proves nothing about whether the list is correct, and the list builder is a trusted party that belongs in the threat model by name. The library's own header says the same.

The inclusion circuit walks a Merkle path and checks no signature, which is why it is one of the cheapest circuits in the repository. Opcode counts are in `architecture.md`, which is the only place they are recorded.

## Mode two: in circuit CSCA verification

`anchor/csca-chain` appears in the intended pipeline in `circuits/README.md`. No circuit package exists for it, so there is no verification key, no public input layout in `prover/layout.manifest`, and no measurement.

It would take the DSC tbsCertificate bytes, hash them, verify the CSCA signature over that hash under a CSCA public key, locate the subjectPublicKeyInfo inside the tbsCertificate, read the Document Signer key out under constraint, and return `dsc_commitment` over that key and the session salt.

This does not remove the trusted list. The CSCA key still has to be anchored, either by an inclusion proof against a master list root or as a public input naming a single CSCA the verifier accepts. What it does is move the list from the signer level to the country level, where the set is smaller and changes far less often, and it removes the need to trust whoever validated the Document Signer Certificates.

What already exists that it needs: `rsa::verify_pkcs1_v15_sha256` for a PKCS#1 v1.5 SHA-256 signature, `hash::sha256_bounded` for the certificate hash, `commit::walk_path` for the master list path, and `commit::dsc_commitment` for the output.

What is missing at the committed state.

Only one RSA shape is implemented. `lib/rsa` accepts PKCS#1 v1.5 over SHA-256 and only the exponent 65537, and nothing else; there is no PSS path and no other digest. The function is generic over limb count and modulus bits, but the only instantiation in the repository is `verify_pkcs1_v15_sha256::<18, 2048>` in `bin/sod/rsa2048_v15_sha256_ec512`. Nothing instantiates 4096 bits and nothing measures it.

Certificate parsing is minimal. Nothing in the repository walks a DER structure; a general decoder existed in `lib/tlv`, was used by no package, and was removed. Locating subjectPublicKeyInfo under constraint, rather than trusting a prover supplied offset, needs code that is not committed. The precedent to avoid is in `lib/lds`, whose own header says `dg_entry_sha256` checks the header at the offset it is given and nothing about how that offset was reached. The same weakness in a certificate parser is worse: bytes read as a public key from an attacker chosen offset would let a prover substitute a key, and "the signature covers the whole encoding" only narrows the choice to offsets inside issuer signed bytes rather than eliminating it.

Hashing is paid per buffer, not per document. `hash::sha256_bounded` takes a fixed size buffer, and `lib/sod` states that a circuit pays for the buffer rather than the actual length. A certificate buffer sized for real Document Signer Certificates is unlikely to fit inside the 512 byte eContent buffer the shipped variants use, and no measurement exists for a circuit that hashes one.

ECDSA signature normalization is not in the prover. The header of `lib/sig` states that the ECDSA backend rejects any signature whose s exceeds n/2 and aborts rather than returning false, while RFC 5280 and RFC 5480 place no such restriction, so roughly half of genuine ECDSA signatures need s replaced by n minus s before the witness is built. `fixtures/generator/src/ec.rs` does this with `normalize_s`, applied in `ec::sign_sha256` and covered by tests, which is why the generated fixtures verify at all. The prover repository does not do it, and it is the place the work belongs. The rule is specific to ECDSA; it does not apply to the RSA path.

Test material for the committed state is one sided. The fixture generator produces Document Signer key pairs and signed documents, and no X.509 certificate and no CSCA, so a chain circuit built against the committed fixtures would have nothing to run on.

## Choosing between the modes

| | Inclusion | CSCA chain |
|---|---|---|
| Trusted party | whoever built the signer list | whoever built the country list |
| Set size | one entry per Document Signer | one entry per CSCA |
| Circuit work | one key hash, one leaf hash, `D` Poseidon2 pairings | certificate hashing, a public key signature verification, DER parsing, plus an inclusion proof for the CSCA key |
| Built | yes, `bin/anchor/dsc_inclusion`, P-256 sized coordinates, depth sixteen | no circuit package |
| Measured | 340 ACIR opcodes at depth sixteen | nothing to measure |
| Update rate | every signer rotation | every CSCA rotation |
| Prover inputs | key, salt, path | key, salt, certificate bytes, CSCA key, CSCA signature, path |

The chain mode is more expensive, and the cost is dominated by the signature and by hashing the certificate buffer. How much more is not known here. The measured comparison the repository does contain points the other way from the usual assumption about RSA: RSA-2048 verification costs roughly a quarter of P-256 verification in these circuits. Opcode counts are in `architecture.md`, which is the only place they are recorded. The chain circuit is now measured at 6841 opcodes for RSA-2048 over a 512 byte certificate buffer. There is still no measurement at 4096 bits, so that cannot be extrapolated from it.

The default should be inclusion. The chain mode is for deployments that will not accept a list builder as a trusted party and can afford whatever it turns out to cost.

A third option: fold the anchor into the Passive Authentication circuit instead of composing with it. That removes the salt and the commitment equality check, which is the part of the composition an auditor has to reason about, at the cost of one circuit and one verification key per combination of algorithm, buffer size and registry depth rather than per algorithm and buffer size. The reason for splitting circuits is that the signature check dominates and everything downstream costs two or three orders of magnitude less. It argues for keeping the anchor separate: a registry depth change recompiles only the cheap circuit, and a deployment that runs no anchor simply omits the proof.

## Where the data comes from

The statements in this section come from outside the repository and nothing here verifies them.

The ICAO Public Key Directory is understood to publish master lists of country signing certificates, and Document Signer lists, to its participants. Access is arranged through participation rather than being open, so a deployment has to obtain it. Some states publish their own master lists directly, which is the fallback for states that are not in the directory and the cross check for those that are.

Documents themselves are a third source. Doc 9303 provides for the Document Signer Certificate to be carried in the certificates field of the Security Object's SignedData, so a deployment can collect signer certificates from documents it processes. That gives no trust on its own. A certificate taken from a document becomes evidence only once it chains to a CSCA the deployment already trusts, so this is useful for measuring the coverage of a master list, not as a source of trust.

The build pipeline below is not implemented. No registry tooling exists in this repository: the only Rust in `circuits` is the fixture generator, which builds synthetic documents and nothing else.

1. Fetch the master lists and signer lists.
2. Verify every Document Signer Certificate against its CSCA with a standard X.509 verifier outside the circuit, including validity dates and whatever revocation data the state publishes.
3. Drop entries whose key type the leaf derivation cannot encode, and record every drop. At the committed state that means everything except elliptic curve keys with coordinates of at most 62 bytes, and the shipped circuit narrows it further to 32 byte coordinates.
4. Derive the leaf per accepted entry, pad to `2^D` with zero, and compute the root with `hash_pair`. For the shipped circuit that is `pubkey_hash` at depth sixteen.
5. Publish the root, the epoch, the depth and the full leaf list.
6. Publish what was excluded and why.

Step five is a privacy requirement, not a convenience. A holder needs the whole set to build a path locally. If paths are served by an API keyed by signer, the operator of that API learns which signer produced the document, which is precisely what the salted commitment hides from the verifier.

## Coverage, and why the stage is optional

Not every state participates in the Public Key Directory. A document from a state that does not participate cannot be anchored from directory data, and if that state publishes nothing of its own, it cannot be anchored at all without a bilateral arrangement.

National identity cards are the harder case. A state's travel document PKI and its national identity card PKI are not necessarily the same, and card infrastructures are frequently not published anywhere. Doc 9303 defines the TD1 card layout, and this repository reads it: `mrz::td1_validate` and `bin/attributes/mrz_td1_sha256` exist and are tested. So zkICAO can parse a card and commit its fields while having no way at all to establish that the key which signed it belongs to a state.

That is why the anchor stage is optional and configurable. `circuits/README.md` marks it optional in the intended pipeline, and the prover repository makes it a policy flag: `Policy::require_anchor(registry_root)` turns it on, and a bundle without an anchor proof then fails with `NoTrustAnchorProof`. Three consequences follow.

A deployment chooses its mode, the roots it accepts and the issuing states it accepts at all. Those are configuration, not circuit constants, with the exception of the tree depth and the coordinate width, which are compiled in.

A verifier running without an anchor should be told plainly what it is getting: a proof that a document is internally consistent and was signed by a key about which the verifier knows nothing. `verify_bundle` returns `signer_registry_root: None` in that case, and its own comment says the same. That is a weaker statement than most people will assume from the phrase "verified passport".

A verifier accepting a registry that covers only some states will silently reject documents from the rest. That has to be a stated policy with a visible failure message, not a surprise at the point of use.

The registry is the part of zkICAO whose quality depends on data the project does not control. No amount of circuit work fixes a state that publishes nothing.

## Open questions

Nothing constrains the salt. `dsc_commitment` accepts zero, both Passive Authentication variants pass `dsc_salt` through untouched, and `bin/anchor/dsc_inclusion` passes `salt` through untouched. Until an assert lands in the circuits and witness preparation draws the value fresh per session, the hiding property the composition is built on rests on a convention in a comment.

The shipped leaf is a bare key hash, so the registry carries no issuing state and no validity window, and nothing in circuit checks either. Adding them changes the leaf derivation, the depth and the verification key.

Nothing binds the signer's country to the document's. A signer trusted for one state could, as far as any circuit here can tell, have signed a document claiming another. Checking that needs a value carried by both the anchor proof and an attribute or predicate proof, and no such binding is specified.

RSA signer keys have a leaf derivation but no circuit that consumes it. `commit::modulus_hash` folds every limb and identifies the whole modulus. The review that produced this document raised the right objection about an earlier form of it: a chain of two wide hashes produces values in exactly the shape of a Merkle internal node, which would break the rule that only nodes take that shape. The fold now ends with a three wide hash carrying the role tag and the limb count, which restores the rule. What remains missing is an inclusion circuit that takes a modulus rather than a coordinate pair.

Non membership would let a revoked signer be excluded without republishing a root that invalidates every path. Nothing in `lib/commit` supports it.

Tracing an entry back to the certificate it came from during an audit would want a serial number or a fingerprint in the leaf. `set_entry` takes exactly four field elements, so adding a fifth value means giving one up or nesting a hash inside a slot.

Chain mode work was in progress in the working tree during this review and is not described above as existing. Anyone picking this document up should re-read `lib/anchor`, `lib/x509` and `bin/anchor` before assuming the gaps listed here are still open.

## Affiliation

zkICAO is an independent open source project. It is not affiliated with, endorsed by or approved by ICAO, the United Nations, or any government or issuing authority. Reading a published master list does not create any relationship with its publisher.
