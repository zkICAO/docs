# Binding values and invariants

A relying party receives several zkICAO proofs, not one. Each proof is sound on its own and says nothing about the others. What makes a bundle describe a single document is a set of derived values that appear as public inputs in more than one proof, plus a verifier that requires them to be equal.

This document specifies those values. Every formula here is implemented once, in `/Users/wstran/Desktop/zkICAO/circuits/lib/commit/src/lib.nr`. No circuit re-derives them. The equalities a verifier enforces are implemented once, in `/Users/wstran/Desktop/zkICAO/prover/src/verify.rs`, over the public input positions declared in `/Users/wstran/Desktop/zkICAO/prover/src/layout.rs` and pinned by `/Users/wstran/Desktop/zkICAO/prover/layout.manifest`.

zkICAO is an independent project. It is not affiliated with or endorsed by ICAO or any government.

## 1. The hash and the tagging rule

Every derived value, apart from the two packing helpers in sections 7.1 and 7.2, is `Poseidon2::hash(inputs, n)` from the `poseidon` library, where `n` is the number of field elements in `inputs`. Every hashed value except one begins with a role tag: a small constant that is the first element of the input array.

The rule is that a value produced for one role must not be usable as a value of another role. Two things enforce it together.

The tag distinguishes values of the same width. `commitment` and `secret_binding` are both three wide; they differ because one starts with 6 and the other with 12.

The width distinguishes tagged values from Merkle internal nodes. Every tagged value is three elements or more. The internal node hash is exactly two. See section 3.

No tag is zero. The tags in use are 1 through 12, contiguous, each used by exactly one function.

## 2. Role tag table

| Constant | Value | Function | Total width | Domain in the hash |
| --- | --- | --- | --- | --- |
| `TAG_ECONTENT` | 1 | `econtent_binding` | 4 | yes |
| `TAG_DG` | 2 | `dg_binding` | 4 | yes |
| `TAG_DSC` | 3 | `dsc_commitment` | 3 | no |
| `TAG_LEAF` | 4 | `leaf` | 8 | no (inherited) |
| `TAG_ENTROPY` | 5 | `entropy_seed` | 5 | yes |
| `TAG_COMMITMENT` | 6 | `commitment` | 3 | yes |
| `TAG_NULLIFIER` | 7 | `nullifier` | 8 | yes |
| `TAG_FIELD_ENTROPY` | 8 | `field_entropy` | 3 | no (inherited) |
| `TAG_DSC_KEY` | 9 | `pubkey_hash` | 5 | no |
| `TAG_SET_ENTRY` | 10 | `set_entry` | 5 | no |
| `TAG_DOCUMENT_SECRET` | 11 | `document_secret` | 5 | no |
| `TAG_SECRET_BINDING` | 12 | `secret_binding` | 3 | yes |

"Inherited" means the value itself does not hash `domain`, but it is only ever reachable through a value that does. A leaf carries per field entropy derived from `entropy_seed`, which hashes `domain`, and the root of the leaves is consumed by `commitment`, which hashes `domain` again.

## 3. Why Merkle internal nodes are the one untagged two input hash

`hash_pair(left, right) = Poseidon2::hash([left, right], 2)`.

A Merkle node is untagged on purpose. Tagging it would buy nothing, because both of its inputs are already outputs of tagged hashes or of the same two input hash, and it would cost an extra field element at every level of every tree. What replaces the tag is arity. A path walk only ever calls the two input hash, and there is no tagged value in the library that is two wide, so no leaf, no seed, no commitment and no set entry can be presented to a verifier as an internal node, and no internal node can be presented as any of them. The invariant that keeps this true is that every tagged constructor stays at three inputs or more; adding a two input tagged value would break it.

`root16(leaves)` folds sixteen leaves through four levels of the same two input hash. `walk_path(leaf_value, index, siblings)` walks those levels in reverse, is generic over depth, and asserts `D < 32` and `index < 2^D`. It is used for the document tree in `lib/predicate::open`, for the sets a verifier publishes in `lib/predicate::member`, and for the signer registry in `lib/anchor::prove_signer_is_trusted`. A separate `leaf_to_root16` was a hand unrolled copy of `walk_path` at depth four and was removed once a test showed the two agreed for every index. Both take one direction bit per level out of `index`, so a sibling cannot be applied on the wrong side, and a path proved from the wrong position produces a different root. `merkle_roundtrip_all_indices` in `lib/commit` checks `root16` and `walk_path` agree for all sixteen indices.

## 4. The domain rule

`domain` is the application scope. It is a public input of every circuit and it is hashed into the values a verifier stores or compares across sessions, so the same document produces different values for different applications and two applications cannot correlate their records by comparing them.

`domain` is hashed into: `econtent_binding`, `dg_binding`, `secret_binding`, `entropy_seed`, `commitment`, `nullifier`.

`domain` is not hashed into: `dsc_commitment`, `pubkey_hash`, `document_secret`, `set_entry`, `field_entropy`, `leaf`, `hash_pair`.

The library header states the rule as "`domain` enters every value a verifier stores or compares across sessions". `dsc_commitment` is the exception to that sentence and the exception is deliberate. A verifier compares it against a Document Signer registry, and a registry that had to be recomputed per application would be useless. Hiding there is carried by `dsc_salt` instead of by `domain`. The test `outputs_change_with_the_domain` in `lib/sod` pins this: it asserts the econtent binding and the secret binding differ between two domains and that the DSC commitment is the same.

`pubkey_hash` and `document_secret` are inputs to domain scoped values, never published themselves. `field_entropy` and `leaf` inherit scope as described in section 2. `set_entry` is built by the verifier, not by the document holder.

## 5. The context rule

`context` is the session scope: a freshness value the relying party issues for one exchange. It is a public input of every circuit and it is hashed into nothing.

That is the whole point. If `context` entered a derived value, that value would change every session, and the equalities in section 9 (which compare values produced by different proofs, potentially cached or produced at different moments) would have nothing stable to compare. Session scoping is achieved by requiring the public input to match the value the verifier issued, not by mixing it into the algebra.

Because it is hashed into nothing, `context` has to be read by an explicit constraint or it would be an ABI entry the circuit never touches. Every binary asserts `context != 0`:

- `bin/sod/ecdsa_p256_sha256_ec512/src/main.nr`: `"sod: context must be set"`
- `bin/dg_extract/sha256_ec512/src/main.nr`: `"dg_extract: context must be set"`
- `bin/attributes/mrz_td3_sha256/src/main.nr` and `bin/attributes/mrz_td1_sha256/src/main.nr`: `"attributes: context must be set"`
- `bin/predicate/compare`, `bin/predicate/member`, `bin/predicate/reveal`: `"predicate: context must be set"`
- `bin/nullifier/document_number/src/main.nr`: `"nullifier: context must be set"`
- `bin/anchor/dsc_inclusion/src/main.nr`: `"anchor: context must be set"`
- `bin/registration/mrz_td3_ecdsa_p256_sha256_ec512_inclusion/src/main.nr`: `"registration: context must be set"`

`verify_bundle` refuses a policy whose context is zero (`Failure::ContextNotSet`) before it looks at any proof.

## 6. The two salt conventions

There are two salts and they behave differently.

### The session salt

Third argument of `entropy_seed`. Fresh random per session, and `entropy_seed` asserts it is not zero with `"commit: session salt must be non-zero"`. It is the only hiding input in the commitment chain. Without it the chain is a deterministic function of `dg_hash` and `domain`, and for the machine readable zone profiles `dg_hash` is SHA-256 over DG1, which is the printed machine readable zone wrapped in two TLV templates. So a zero session salt does not merely link sessions: anyone holding a photocopy of the data page can recompute the seed, every leaf, the root and therefore the holder's `commitment` for any domain, and test it against a stored value. The assert is what closes that. A persistent per holder registry entry has to be built on a holder secret, not on a fixed salt. `the_commitment_hides_behind_the_session_salt` in `lib/attributes` checks that two salts give two commitments and the same `dg_binding`.

### The DSC salt

Second argument of `dsc_commitment`. Zero is a legitimate value here and means one specific thing: the public registry convention, where the verifier compares the published commitment against a table it precomputed as `dsc_commitment(pubkey_hash(x, y), 0)` over the signer keys it accepts. What that costs is which signer signed, and therefore the issuing state and the issuing batch, plus linkability between two holders whose documents share a signer. A random salt hides that, and it is required when trust is proved in zero knowledge instead of looked up: `lib/anchor` returns `dsc_commitment(pubkey_hash(x, y), salt)` for the same salt the Passive Authentication proof used, so the verifier requires the two commitments to be equal without either proof revealing the key. `the_salt_hides_which_signer_it_was` in `lib/anchor` checks that the same key under two salts gives two commitments.

Cost of the other zero values, for completeness. `nullifier` asserts `secret != 0` (section 7.14). `context == 0` and `domain == 0` are rejected in every circuit binary, and `verify_bundle` rejects a policy carrying either before it looks at any proof (`ContextNotSet`, `DomainNotSet`).

## 7. Derived values

Notation: `H(a, b, ...)` is `Poseidon2::hash([a, b, ...], n)` with `n` the number of arguments shown.

### 7.1 `hash32_to_fields(h: [u8; 32]) -> [Field; 2]`

Not a hash. It splits a 32 byte digest into two field elements, big endian, `h[0..16]` into element 0 and `h[16..32]` into element 1. 16 bytes always fit a BN254 element, and the split is injective for a fixed 32 byte input. Pinned by `hash32_packs_big_endian`.

### 7.2 `pack_pair(a: [u8; K], b: [u8; K]) -> [Field; 4]`

Not a hash. Splits each of two equal length byte strings in half and packs each half big endian into one element: `[a[0..K/2], a[K/2..K], b[0..K/2], b[K/2..K]]`. Asserts `K` is even (`"commit: length must be even"`) and `K/2 <= 31` (`"commit: half does not fit a field element"`), so up to 62 bytes per string. `K` is not itself hashed, so injectivity holds within a fixed `K` only; see section 11, gap 5.

### 7.3 `econtent_binding(h, domain) = H(TAG_ECONTENT, h[0], h[1], domain)`, tag 1

Binds one authenticated Security Object to one application. `h` is `hash32_to_fields` of the SHA-256 of eContent.

`lib/sod::link` hashes eContent, reads the `messageDigest` signed attribute with `cms::message_digest_sha256`, asserts the two are equal byte for byte (`"sod: security object digest does not match the signed attribute"`) and returns both that digest and the hash of the signed attributes. The signature over the signed attributes is verified in the binary, not in `link`: `bin/sod/ecdsa_p256_sha256_ec512` calls `sig::verify_ecdsa_p256` on the returned `signed_attrs_hash` before it calls `lib/sod::outputs`, which computes the binding. Published as `sod` return[0].

Checked in `lib/dg_extract::extract_sha256`, which re-hashes the Security Object it was given and asserts the recomputed binding equals the `econtent_binding` public input, with `"dg_extract: security object does not match the authenticated one"`. Checked again across proofs by `verify_bundle`, step 4 of section 9.

### 7.4 `dg_binding(h, domain) = H(TAG_DG, h[0], h[1], domain)`, tag 2

Binds one data group hash to one application. Same shape as 7.3 under a different tag, which is what stops a Security Object binding standing in for a data group binding; `bindings_are_role_separated` asserts the two differ for identical inputs.

Computed in `lib/dg_extract::extract_sha256` from the hash it read out of the authenticated Security Object, after `lds::check_sha256_oid` and `lds::dg_entry_sha256` confirm the entry is the requested `dg_number`. Published as `dg_extract` return[0].

Checked in `lib/attributes::td3` and `lib/attributes::td1`, which hash the DG1 buffer they were given and assert the recomputed binding equals the `dg_binding` public input, with `"attributes: data group was not the authenticated one"`. Checked again across proofs by `verify_bundle`, step 5 of section 9.

### 7.5 `pubkey_hash(x, y) = H(TAG_DSC_KEY, p[0], p[1], p[2], p[3])` where `p = pack_pair(x, y)`, tag 9

Identifies a Document Signer public key by a single element. Never a public input on its own. It is the leaf of the registry tree in `lib/anchor::prove_signer_is_trusted` and the input to `dsc_commitment`.

### 7.6 `dsc_commitment(dsc_pubkey_hash, salt) = H(TAG_DSC, dsc_pubkey_hash, salt)`, tag 3

Binds a proof to the signer key without revealing it. Computed in `lib/sod::outputs` from the key the signature verified under, and published as `sod` return[1]. Computed again in `lib/anchor::prove_signer_is_trusted` from the key it proved is in the published registry, and published as the return of `bin/anchor/dsc_inclusion`.

Nothing inside a circuit compares the two. `verify_bundle` does: every `Anchor` proof in a bundle must carry an `anchor_dsc_commitment` (index 3) equal to the Security Object proof's `sod_dsc_commitment` (index 3), else `Failure::AnchorForAnotherSigner`. A verifier that wants signer trust enforced sets `Policy::require_anchor(registry_root)`, which makes a bundle without an anchor proof fail with `Failure::NoTrustAnchorProof` and an anchor proof against another registry fail with `Failure::AnchorAgainstAnotherRegistry`. Without that flag the commitment is returned in `Verified.dsc_commitment` and compared against nothing; see section 11, gap 2.

### 7.7 `document_secret(signature_r, signature_s) = H(TAG_DOCUMENT_SECRET, p[0], p[1], p[2], p[3])` where `p = pack_pair(signature_r, signature_s)`, tag 11

Material that identifies one document and that only a party who read its chip can produce. The signature over the Security Object serves because it is fixed at issuance, so a prover cannot choose it, and it is not printed on the data page, so it cannot be guessed from a photocopy. It does not survive reissue: a replacement document carries a different signature and therefore a different secret.

Never published. It exists only as the input to `secret_binding` and as the private `secret` input of the nullifier circuit.

### 7.8 `secret_binding(secret, domain) = H(TAG_SECRET_BINDING, secret, domain)`, tag 12

Lets a later circuit prove it holds the same secret without revealing it. Scoped by `domain`, because unscoped it would itself be a stable per document identifier visible to every application at once.

Computed in `lib/sod::outputs` as `secret_binding(document_secret(signature_r, signature_s), domain)` and published as `sod` return[2].

Checked in `lib/nullifier::document_number`, which recomputes `secret_binding(secret, domain)` from its private `secret` input and asserts it equals the `secret_binding` public input, with `"nullifier: secret does not match the authenticated document"`. Checked again across proofs by `verify_bundle`, step 6 of section 9. `the_secret_binding_separates_documents` in `lib/sod` asserts two documents give different bindings under one domain.

### 7.9 `entropy_seed(dg_hash, domain, session_salt) = H(TAG_ENTROPY, dg_hash[0], dg_hash[1], domain, session_salt)`, tag 5

Asserts `session_salt != 0`. The root of all per field blinding. Computed in `lib/attributes::td3` and `td1` from the same `dg_hash_fields` used for `dg_binding`. Never published; it stays private inside the attribute circuit.

### 7.10 `field_entropy(seed, field_id) = H(TAG_FIELD_ENTROPY, seed, field_id)`, tag 8

One blinding value per field, so that opening one leaf of the commitment tree tells the verifier nothing about the others. Computed in `lib/attributes::build_commitment` for each of the sixteen field slots. Never published. It travels to a predicate circuit as the private `entropy` input of a `FieldOpening`, where the leaf recomputation is what checks it.

### 7.11 `leaf(field_id, length, data, entropy) = H(TAG_LEAF, field_id, length, data[0], data[1], data[2], data[3], entropy)`, tag 4

One committed field. `field_id` is in `1..=16` and fixes the leaf's position in the tree as `field_id - 1`, which is what stops a statement about one field being presented as a statement about another. `length` is the field's length before packing: the byte count for the fields packed out of the machine readable zone, and 8 for the two date fields, which carry the normalized YYYYMMDD integer rather than packed characters. It is hashed because `normalize::pack_to_4` is big endian with no length prefix, so two byte strings that differ only in leading zeros pack identically and only `length` separates them. `data` is four elements of up to 31 bytes each.

The field identifiers for the machine readable zone profiles are declared in `lib/attributes`: `FIELD_DOCUMENT_CODE` 1, `FIELD_ISSUING_STATE` 2, `FIELD_DOCUMENT_NUMBER` 3, `FIELD_NATIONALITY` 4, `FIELD_BIRTH_DATE` 5, `FIELD_SEX` 6, `FIELD_EXPIRY_DATE` 7, `FIELD_NAME` 8, `FIELD_OPTIONAL_DATA` 9, with `FIELD_COUNT` 16. Slots 10 through 16 are filled with `empty_field`, which is identifier `i + 1`, length 0 and zero data, so the tree is always sixteen wide.

Computed in `lib/attributes::build_commitment`. Recomputed in `lib/predicate::open`, which rebuilds the leaf from the opening, walks it to a root with `walk_path(value, field_id - 1, siblings)` and asserts `commitment(root, domain)` equals the `commitment` public input, with `"predicate: field is not part of the committed document"`. `open` also asserts `field_id >= 1` and `field_id <= 16`, both with `"predicate: field identifier out of range"`.

### 7.12 `commitment(root, domain) = H(TAG_COMMITMENT, root, domain)`, tag 6

The value every statement about the document's fields is proved against. `root` is `root16` over the sixteen leaves.

Computed in `lib/attributes::build_commitment` and published as `attributes` return[0]. Checked in `lib/predicate::open` for all three predicates, and in `lib/nullifier::document_number` through the two `predicate::open_field` calls it makes before it uses any field value. Checked again across proofs by `verify_bundle`, step 6 of section 9.

### 7.13 `set_entry(data) = H(TAG_SET_ENTRY, data[0], data[1], data[2], data[3])`, tag 10

An entry in a set the verifier publishes, for example a list of accepted issuing states. Tagged so a set entry cannot be read as a document leaf, and five wide so it cannot be read as a Merkle node.

Computed in `lib/predicate::member` from the opened field's `data`, then walked with `walk_path(set_entry(opening.data), set_index, set_siblings)` and asserted equal to the `set_root` public input, with `"predicate: value is not in the set"`. The verifier builds the same tree off circuit and publishes only its root. Note that `set_entry` hashes `data` alone: not `length`, not `field_id`. Membership is therefore over packed values, and the verifier is responsible for building the set with the same packing that `normalize::pack_to_4` produces and for knowing which field the proof is about from the public `field_id`.

### 7.14 `nullifier(policy_id, packed, secret, domain) = H(TAG_NULLIFIER, policy_id, packed[0], packed[1], packed[2], packed[3], secret, domain)`, tag 7

Asserts `secret != 0` with `"commit: nullifier secret must be non-zero"`. One value per holder per application, which an application stores to recognise a repeat registration without learning who registered.

Two properties are required of `secret`, and both matter. It must be unguessable without access to the chip or to a keyed service, which is what closes the enumeration oracle: without a secret the value would be a hash of a public policy identifier, a public domain and fields printed on the data page, so anyone holding a copy of a document could compute its holder's nullifier for any domain and test whether that person had registered. And it must not be chosen by the prover, since a holder who can pick it can register twice and defeat the uniqueness the nullifier exists to provide. The shipped choice, `document_secret`, has both properties and does not survive reissue.

Computed in `lib/nullifier::document_number`, which first asserts the two openings are `field_id` 2 and 3 in that order, opens both against the commitment, checks the secret binding, then packs `[issuing_state.data[0], document_number.data[0], document_number.data[1], document_number.data[2]]` and derives the value with `policy::DOCUMENT_NUMBER_V1` (1001). Published as `nullifier` return[0].

Policy identifiers live in `lib/policy`: `DOCUMENT_NUMBER_V1` 1001, `MRZ_STABLE_V1` 2001, `NATIONAL_IDENTIFIER_V1` 3001, encoded as `family * 1000 + version`. `policy::assert_supported` exists but is called only from that library's own tests, never on the nullifier path. In the shipped circuit the policy identifier is a compile time constant, not a public input; see section 11, gap 3.

## 8. Public input order

`layout.manifest` is generated from the compiled ABIs and committed in the prover crate. Barretenberg lays out the public parameters in declaration order followed by the return values. The tests at the end of `layout.rs` cover this table by reading the manifest, and they fail if the indices this crate uses drift from it. `cargo test` in `/Users/wstran/Desktop/zkICAO/prover` reports 19 unit tests and one doc test on the current tree, plus 18 integration tests over real proofs when `ZKICAO_BUNDLE` points at a bundle the circuits produced.

| Package | Public inputs, in order |
| --- | --- |
| `sod_ecdsa_p256_sha256_ec512` | `domain`, `context`, `return[0]` econtent binding, `return[1]` DSC commitment, `return[2]` secret binding |
| `dg_extract_sha256_ec512` | `dg_number`, `econtent_binding`, `domain`, `context`, `return[0]` dg binding |
| `attributes_mrz_td1_sha256` | `dg_binding`, `current_yyyymmdd`, `domain`, `context`, `return[0]` commitment |
| `attributes_mrz_td3_sha256` | `dg_binding`, `current_yyyymmdd`, `domain`, `context`, `return[0]` commitment |
| `predicate_compare` | `field_id`, `commitment`, `minimum`, `maximum`, `domain`, `context` |
| `predicate_member` | `field_id`, `commitment`, `set_root`, `domain`, `context` |
| `predicate_reveal` | `field_id`, `commitment`, `revealed[0..3]`, `revealed_length`, `domain`, `context` |
| `nullifier_document_number` | `commitment`, `secret_binding`, `domain`, `context`, `return[0]` nullifier |
| `anchor_dsc_inclusion` | `registry_root`, `domain`, `context`, `return[0]` DSC commitment |
| `registration_mrz_td3_ecdsa_p256_sha256_ec512_inclusion` | `domain`, `context`, `return[0]` commitment, `return[1]` secret binding, `return[2]` current date, `return[3]` registry root |

`Circuit::domain_index` gives 0, 2, 2, 4, 3, 7, 2, 1, 2, 0 for `Sod`, `DgExtract`, `Attributes`, `Compare`, `Member`, `Reveal`, `Nullifier`, `AnchorInclusion`, `AnchorChain`, `Registration`. `Circuit::context_index` is defined as `domain_index() + 1`, and `context_always_follows_domain` plus `domain_and_context_sit_where_this_crate_reads_them` check that against the manifest for every circuit.

## 9. The equalities a verifier enforces

`verify_bundle(proofs, policy)` in `prover/src/verify.rs`, in execution order. A `Policy` fixes the accepted verification key hashes per circuit, the `domain`, the `context`, whether a trust anchor proof is required (`require_trust_anchor`) and the registry root an anchor proof has to be against (`registry_root`). Any public input read that fails returns `Failure::Malformed`.

1. `policy.context` is not zero, else `ContextNotSet`. `policy.domain` is not zero, else `DomainNotSet`. If `policy.require_trust_anchor` is set without `policy.registry_root`, `RegistryRootNotSet`, since an anchor accepted against an unspecified registry proves membership of a set the prover may have published itself.
2. One pass over every proof, in order. Its verification key must be in `policy.accepted_keys[circuit]`, compared by the key bytes, else `UntrustedVerificationKey`. This is the downgrade check: without it a proof from a weaker circuit variant would pass on the strength of being a valid proof of something. Then `bb verify` must succeed over the verification key, the proof bytes and the serialised public inputs, else `ProofRejected`; verification is delegated to Barretenberg rather than reimplemented in Rust. Then `public_inputs[domain_index]` must equal `policy.domain`, else `WrongDomain`, since a bundle whose proofs carry different domains is several documents wearing one identity. Then `public_inputs[context_index]` must equal `policy.context`, else `WrongContext`. Document proofs, `Circuit::Sod` or `Circuit::Registration`, are collected as they are seen.
3. Exactly one document proof, of either kind. Zero gives `NoSecurityObjectProof`, two or more give `MoreThanOneSecurityObjectProof`.
4. Leaf form, when the document proof is a `Sod` proof. For every `DgExtract` proof, `dg_extract_econtent_binding()` (index 1) equals the Security Object proof's `sod_econtent_binding()` (index 2), else `UnlinkedDataGroup`; the `dg_number` values become `Statement::DataGroup` entries and the `dg_extract_dg_binding()` values (index 4) are collected. For every `Attributes` proof, `attributes_dg_binding()` (index 0) is one of those bindings, else `UnlinkedDataGroup`; its date passes the window check of step 6 and the `attributes_commitment()` values (index 4) are collected. For every anchor proof of either mode, `anchor_dsc_commitment()` equals the Security Object proof's `sod_dsc_commitment()` (index 3), else `AnchorForAnotherSigner`; a chain anchor's date passes the window check; if `policy.registry_root` is set the anchor's first public input must equal it, else `AnchorAgainstAnotherRegistry`; and if `policy.require_trust_anchor` is set and no anchor proof was seen, `NoTrustAnchorProof`.
5. Aggregate form, when the document proof is a `Registration` proof. A `DgExtract`, `Attributes` or anchor proof beside it gives `NotLinkableToRegistration`, because the registration proof exposes none of the values such a proof would have to be checked against. `Statement::DataGroup { number: 1 }` is recorded, since the circuit pins the extraction to DG1. The returned commitment (index 2) is collected, the date (index 4) passes the window check, and the registry root (index 5) must equal `policy.registry_root` when one is fixed, else `AnchorAgainstAnotherRegistry`. A required trust anchor is satisfied by construction.
6. Dates. Every date read in steps 4 and 5 must sit inside `policy.date_window` when one is set, else `DateOutsideWindow`, and every date carrying proof in one bundle must have used the same date, else `InconsistentDates`, so a bundle cannot resolve a birth year against one date and certificate validity against another.
7. One pass over every proof again. For a `Compare`, `Member` or `Reveal` proof, `referenced_commitment()` (index 1) is one of the collected commitments, else `UnlinkedCommitment`; each contributes a `Statement` carrying its `field_id` and its bounds, set root, or revealed elements and length. For a `Nullifier` proof, `referenced_commitment()` (index 0) is one of those commitments, else `UnlinkedCommitment`, and `nullifier_secret_binding()` (index 1) equals the document proof's secret binding, `return[2]` of a `Sod` proof or `return[1]` of a `Registration` proof, else `NullifierFromAnotherDocument`. A second `Nullifier` proof gives `MoreThanOneNullifierProof`.

On success it returns `Verified { nullifier, dsc_commitment, statements, asserted_date, signer_registry_root }`: the nullifier value if one proof carried it, the salted signer commitment when the document proof exposes one, `None` in the aggregate form, everything the bundle proved as statements, the one date the proofs resolved against, and the registry root the signer was shown to belong to.

Chained together, steps 3 through 6 are the linkage argument for the document data. A signature the issuing state made covers signed attributes; those attributes carry the eContent digest; that digest becomes `econtent_binding`; a data group hash read out of that same eContent becomes `dg_binding`; DG1 hashing to that `dg_binding` becomes `commitment`; a field opened against that `commitment` is what a predicate or the nullifier speaks about. Break any one equality and the proofs are about different documents. Steps 7 and 8 attach the separate question of whose key signed, through `dsc_commitment`.

## 10. What the verifier does not check

These are the relying party's own policy layer, not defects, but an integration that assumes otherwise is wrong:

`dg_number` is surfaced as a `Statement::DataGroup` and compared to nothing. A verifier that needs DG1 specifically must read the statements; only the registration circuit pins the number in circuit.

`current_yyyymmdd` is compared only against the window the policy sets. A policy without `require_date_within` constrains no date, and a prover free to choose the date moves a birth date by a century, so a verifier must set the window or check `asserted_date` itself.

`minimum`, `maximum` and `set_root` are surfaced in `Statement::Compare` and `Statement::Member` and compared to nothing. The statement proved is only as useful as the bounds or the set the verifier required, so it must read them back.

Signer trust in the leaf form is checked only when the policy asks for it. With `require_trust_anchor` off and no anchor proof in the bundle, `dsc_commitment` is returned and compared against nothing; see gap 2. The aggregate form always carries signer trust.

## 11. Known gaps

1. Closed at both layers: every circuit binary asserts `domain != 0`, and `verify_bundle` rejects a zero policy domain with `DomainNotSet` before reading any proof. The residual obligation is choosing a domain distinct from other applications, which nothing can check for the caller.
2. Signer trust in the leaf form is enforced only when the caller asks for it. `Policy::new` leaves `require_trust_anchor` false and `registry_root` unset, and in that state a leaf bundle proves that some key signed the document and nothing about whose key it is. Setting `require_trust_anchor` by hand without a root is now a stated failure, `RegistryRootNotSet`, rather than an anchor accepted against any registry; `Policy::require_anchor(root)` sets both. Separately, `lib/anchor` notes that the inclusion mode assumes whoever built the set checked the certificates; the chain mode removes that assumption for one link.
3. `lib/policy`'s header says the policy identifier "is a public input and is hashed into the nullifier". Only the second half is true of the shipped circuit: `lib/nullifier::document_number` hashes the constant `policy::DOCUMENT_NUMBER_V1`, and `bin/nullifier/document_number` has no policy public input. A verifier distinguishes policies by which verification key it accepts, not by reading a value. `policy::assert_supported` is never called outside that library's tests. `MRZ_STABLE_V1` and `NATIONAL_IDENTIFIER_V1` have identifiers but no circuit.
4. Closed: `Statement::Reveal` carries `field_id`, the four packed elements and the length, so a consumer decoding bytes no longer reads an index by hand.
5. `pack_pair` does not hash `K`, so `pubkey_hash` and `document_secret` are injective within one byte length only. Two instantiations at different curve sizes are separated by the verification key a verifier accepts, not by the derived value itself.
6. Half closed: a second `Nullifier` proof is now rejected with `MoreThanOneNullifierProof`. Anchor proofs remain uncapped, each individually linked, with `signer_registry_root` reporting the last one seen; a policy that fixes a root removes the ambiguity, since every anchor must then match it.
7. `lib/nullifier::document_number` packs `document_number.data[0..2]` and drops `data[3]`. For the machine readable zone profiles the document number is nine bytes and lives entirely in `data[0]`, so nothing is lost today. `normalize::pack_to_4` puts 31 bytes in each element and `normalize::MAX_FIELD_BYTES` is 124, so a profile with a document number longer than 93 bytes would lose bytes silently.

## 12. Invariants

1. Every derived value in `lib/commit` except `hash_pair` and the two packing helpers begins with a role tag, and each of the twelve tags belongs to exactly one function. No tag is zero.
2. Every tagged value hashes three or more field elements. `hash_pair` hashes exactly two. Therefore no tagged value can be read as a Merkle internal node and no internal node can be read as a tagged value. Any new two input tagged constructor breaks this and must not be added.
3. `domain` is hashed into `econtent_binding`, `dg_binding`, `secret_binding`, `entropy_seed`, `commitment` and `nullifier`. The same document under two domains produces six different values, so two applications cannot correlate their records by comparing them.
4. `dsc_commitment` is deliberately domain free so that one registry table serves every application. Its hiding comes from `dsc_salt`, not from `domain`.
5. `context` is hashed into nothing. It is a public input of every circuit, every binary asserts it is non-zero, and `verify_bundle` rejects a zero policy context and requires every proof to carry the policy's value.
6. `entropy_seed` rejects a zero session salt. A fresh random session salt per proving session is required; it is the only hiding input in the commitment chain, and without it the chain is recomputable by anyone holding a photocopy of the data page.
7. `nullifier` rejects a zero secret. The secret must be unguessable without the chip and not choosable by the prover; the shipped source is `document_secret` over the Security Object signature, which is fixed at issuance and not printed.
8. `secret` never leaves the prover. Passive Authentication publishes `secret_binding(secret, domain)`, and the nullifier circuit proves it holds the matching secret by recomputing that binding.
9. A leaf's position in the commitment tree is `field_id - 1`, `field_id` is hashed into the leaf, and the tree is always sixteen wide with unused slots filled by `empty_field`. A statement proved about one field cannot be presented as a statement about another.
10. `length` is hashed into every leaf, because `normalize::pack_to_4` is big endian with no length prefix and two byte strings differing only in leading zeros pack identically.
11. Path walks take one direction bit per level from the index and assert the index is in range (`index < 2^D` and `D < 32` in `walk_path`). A sibling cannot be applied on the wrong side.
12. A document proof is what the rest of a bundle hangs off, and exactly one must be present: a Passive Authentication proof, which the leaf proofs reach through the chain econtent binding, dg binding, commitment, or a registration proof, which carries that chain inside and exposes only its ends. An anchor proof attaches through `dsc_commitment` equality and says nothing about the document's fields; beside a registration proof it has nothing to attach to and is rejected.
13. Every proof in a bundle must carry the same `domain` and the same `context` as the verifier's policy.
14. Every proof in a bundle must have been produced with a verification key the verifier listed in advance for that circuit. This is what makes a circuit variant a policy decision rather than a prover's choice.
15. An application must fix exactly one nullifier policy per `domain`. Accepting two lets one holder present two different nullifiers, which defeats the uniqueness the nullifier exists to provide. With the shipped circuit this means accepting exactly one nullifier verification key per domain.
16. The nullifier is stable per document, not per person. A replacement document produces a different value, both because the document number usually changes and because `document_secret` is tied to the signature on this document. A policy that promises stability across reissue cannot be built on it, and none is implemented.

## Appendix: circuit sizes

Opcode counts are in `architecture.md`, which is the only place they are recorded.

That shape is the reason the chain is split the way it is. The signature check runs once and dominates: the two attribute circuits and the extraction circuit are roughly an order of magnitude smaller, and every predicate, the nullifier and the anchor are two orders of magnitude smaller or more, so asking one more question of a document costs a small fraction of the first proof.
