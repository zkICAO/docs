# zkICAO architecture

## Scope of this document

This describes the circuit set as it exists in code, not a design that is planned. Every statement below was checked against the source at these revisions:

| Repository | Revision | Contents |
|---|---|---|
| zkICAO/circuits | HEAD `14a081c`, last code change `6244f20` (2026-07-25) | 18 library packages, 11 circuits, 1 build probe |
| zkICAO/prover | `adc4dcc` | the off-chain verifier, `verify_bundle` |
| toolchain | nargo 1.0.0-beta.19 | pinned in `TOOLCHAIN.md` |

`14a081c` changes documentation only; `6244f20` is the last commit that changed a circuit. The repository is under active development and the set grows faster than a document can track. Check the revision before relying on the inventory here. What is stable is the shape: the linkage between circuits, the derived value formats, and the verification procedure.

One caution about the pin. `TOOLCHAIN.md` still carries a line saying RSA is not implemented. That line is stale: `lib/rsa` and `bin/sod/rsa2048_v15_sha256_ec512` exist and are described below.

Where something is absent, this document says so rather than describing an intention. The section "What is not implemented" is not a roadmap, it is the boundary of what a proof from this system means.

zkICAO is an independent open source project. It is not affiliated with, endorsed by, or approved by the International Civil Aviation Organization or the United Nations. It reads documents that follow ICAO Doc 9303 because that specification is public.

## 1. Why the protocol is several circuits

A holder does not present one proof. A holder presents a bundle, and each proof in it is sound on its own and says nothing about the others. What makes a bundle describe a single document is a set of equalities between public values that the verifier checks after every proof has verified.

The chain runs in one direction. Passive Authentication establishes that a Security Object was signed and publishes a binding to that Security Object. A data group extraction proof re-hashes the same Security Object, matches that binding, and publishes a binding to one data group hash. An attribute proof takes the data group, checks its hash against that binding, and publishes a salted commitment over the individual fields. Predicate proofs and the nullifier open one field of that commitment and say something about it.

```
anchor_dsc_inclusion              sod_<sigalg>_<digest>_ec<n>
anchor_csca_chain_<...>           Passive Authentication
the signer is one we trust                 |
        |                                  |
        +====== dsc_commitment ============+
                                           |
                       econtent_binding    |    secret_binding
                                v          |          |
                    dg_extract_<digest>_ec<n>         |
                       one data group hash            |
                                |                     |
                            dg_binding                |
                                v                     |
                    attributes_mrz_<layout>_<digest>  |
                       commitment over the fields     |
                                |                     |
                            commitment                |
                                v                     |
        predicate_compare   range over one field      |
        predicate_member    membership in a set       |
        predicate_reveal    disclose one field        |
        nullifier_document_number  scoped identifier==+
```

The `====` lines are equalities the verifier checks between public values of different proofs. The `v` arrows are values one proof publishes and the next consumes as a public input.

Two properties come out of this shape. The expensive step runs once per document rather than once per question, which section 3 quantifies. And a verifier that only wants to know whether the holder is over eighteen never receives a birth date, because the date is read inside the attribute circuit, goes into the commitment, and never becomes a public value.

Two scoping values appear in every circuit. `domain` identifies the application and enters every derived value the verifier stores or compares across sessions, with one exception, `dsc_commitment`, which section 4 covers. `context` identifies one session, is asserted non-zero in all eleven circuits, and deliberately enters no derived value, because mixing it in would change stored values every session. Both are public inputs of every circuit.

## 2. The circuits

Public inputs are listed in Barretenberg layout order, which is the public parameters in declaration order followed by the return values. That order is recorded in `prover/layout.manifest`, generated from the compiled ABIs and checked by the prover tests.

### 2.1 Passive Authentication: sod_ecdsa_p256_sha256_ec512 and sod_rsa2048_v15_sha256_ec512

Packages `bin/sod/ecdsa_p256_sha256_ec512` and `bin/sod/rsa2048_v15_sha256_ec512`, over `lib/sod`, `lib/cms`, `lib/hash`, `lib/commit`, plus `lib/sig` or `lib/rsa` for the signature step. `lib/sod` is generic over the buffer sizes and splits the shared linking (`link`) from the signature check, so a variant supplies only its own algorithm.

Both variants take `econtent [u8; 512]`, `econtent_len u32`, `signed_attrs [u8; 256]`, `signed_attrs_len u32`, `digest_offset u32` and `dsc_salt Field` privately, and differ only in the key and signature witnesses. The curve variant takes `pubkey_x [u8; 32]`, `pubkey_y [u8; 32]`, `signature_r [u8; 32]`, `signature_s [u8; 32]`. The RSA variant takes `modulus_limbs [u128; 18]`, `redc_limbs [u128; 18]` and `signature_limbs [u128; 18]`.

Both publish the same five field elements in the same layout order: `domain`, `context`, `econtent_binding`, `dsc_commitment`, `secret_binding`. They are interchangeable to everything downstream, and a verifier tells them apart only by verification key.

What they prove, from `sod::link` and `sod::outputs`:

1. SHA-256 over the first `econtent_len` bytes of `econtent` equals the 32 bytes at `digest_offset` in `signed_attrs`, where `cms::message_digest_sha256` has checked that the 11 bytes beginning 15 bytes before that offset are the messageDigest OID encoding, that byte `digest_offset - 4` is `0x31`, and that bytes `digest_offset - 2` and `digest_offset - 1` are `0x04 0x20`.
2. The signature verifies over SHA-256 of the first `signed_attrs_len` bytes of `signed_attrs`. In the curve variant that is an ECDSA P-256 verification, and the wrapper in `lib/sig` calls `validate_in_field` on all four decoded values first, since byte deserialization in noir-bignum only bounds a value by `2^MOD_BITS`. In the RSA variant it is PKCS#1 v1.5: the signature is raised to 65537 as sixteen squarings and one multiply, and the recovered encoding is checked byte for byte, the leading `00 01`, every `FF` of the padding run, the `00` separator, the 19 byte SHA-256 DigestInfo prefix and the digest. Constraining the whole padding run is what stops a forger placing the DigestInfo at another offset. Only the exponent 65537 is accepted. `redc_limbs` is a Barrett reduction hint for the runtime modulus. The header of `lib/rsa` states that the bignum backend constrains every multiplication against it, so a wrong hint cannot make a bad signature verify; that is a property of the pinned dependency and nothing here checks it.
3. The three outputs are derived: `econtent_binding` over the Security Object hash and `domain`, `dsc_commitment` over the key hash and the private `dsc_salt`, `secret_binding` over the document secret and `domain`.

What they do not prove. Neither parses the Security Object: no LDS structure, version, or data group list is read here. Neither checks any signed attribute other than messageDigest, so contentType, eContentType and signingTime are unconstrained. Neither checks that `signed_attrs` starts with the DER SET tag or that `signed_attrs_len` is its true DER length; the only defence there is that changing those bytes changes the digest the signature covers. Above all neither proves the key belongs to a Document Signer. The key is a witness, and nothing here reads a certificate; that is a separate proof, section 2.6. On its own, this proof says a key signed the document, not whose key it was. It says nothing about expiry, revocation, or whether the data came from a live chip.

The public key stays private and only a salted commitment leaves, so that a trust proof can match a registry without revealing which signer, and therefore which issuing state and batch, produced the document.

The two algorithms carry their key and signature in different shapes, and `commit` has a helper for each. `pubkey_hash` and `document_secret` take a curve point or a signature pair through `pack_pair`, which asserts each half is at most 31 bytes. `modulus_hash` and `limbs_document_secret` take a number as limbs and fold every one of them, then finish with a three wide hash carrying the role tag and the limb count. `sod::outputs` takes both values already hashed, so the variant that knows its algorithm chooses the helper and no caller can pass a value in a shape that drops part of it.

An earlier revision did drop part of it. The RSA variant reshaped a modulus into two 32 byte halves by keeping three bytes of each limb, which committed to 432 bits of 2048 and made `dsc_commitment` an identifier for a sample rather than for the key. Nothing was exploitable at that width, and it was corrected in `98d7611`.

One consequence of the low-s rule in `lib/sig` matters for anyone deriving values from the signature. The header of `lib/sig` records that the ECDSA backend rejects `s` above `n/2` and aborts rather than returning false, so the only witness that can prove at all carries the normalized form. In the curve variant `document_secret` is therefore computed over a canonical `(r, s)` and does not depend on which of the two equivalent encodings the chip happened to store.

### 2.2 dg_extract_sha256_ec512

Package `bin/dg_extract/sha256_ec512`, over `lib/dg_extract`, `lib/lds`, `lib/hash`, `lib/commit`.

Private: `econtent [u8; 512]`, `econtent_len u32`, `oid_offset u32`, `dg_offset u32`.

Public: `dg_number u8`, `econtent_binding`, `domain`, `context`, then the returned `dg_binding`. Five field elements.

It re-hashes the Security Object, derives `econtent_binding` the same way the Passive Authentication circuit did, and asserts it equals the public one. That equality is the whole link to the signature: this circuit does not verify a signature. It then asserts the 11 bytes at `oid_offset` are the SHA-256 algorithm OID encoding, and that the 39 bytes at `dg_offset` are `30 25 02 01 <dg_number> 04 20` followed by 32 bytes, with `dg_number` between 1 and 16. It returns `dg_binding` over those 32 bytes and `domain`.

`dg_number` is public so the verifier states which data group the proof is about instead of trusting the prover to say afterwards.

What it does not prove is documented in the header of `lib/lds` and is worth repeating. `dg_entry_sha256` checks the header bytes sitting at the offset it is given and nothing about how that offset was reached. It does not walk the Security Object from its start, so it cannot distinguish a genuine entry from any other byte sequence in the buffer with the same seven header bytes. Both offsets are private and independent, so nothing ties the algorithm identifier at `oid_offset` to the entry at `dg_offset`. The argument that this is still safe is that every byte read lies inside a buffer whose hash matches the authenticated `econtent_binding`, so a prover who finds a matching pattern only obtains data the issuer signed. A circuit that needs a stronger guarantee has to establish the offset itself, and none does.

### 2.3 attributes_mrz_td3_sha256 and attributes_mrz_td1_sha256

Packages `bin/attributes/mrz_td3_sha256` and `bin/attributes/mrz_td1_sha256`, over `lib/attributes`, `lib/mrz`, `lib/normalize`, `lib/hash`, `lib/commit`. TD3 is the passport layout, two lines of 44 characters. TD1 is the card layout, three lines of 30.

Private: `dg1 [u8; 128]`, `dg1_len u32`, `session_salt Field`.

Public: `dg_binding`, `current_yyyymmdd u32`, `domain`, `context`, then the returned `commitment`. Five field elements.

The circuit asserts the DG1 template is `61 <len> 5F 1F <mrz_len>` with `dg1_len == 5 + mrz_len` and `len == mrz_len + 3`, hashes DG1, and asserts the resulting `dg_binding` equals the public one. It then validates the MRZ check digits under the 7-3-1 weighting, accepting the filler character where Doc 9303 puts one in place of a check digit, which is the document number position in both layouts and the optional data position in TD3, resolves both dates to `YYYYMMDD` integers with calendar validation including leap years, and builds a 16 leaf Poseidon2 Merkle tree whose root, hashed with the domain, becomes the commitment.

Nine fields are populated, at leaf index `field_id - 1`: document code 1, issuing state 2, document number 3, nationality 4, birth date 5, sex 6, expiry date 7, name 8, optional data 9. Leaves 10 to 16 carry length zero and empty data. Each leaf carries per-field entropy derived from `entropy_seed`, which mixes the data group hash, the domain and the private `session_salt`, and which rejects a zero salt. That salt is the only hiding input in the chain: without it the commitment is a deterministic function of DG1, which is the printed machine readable zone, and anyone holding a photocopy of the data page could recompute a holder's commitment for a domain.

Nothing is published except the commitment. Dates in particular are read to build it and never leave.

`current_yyyymmdd` is public because it decides the century a two digit birth year resolves to. A prover free to choose it could move a birth date by a century. The circuit does not and cannot check that this value is today's date, which is the verifier's job.

Known limits of the profile. The template parse is fixed offset and short form only, which is sufficient because both layouts produce a length below 0x80 but would not extend to a longer data group. `TD1_OPTIONAL1`, the first optional data field of the card layout at offset 15, is defined in `lib/mrz` and referenced nowhere else in the workspace; the TD1 profile commits `TD1_OPTIONAL2` only, and a comment in `lib/attributes` records that as the deliberate choice. Check digits detect transcription mistakes and not tampering: a test in `lib/mrz` named `check_digits_miss_multiple_of_ten_substitutions` documents that substituting a character whose value differs by a multiple of ten leaves every check digit unchanged. Integrity of the MRZ rests entirely on the signature over DG1, not on the check digits.

### 2.4 predicate_compare, predicate_member, predicate_reveal

Packages under `bin/predicate/`, over `lib/predicate` and `lib/commit`. Each takes a `FieldOpening` of `field_id`, `length`, `data [Field; 4]`, `entropy` and `siblings [Field; 4]`, rebuilds the leaf, walks it to the root at index `field_id - 1`, and asserts `commitment(root, domain)` equals the public commitment before saying anything about the value. The field identifier is public, so a statement about one field cannot be presented as a statement about another.

`predicate_compare` proves `minimum <= value <= maximum` inclusive, with both bounds public. One circuit covers over, under and between, since a one sided bound is a range with the other end at its extreme. It refuses any value that does not fit one element and any element that does not fit a `u64`, the width of the bounds, so it applies to the date fields and not to packed text.

`predicate_member` proves `set_entry(data)` sits in a Merkle tree the verifier publishes, at a private index with an eight level path, which holds up to 256 entries and covers a list of issuing states or nationalities. Only the root is public, so the verifier learns that the value is in the list and not which entry it is.

`predicate_reveal` discloses the field: `revealed [Field; 4]` and `revealed_length` are public and must equal the opening. Its public input vector is nine field elements, the widest in the set.

None of the three says which document it is about. That comes only from the verifier checking the referenced commitment against one an attribute proof published. A predicate proof presented alone is worthless. Nor does any of them attach meaning to `field_id`: the mapping from identifier to field is fixed in `lib/attributes`, and which mapping applies depends on which attribute variant produced the commitment, which the verifier knows from the verification key it accepted.

### 2.5 nullifier_document_number

Package `bin/nullifier/document_number`, over `lib/nullifier`, `lib/predicate`, `lib/policy`, `lib/commit`.

Private: two field openings plus `secret Field`. Public: `commitment`, `secret_binding`, `domain`, `context`, then the returned nullifier. Five field elements.

It requires the first opening to be `field_id` 2 and the second to be 3, opens both against the commitment, asserts `secret_binding(secret, domain)` equals the value the Passive Authentication proof published, and returns a Poseidon2 hash over the policy identifier `DOCUMENT_NUMBER_V1`, the packed issuing state and document number, the secret and the domain.

The secret exists to close an enumeration oracle. Without it the value would be a hash of a public policy identifier, a public domain and fields printed on the data page, so anyone holding a copy of a document could compute its holder's value for any application and test whether that person had registered. The secret used is derived from the Security Object signature, which is fixed at issuance, so the prover cannot choose it and register twice, and which is not printed, so it cannot be read off a photocopy. It never becomes public: Passive Authentication publishes a domain scoped binding, and this circuit proves it holds a matching preimage.

What it does not give is stability across reissue. A replacement document carries a different signature and usually a different number, so it produces a different value. `lib/policy` names two other policies, `MRZ_STABLE_V1` and `NATIONAL_IDENTIFIER_V1`, under the families `FAMILY_MRZ_STABLE` and `FAMILY_NATIONAL_IDENTIFIER`, and no circuit implements either.

The policy identifier is a constant in `lib/policy` that `lib/nullifier` hashes in directly. It is not a public input, whatever the header of `lib/policy` says, so the circuit identity is what tells a verifier which uniqueness guarantee it received. `policy::assert_supported` exists and no circuit calls it; only its own unit tests do. An application must fix exactly one policy per domain: accepting two lets one holder present two different values and defeats the point.

### 2.6 anchor_dsc_inclusion and anchor_csca_chain_rsa2048_sha256_tbs512

Passive Authentication proves a key signed the document. Whether that key belongs to a state is a separate question, and these two circuits are the two ways of answering it. Both are optional, both return the same `dsc_commitment` the Passive Authentication circuit returns, and the tie in each case is that equality, which the verifier checks and which requires the prover to use the same private salt in both proofs. Since the commitment is a Poseidon2 hash of the key hash and the salt, equality implies the same key hash and the same salt, short of a Poseidon2 collision. For the RSA variant that key hash is `modulus_hash`, which folds every limb, so equality pins the modulus as well. Both anchor circuits are also the only ones that assert `domain != 0` as well as `context != 0`.

`bin/anchor/dsc_inclusion`, over `lib/anchor` and `lib/commit`, is the cheap mode. Private: `pubkey_x [u8; 32]`, `pubkey_y [u8; 32]`, `salt Field`, `index u32`, `siblings [Field; 16]`. Public: `registry_root`, `domain`, `context`, then the returned `dsc_commitment`. Four field elements, the narrowest in the set. It proves `pubkey_hash(pubkey_x, pubkey_y)` is a leaf of a depth sixteen Merkle tree with the published root, and nothing else. It verifies no signature and reads no certificate. What it assumes is that whoever built the set checked the certificates behind it.

`bin/anchor/csca_chain_rsa2048_sha256_tbs512`, over `lib/anchor`, `lib/x509`, `lib/rsa`, `lib/hash` and `lib/commit`, removes that assumption. Private: `tbs [u8; 512]`, `tbs_len u32`, `public_key_offset u32`, `not_before_offset u32`, `not_after_offset u32`, `authority_modulus [u128; 18]`, `authority_redc [u128; 18]`, `authority_signature [u128; 18]`, `authority_index u32`, `authority_siblings [Field; 8]`, `salt Field`. Public: `master_list_root`, `current_yyyymmdd u32`, `domain`, `context`, then the returned `dsc_commitment`. Five field elements.

It verifies an RSA PKCS#1 v1.5 signature by the authority over SHA-256 of the certificate body, asserts through `x509::assert_valid_at` that `current_yyyymmdd` falls inside the certificate validity period, asserts that `commit::modulus_hash` of the authority modulus is a leaf of a depth eight Merkle tree with the published master list root, and then reads the subject public key out of the signed body and commits to it. Reading the key out of the certificate rather than taking it as an input is what makes the commitment a commitment to the key the authority actually certified.

What stays trusted in this mode is the list of country signing keys. That list is the anchor of the system and cannot be derived from a document, so it has to come from outside.

What neither mode proves. Neither checks revocation. Neither checks issuer or subject names, key usage, or any certificate extension. The inclusion mode checks no validity period at all, and the chain mode checks only the Document Signer certificate's own period against a date the verifier supplies, not the authority certificate's. Offsets into the certificate body are supplied rather than searched for; the structure at each offset is constrained and the authority signature covers the whole encoding, so a wrong offset fails and no offset reaches outside what was signed, which is the same argument the data group extraction circuit rests on.

One pairing limit follows from the types. `x509::ec_public_key` is generic over the coordinate width and the chain anchor instantiates it at 32 bytes, so that mode reads an uncompressed elliptic curve point out of the certificate and commits to it through `pubkey_hash`. The RSA Passive Authentication variant derives its key hash with `modulus_hash` instead, and nothing in the chain mode can read an RSA subject key out of a certificate. There is therefore no combination today that chains an RSA Document Signer key to a country signing key, even though both halves exist. The inclusion mode carries the matching gap: it takes two 32 byte coordinate arrays, so a registry of RSA signer keys has no circuit to consume it, and `modulus_hash` is what such a registry would build leaves from.

### 2.7 probe

`probe/` compiles against every pinned dependency so that a successful workspace compile proves the dependency graph resolves under the pin. It verifies nothing about the protocol and is not part of any proving flow.

## 3. Why the signature check and the extraction are separate circuits

They are separate because a document normally needs more than one data group, and folding the extraction into the signature circuit would repeat the signature check for each one. The signature check dominates the cost of a proof.

Measured with `nargo info` under the pinned compiler. Every figure below was reproduced at this revision, and each also appears in the commit that introduced the circuit: `60f7fef` for the first eight, `613231b` for `anchor_dsc_inclusion`, `ae0a9c8` for the RSA variant, `6244f20` for the chain anchor.

| Circuit | ACIR opcodes |
|---|---|
| sod_ecdsa_p256_sha256_ec512 | 35096 |
| sod_rsa2048_v15_sha256_ec512 | 8719 |
| anchor_csca_chain_rsa2048_sha256_tbs512 | 6807 |
| dg_extract_sha256_ec512 | 3299 |
| attributes_mrz_td1_sha256 | 2447 |
| attributes_mrz_td3_sha256 | 2101 |
| anchor_dsc_inclusion | 340 |
| predicate_member | 228 |
| predicate_compare | 121 |
| predicate_reveal | 98 |
| nullifier_document_number | 56 |

Commit `8bfd6d1` recorded the same pair one change earlier, at the same 512 byte buffer: 35080 for the signature circuit and 3297 for the extraction. The extraction circuit re-hashes the same 512 byte buffer, which is what re-deriving `econtent_binding` costs instead of verifying the signature again.

The ratio is the argument. Against the extraction circuit, Passive Authentication costs about two and a half times as much in the RSA variant and about eleven times as much in the curve variant. Against the four circuits a verifier uses to ask a question, the curve variant costs between 154 and 627 times as much, and the RSA variant between 38 and 156 times. Asking one more question of a document that has already been authenticated costs between 56 and 228 opcodes.

The two Passive Authentication figures are also worth reading against each other. RSA is four times cheaper than ECDSA here, which inverts the usual expectation, and the reason is recorded in commit `ae0a9c8`: verifying RSA with a small exponent is seventeen modular multiplications, while an ECDSA verification is two scalar multiplications over a curve whose field is not the proving field, so it pays for non native arithmetic throughout.

Commit `c9a27c9` recorded end to end numbers for the Passive Authentication circuit on the author's machine, at a time when that circuit had four public inputs rather than the five it has now: proving 1.9 seconds, proof 16000 bytes, public inputs 128 bytes for four field elements, verification key 3680 bytes. Those figures come from one machine and one revision and should be re-measured before being relied on.

## 4. Derived values

Every binding value, leaf format and salt convention lives in `lib/commit`, and no circuit re-derives them. All are Poseidon2. Each starts with a role tag so a value produced for one role cannot stand in for another. The header of that library states a second rule on top of the tags: Merkle internal nodes are the single untagged hash and are two wide, while every tagged value is three wide or more, which is what stops a leaf or a seed being read as an internal node.

| Value | Formula | Tag |
|---|---|---|
| `econtent_binding` | H(1, hash_hi, hash_lo, domain) | 1 |
| `dg_binding` | H(2, hash_hi, hash_lo, domain) | 2 |
| `dsc_commitment` | H(3, pubkey_hash, salt) | 3 |
| `leaf` | H(4, field_id, length, d0, d1, d2, d3, entropy) | 4 |
| `entropy_seed` | H(5, dg_hi, dg_lo, domain, session_salt) | 5 |
| `commitment` | H(6, root, domain) | 6 |
| `nullifier` | H(7, policy_id, p0, p1, p2, p3, secret, domain) | 7 |
| `field_entropy` | H(8, seed, field_id) | 8 |
| `pubkey_hash` | H(9, x_hi, x_lo, y_hi, y_lo) | 9 |
| `set_entry` | H(10, d0, d1, d2, d3) | 10 |
| `document_secret` | H(11, r_hi, r_lo, s_hi, s_lo) | 11 |
| `secret_binding` | H(12, secret, domain) | 12 |
| `modulus_hash` | fold of H(accumulator, limb) from 9 | 9 |
| internal node | H(left, right) | none |

`entropy_seed` rejects a zero salt and `nullifier` rejects a zero secret; both are the only zero checks in the library.

`modulus_hash` is the one entry that does not follow the shape rule the header of `lib/commit` states. It is a chain of two wide hashes seeded with `TAG_DSC_KEY`, so its intermediate values have exactly the form of Merkle internal nodes, and its output shares a tag with `pubkey_hash` while being built differently. Two things stand between that and a confusion attack on the master list tree. Each fold step hashes `limbs[i] as Field`, a value cast from `u128` and therefore below 2^128, while an internal node takes a general field element on both sides. And every master list leaf is a fold from the same fixed seed, so matching an internal node would require a preimage rather than a choice of input. The invariant that made this reasoning unnecessary no longer holds for this value, which is reason enough to read it again before the master list format is fixed.

`hash32_to_fields` splits a 32 byte digest into two big endian halves of 16 bytes. `pack_pair` splits two equal length byte strings in half and packs each half into one element, requiring an even length and at most 31 bytes per half. `normalize::pack_to_4` packs up to 124 bytes big endian into four elements of 31 bytes each.

Two properties of this table matter when integrating. Every derived value a verifier stores or compares across sessions takes `domain`, so the same document produces different values under different applications, and a binding from one domain cannot be chained to a proof from another. Disclosed values are not scoped that way: `predicate_reveal` publishes the field itself, so a holder who reveals the same field to two applications links those sessions whatever the domain. And there is one exception among the derived values: `dsc_commitment` takes a salt but not a domain. A holder who reuses one random salt across applications publishes an equal value in both, which links those sessions. A fresh salt per session avoids that. The zero salt is a deliberate convention for the case where the verifier compares the commitment against a table it precomputes from a public registry, and it gives up hiding: with a zero salt the commitment identifies the signer to anyone with the registry.

## 5. Variants

Circuit names encode the dimensions a circuit cannot be generic over. A Noir circuit is fixed size, so a buffer is part of the circuit identity, and the algorithm a document was signed with is part of the arithmetic.

Passive Authentication names three dimensions, `sod/<signature algorithm>_<CMS digest algorithm>_ec<eContent buffer bytes>`, where the first token carries whatever the algorithm needs to be pinned down: `ecdsa_p256` is a curve, `rsa2048_v15` is a modulus size and a padding scheme. Data group extraction names two, `dg_extract/<data group hash algorithm>_ec<eContent buffer bytes>`. Attribute profiles name the data group and layout plus the data group hash algorithm, `attributes/mrz_<layout>_<algorithm>`. Anchors name the mode first and then whatever that mode needs: inclusion needs nothing, while the chain mode names the authority algorithm, the digest and its certificate body buffer, `anchor/csca_chain_<authority algorithm>_<digest>_tbs<certificate buffer bytes>`. The predicates and the nullifier have no algorithm dimension at all, since they operate on committed field elements; the nullifier names its policy instead.

Doc 9303 allows the CMS digest algorithm and the Security Object data group hash algorithm to differ, which is why `lib/hash` treats them as separate dimensions rather than one.

Variants that exist today:

| Package | Notes |
|---|---|
| `sod/ecdsa_p256_sha256_ec512` | ECDSA over P-256 |
| `sod/rsa2048_v15_sha256_ec512` | RSA-2048, PKCS#1 v1.5, exponent 65537 only |
| `dg_extract/sha256_ec512` | the only extraction variant |
| `attributes/mrz_td3_sha256` | passport layout |
| `attributes/mrz_td1_sha256` | card layout |
| `predicate/compare`, `predicate/member`, `predicate/reveal` | no variants |
| `nullifier/document_number` | one policy |
| `anchor/dsc_inclusion` | published set of signer keys, depth sixteen |
| `anchor/csca_chain_rsa2048_sha256_tbs512` | RSA-2048 authority, master list depth eight |

Not every fixed size is in a name. The Passive Authentication circuit fixes `signed_attrs` at 256 bytes and the attribute circuits fix the DG1 buffer at 128 bytes; neither appears in the package name. The membership tree depth of eight, the signer registry depth of sixteen and the master list depth of eight are likewise fixed in the circuit and absent from the name. If a second size of either is ever needed, the naming scheme has to grow before the package does.

A relying party pins the variant by verification key. `Policy::accepted_keys` in the prover maps a circuit kind to the key hashes it accepts, and a proof from any other variant is rejected before its public values are looked at. This is what prevents an algorithm downgrade, and it is also the only thing that distinguishes a TD3 attribute proof from a TD1 one, since the two share an ABI and a circuit kind in the verifier.

## 6. The two verification models

### 6.1 Off-chain: verify each proof, then check the bindings

This is the model that exists. `verify_bundle` in `prover/src/verify.rs` implements it once so that an integration does not carry its own copy of the rules. The crate has no dependencies and does not reimplement proof verification: it shells out to the `bb` binary, the same prover that produced the proof, writing the verification key, the proof and the serialized public inputs to a temporary directory and running `bb verify`. Public inputs are 32 byte big endian elements concatenated in layout order.

A relying party supplies a `Policy`: its `domain`, the `context` it issued for this exchange, the accepted verification key hashes per circuit kind, and optionally a required registry root for the trust anchor.

The order is fixed, and cryptographic verification comes first so that a rejection has a stated reason rather than resting on one proof.

1. Reject immediately if the policy `context` is zero.
2. For each proof in the bundle, in order: reject if its verification key hash is not on the accepted list for its circuit kind, reject if `bb verify` fails, reject if its `domain` differs from the policy domain, reject if its `context` differs from the policy context. Passive Authentication proofs are collected while passing.
3. Require exactly one Passive Authentication proof. Zero means nothing establishes the document was signed; more than one means the bundle describes more than one document.
4. Every data group extraction proof must carry the `econtent_binding` that proof published. Collect the `dg_binding` each one returns.
5. Every attribute proof must carry a `dg_binding` collected in step 4. Collect the commitment each one returns.
6. Every compare, member and reveal proof must reference a commitment collected in step 5. Reveal proofs contribute their `field_id` and revealed value to the result.
7. A nullifier proof must reference a commitment collected in step 5 and must carry the same `secret_binding` the Passive Authentication proof published. Its value becomes the bundle nullifier.
8. Every anchor proof, of either mode, must carry a `dsc_commitment` equal to the one the Passive Authentication proof published, and if the policy fixes a root, its first public input must equal that root. That input is the registry root in the inclusion mode and the master list root in the chain mode, and the checklist treats them identically, so a policy that fixes a root also fixes which mode can satisfy it.
9. If the policy requires a trust anchor and no anchor proof was seen, reject.

The result is the nullifier if one was present, the `dsc_commitment`, the disclosed fields as identifier and value pairs, and the registry root the signer was shown to belong to if an anchor proof was present.

Nothing in `verify.rs` is covered by a test. The crate's 12 unit tests live in `field.rs` and `layout.rs`, and the checklist above has no test module of its own.

What `verify_bundle` deliberately does not do, and what a relying party must therefore do itself:

- Check that `current_yyyymmdd` on an attribute proof is actually today. The accessor `attributes_current_date` exists and the checklist never calls it. A stale date moves a century boundary.
- Check the `current_yyyymmdd` a chain anchor proof was made against, at public input index 1. There is no accessor for it in `layout.rs` and the checklist does not read it, so an expired Document Signer certificate passes if the prover supplies a date at which it was still valid.
- Check that `dg_number` on an extraction proof is the data group it asked about. The accessor exists and is unused by the checklist.
- Check that `field_id`, `minimum`, `maximum` and `set_root` on predicate proofs are the values it asked for. There is no accessor for `minimum`, `maximum` or `set_root` at all, and the checklist reads `field_id` only on reveal proofs, to label the output.
- Do the nullifier bookkeeping. The checklist returns the value and stores nothing. It also puts no cap on how many nullifier or anchor proofs a bundle carries, unlike the Passive Authentication proof it requires exactly one of; with several, each is checked but the last one seen supplies the reported value.
- Issue a fresh `context` per exchange and never accept a reused one. Nothing inside a circuit can enforce freshness; the circuits only reject zero.
- Decide whether a bundle without an anchor proof is acceptable. Without one, the bundle establishes that some key signed the document and nothing about whose key it is.

### 6.2 On-chain by recursive aggregation: not implemented

The intended second model is to fold the bundle into one proof by recursive verification, so that a chain verifies a single proof and a single set of public inputs instead of a bundle plus a checklist. None of it exists. There is no aggregation circuit, no circuit calls a recursive verification opcode, and there is no Solidity or other on-chain verifier anywhere in either repository. Nothing in this document should be read as describing an on-chain deployment path that can be built against today.

## 7. What is not implemented

Signature algorithms. Two variants exist, ECDSA over P-256 and RSA-2048 with PKCS#1 v1.5 and exponent 65537. Nothing else can be proved. RSA-3072 and RSA-4096 have no variant, RSA-PSS has no implementation at all, and the public exponent is fixed at 65537 in the arithmetic, so a key that uses any other exponent cannot be proved. `lib/sig` exposes wrappers for P-384 and Brainpool P-384r1 that no circuit instantiates.

Digest algorithms. `lib/hash` exposes SHA-256 and nothing else. SHA-1 appears only in the build probe. Documents whose CMS digest or data group hashes use any other algorithm are out of reach, and the variant naming has room for them but the packages do not exist.

Document layouts. `lib/mrz` implements TD1 and TD3. Doc 9303 also defines TD2, which is not implemented. No profile exists for any data group other than DG1, so nothing reads a portrait, a state specific group such as DG13, or anything else, even though the extraction circuit will extract any data group number from 1 to 16.

Trust. The chain mode verifies one link, an RSA-2048 country signing signature over an elliptic curve Document Signer certificate. It does not walk further, does not check revocation, does not read names or extensions, and cannot certify an RSA Document Signer key, so the RSA Passive Authentication variant has no chain anchor to pair with. Beyond that link the list of country signing keys is trusted input, which is unavoidable and is what a master list is.

Chip presence. Nothing here proves a document was read from a genuine live chip. There is no Active Authentication or Chip Authentication circuit, and no equivalent. Every proof is over data a holder supplies, so a copy of a chip's data produces proofs indistinguishable from the original. This is a property of Passive Authentication, and the system inherits it.

Recursion and on-chain verification, as described in 6.2.

Supporting code. `lib/tlv` implements DER length decoding with minimality checks, is a workspace member, and no package depends on it; the structure checks that ship are fixed offset byte comparisons in `lib/lds`, `lib/cms`, `lib/attributes` and `lib/x509`. `policy::assert_supported` and `normalize::pack_alpha3` are called only by their own unit tests. Witness preparation does not exist as code: `lib/sig` documents that a caller has to normalize `s` to `n - s` when it exceeds `n/2`, and the only implementation of that rule is `ec::normalize_s` in the Rust fixture generator that builds synthetic documents. The prover crate verifies and does not prove; the noir_rs and Barretenberg pins in `TOOLCHAIN.md` are recorded as intended and are not exercised.

Real documents. Every fixture in `lib/testdata` is generated by `fixtures/generator`, which builds synthetic Doc 9303 material over the specimen machine readable zones from the standard: DG1, a Security Object, CMS signed attributes, a signature under a generated Document Signer key, and a Document Signer certificate signed by a generated country signing key. No test in either repository runs against a document issued by a state.

The repository was bootstrapped on 2026-07-23 and the pinned revision is from 2026-07-25, so the whole set above is two days of work and is still growing. Two gaps this document originally listed as absent, RSA Passive Authentication and country signing certificate verification, were filled while it was being written. Re-read the inventory against the revision you are auditing.

## 8. Obligations on the prover

These follow from the circuits and are not enforced by them.

Use the same `domain` in every proof of a bundle. The bindings are domain scoped, so a mismatch breaks the chain cryptographically as well as failing the verifier's check.

Use the `context` the verifier issued, and never zero.

Use one salt value for both the `dsc_salt` of the Passive Authentication proof and the `salt` of the anchor proof, or the two commitments will not match. Use a fresh one per session unless the zero salt registry convention is deliberate, since a reused random salt is a value that links sessions.

Use a fresh non-zero `session_salt` per attribute proof. It is the only hiding input in the commitment chain.

Normalize ECDSA `s` to `n - s` when it exceeds `n/2` before building the witness. The backend aborts otherwise.

For the RSA variant, compute the Barrett reduction parameter the bignum backend takes alongside the modulus. Commit `ee6387b` records it as `floor(2^(2 * MOD_BITS + 6) / n)` and notes that the fixture generator carries a small big integer implementation because no shell tool exposes that division.

Compute `document_secret` from the same normalized signature the Passive Authentication proof used, since the nullifier circuit checks it against the binding that proof published.

## 9. State of the test suite

Re-run at this revision: `nargo test` reports 118 tests passing across the 30 workspace packages, matching the count commit `6244f20` records, and `cargo test` in `fixtures/generator` reports 17. The prover crate has 12 unit tests. They live in `field.rs` and `layout.rs`; `verify.rs`, which holds the whole checklist, has no test module, so the binding rules in section 6.1 are unexercised by any test.

The circuit tests cover both layouts end to end and rejections for a swapped signature, swapped signed attributes, a signature over another Security Object with the digest link repaired, a Security Object that was not the authenticated one, an entry read as the wrong data group, a card layout read as a passport, an opening from another document, a field claimed under another identifier, a value outside a published set, a disclosure that does not match, a secret the prover invented, openings supplied in the wrong order, a signer outside the published set, a tampered certificate, an expired certificate, an authority outside the published list, and an unset session context. That last case is tested in four circuits of the eleven, `attributes_mrz_td3_sha256`, `predicate_compare`, `anchor_dsc_inclusion` and `anchor_csca_chain_rsa2048_sha256_tbs512`, although all eleven contain the assertion.

CI in the circuits repository runs `nargo fmt --check`, `nargo compile` and `nargo test` on the pinned compiler. CI in the prover repository runs `cargo build --all-targets`, `cargo fmt --check` and `cargo test`.
