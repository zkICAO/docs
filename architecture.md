# zkICAO architecture

## Scope of this document

This describes the circuit set as it exists in code, not a design that is planned. Every statement below was checked against the source at these revisions:

| Repository | Revision | Contents |
|---|---|---|
| zkICAO/circuits | the revision this document sits beside | 17 library packages, 17 circuits, 5 witness tools |
| zkICAO/prover | `0c7e2f0` | the off-chain verifier, `verify_bundle` |
| toolchain | nargo 1.0.0-beta.19 | pinned in `TOOLCHAIN.md` |

`5257a48`, which added the chain walking registration variant, is the last commit that changed a circuit. The on chain half lives in a fifth repository, zkICAO/contracts, described in section 6.2. The repository is under active development and the set grows faster than a document can track. Check the revision before relying on the inventory here. What is stable is the shape: the linkage between circuits, the derived value formats, and the verification procedure.

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

Packages `bin/sod/ecdsa_p256_sha256_ec512` and `bin/sod/rsa2048_v15_sha256_ec512`, over `lib/emrtd/sod`, `lib/emrtd/cms`, `lib/core/hash`, `lib/core/commit`, plus `lib/core/sig` or `lib/core/rsa` for the signature step. `lib/emrtd/sod` is generic over the buffer sizes and splits the shared linking (`link`) from the signature check, so a variant supplies only its own algorithm.

Both variants take `econtent [u8; 512]`, `econtent_len u32`, `signed_attrs [u8; 256]`, `signed_attrs_len u32`, `digest_offset u32` and `dsc_salt Field` privately, and differ only in the key and signature witnesses. The curve variant takes `pubkey_x [u8; 32]`, `pubkey_y [u8; 32]`, `signature_r [u8; 32]`, `signature_s [u8; 32]`. The RSA variant takes `modulus_limbs [u128; 18]`, `redc_limbs [u128; 18]` and `signature_limbs [u128; 18]`.

Both publish the same five field elements in the same layout order: `domain`, `context`, `econtent_binding`, `dsc_commitment`, `secret_binding`. They are interchangeable to everything downstream, and a verifier tells them apart only by verification key.

What they prove, from `sod::link` and `sod::outputs`:

1. SHA-256 over the first `econtent_len` bytes of `econtent` equals the 32 bytes at `digest_offset` in `signed_attrs`, where `cms::message_digest_sha256` has checked that the 11 bytes beginning 15 bytes before that offset are the messageDigest OID encoding, that byte `digest_offset - 4` is `0x31`, and that bytes `digest_offset - 2` and `digest_offset - 1` are `0x04 0x20`.
2. The signature verifies over SHA-256 of the first `signed_attrs_len` bytes of `signed_attrs`. In the curve variant that is an ECDSA P-256 verification, and the wrapper in `lib/core/sig` calls `validate_in_field` on all four decoded values first, since byte deserialization in noir-bignum only bounds a value by `2^MOD_BITS`. In the RSA variant it is PKCS#1 v1.5: the signature is raised to 65537 as sixteen squarings and one multiply, and the recovered encoding is checked byte for byte, the leading `00 01`, every `FF` of the padding run, the `00` separator, the 19 byte SHA-256 DigestInfo prefix and the digest. Constraining the whole padding run is what stops a forger placing the DigestInfo at another offset. Only the exponent 65537 is accepted. `redc_limbs` is a Barrett reduction hint for the runtime modulus. The header of `lib/core/rsa` states that the bignum backend constrains every multiplication against it, so a wrong hint cannot make a bad signature verify; that is a property of the pinned dependency and nothing here checks it.
3. The three outputs are derived: `econtent_binding` over the Security Object hash and `domain`, `dsc_commitment` over the key hash and the private `dsc_salt`, `secret_binding` over the document secret and `domain`.

What they do not prove. Neither parses the Security Object: no LDS structure, version, or data group list is read here. Neither checks any signed attribute other than messageDigest, so contentType, eContentType and signingTime are unconstrained. Neither checks that `signed_attrs` starts with the DER SET tag or that `signed_attrs_len` is its true DER length; the only defence there is that changing those bytes changes the digest the signature covers. Above all neither proves the key belongs to a Document Signer. The key is a witness, and nothing here reads a certificate; that is a separate proof, section 2.6. On its own, this proof says a key signed the document, not whose key it was. It says nothing about expiry, revocation, or whether the data came from a live chip.

The public key stays private and only a salted commitment leaves, so that a trust proof can match a registry without revealing which signer, and therefore which issuing state and batch, produced the document.

The two algorithms carry their key and signature in different shapes, and `commit` has a helper for each. `pubkey_hash` and `document_secret` take a curve point or a signature pair through `pack_pair`, which asserts each half is at most 31 bytes. `modulus_hash` and `limbs_document_secret` take a number as limbs and fold every one of them, then finish with a three wide hash carrying the role tag and the limb count. `sod::outputs` takes both values already hashed, so the variant that knows its algorithm chooses the helper and no caller can pass a value in a shape that drops part of it.

An earlier revision did drop part of it. The RSA variant reshaped a modulus into two 32 byte halves by keeping three bytes of each limb, which committed to 432 bits of 2048 and made `dsc_commitment` an identifier for a sample rather than for the key. Nothing was exploitable at that width, and it was corrected in `98d7611`.

One consequence of the low-s rule in `lib/core/sig` matters for anyone deriving values from the signature. The header of `lib/core/sig` records that the ECDSA backend rejects `s` above `n/2` and aborts rather than returning false, so the only witness that can prove at all carries the normalized form. In the curve variant `document_secret` is therefore computed over a canonical `(r, s)` and does not depend on which of the two equivalent encodings the chip happened to store.

### 2.2 dg_extract_sha256_ec512

Package `bin/dg_extract/sha256_ec512`, over `lib/emrtd/dg_extract`, `lib/emrtd/lds`, `lib/core/hash`, `lib/core/commit`.

Private: `econtent [u8; 512]`, `econtent_len u32`, `oid_offset u32`, `dg_offset u32`.

Public: `dg_number u8`, `econtent_binding`, `domain`, `context`, then the returned `dg_binding`. Five field elements.

It re-hashes the Security Object, derives `econtent_binding` the same way the Passive Authentication circuit did, and asserts it equals the public one. That equality is the whole link to the signature: this circuit does not verify a signature. It then asserts the 11 bytes at `oid_offset` are the SHA-256 algorithm OID encoding, and that the 39 bytes at `dg_offset` are `30 25 02 01 <dg_number> 04 20` followed by 32 bytes, with `dg_number` between 1 and 16. It returns `dg_binding` over those 32 bytes and `domain`.

`dg_number` is public so the verifier states which data group the proof is about instead of trusting the prover to say afterwards.

What it does not prove is documented in the header of `lib/emrtd/lds` and is worth repeating. `dg_entry_sha256` checks the header bytes sitting at the offset it is given and nothing about how that offset was reached. It does not walk the Security Object from its start, so it cannot distinguish a genuine entry from any other byte sequence in the buffer with the same seven header bytes. Both offsets are private and independent, so nothing ties the algorithm identifier at `oid_offset` to the entry at `dg_offset`. The argument that this is still safe is that every byte read lies inside a buffer whose hash matches the authenticated `econtent_binding`, so a prover who finds a matching pattern only obtains data the issuer signed. A circuit that needs a stronger guarantee has to establish the offset itself, and none does.

### 2.3 attributes_mrz_td3_sha256 and attributes_mrz_td1_sha256

Packages `bin/attributes/mrz_td3_sha256` and `bin/attributes/mrz_td1_sha256`, over `lib/emrtd/attributes`, `lib/emrtd/mrz`, `lib/core/normalize`, `lib/core/hash`, `lib/core/commit`. TD3 is the passport layout, two lines of 44 characters. TD1 is the card layout, three lines of 30.

Private: `dg1 [u8; 128]`, `dg1_len u32`, `session_salt Field`.

Public: `dg_binding`, `current_yyyymmdd u32`, `domain`, `context`, then the returned `commitment`. Five field elements.

The circuit asserts the DG1 template is `61 <len> 5F 1F <mrz_len>` with `dg1_len == 5 + mrz_len` and `len == mrz_len + 3`, hashes DG1, and asserts the resulting `dg_binding` equals the public one. It then validates the MRZ check digits under the 7-3-1 weighting, accepting the filler character where Doc 9303 puts one in place of a check digit, which is the document number position in both layouts and the optional data position in TD3, resolves both dates to `YYYYMMDD` integers with calendar validation including leap years, and builds a 16 leaf Poseidon2 Merkle tree whose root, hashed with the domain, becomes the commitment.

Nine fields are populated, at leaf index `field_id - 1`: document code 1, issuing state 2, document number 3, nationality 4, birth date 5, sex 6, expiry date 7, name 8, optional data 9. Leaves 10 to 16 carry length zero and empty data. Each leaf carries per-field entropy derived from `entropy_seed`, which mixes the data group hash, the domain and the private `session_salt`, and which rejects a zero salt. That salt is the only hiding input in the chain: without it the commitment is a deterministic function of DG1, which is the printed machine readable zone, and anyone holding a photocopy of the data page could recompute a holder's commitment for a domain.

Nothing is published except the commitment. Dates in particular are read to build it and never leave.

`current_yyyymmdd` is public because it decides the century a two digit birth year resolves to. A prover free to choose it could move a birth date by a century. The circuit does not and cannot check that this value is today's date, which is the verifier's job.

Known limits of the profile. The template parse is fixed offset and short form only, which is sufficient because both layouts produce a length below 0x80 but would not extend to a longer data group. The TD1 profile commits `TD1_OPTIONAL2` only, and a comment in `lib/emrtd/attributes` records that as the deliberate choice; the first optional data field of the card layout has no constant, because nothing reads it. Check digits detect transcription mistakes and not tampering: a test in `lib/emrtd/mrz` named `check_digits_miss_multiple_of_ten_substitutions` documents that substituting a character whose value differs by a multiple of ten leaves every check digit unchanged. Integrity of the MRZ rests entirely on the signature over DG1, not on the check digits.

### 2.4 predicate_compare, predicate_member, predicate_reveal

Packages under `bin/predicate/`, over `lib/claims/predicate` and `lib/core/commit`. Each takes a `FieldOpening` of `field_id`, `length`, `data [Field; 4]`, `entropy` and `siblings [Field; 4]`, rebuilds the leaf, walks it to the root at index `field_id - 1`, and asserts `commitment(root, domain)` equals the public commitment before saying anything about the value. The field identifier is public, so a statement about one field cannot be presented as a statement about another.

`predicate_compare` proves `minimum <= value <= maximum` inclusive, with both bounds public. One circuit covers over, under and between, since a one sided bound is a range with the other end at its extreme. It refuses any value that does not fit one element and any element that does not fit a `u64`, the width of the bounds, so it applies to the date fields and not to packed text.

`predicate_member` proves `set_entry(data)` sits in a Merkle tree the verifier publishes, at a private index with an eight level path, which holds up to 256 entries and covers a list of issuing states or nationalities. Only the root is public, so the verifier learns that the value is in the list and not which entry it is.

`predicate_reveal` discloses the field: `revealed [Field; 4]` and `revealed_length` are public and must equal the opening. Its public input vector is nine field elements, the widest in the set.

None of the three says which document it is about. That comes only from the verifier checking the referenced commitment against one an attribute proof published. A predicate proof presented alone is worthless. Nor does any of them attach meaning to `field_id`: the mapping from identifier to field is fixed in `lib/emrtd/attributes`, and which mapping applies depends on which attribute variant produced the commitment, which the verifier knows from the verification key it accepted.

### 2.5 nullifier_document_number

Package `bin/nullifier/document_number`, over `lib/claims/nullifier`, `lib/claims/predicate`, `lib/claims/policy`, `lib/core/commit`.

Private: two field openings plus `secret Field`. Public: `commitment`, `secret_binding`, `domain`, `context`, then the returned nullifier. Five field elements.

It requires the first opening to be `field_id` 2 and the second to be 3, opens both against the commitment, asserts `secret_binding(secret, domain)` equals the value the Passive Authentication proof published, and returns a Poseidon2 hash over the policy identifier `DOCUMENT_NUMBER_V1`, the packed issuing state and document number, the secret and the domain.

The secret exists to close an enumeration oracle. Without it the value would be a hash of a public policy identifier, a public domain and fields printed on the data page, so anyone holding a copy of a document could compute its holder's value for any application and test whether that person had registered. The secret used is derived from the Security Object signature, which is fixed at issuance, so the prover cannot choose it and register twice, and which is not printed, so it cannot be read off a photocopy. It never becomes public: Passive Authentication publishes a domain scoped binding, and this circuit proves it holds a matching preimage.

What it does not give is stability across reissue. A replacement document carries a different signature and usually a different number, so it produces a different value. One policy is implemented and one identifier exists; a second family would take the next free number under the `family * 1000 + version` scheme. Earlier revisions reserved identifiers for two policies that had no derivation, which promised guarantees the library could not make, and one of them, stability across reissue, cannot be built on a secret that changes on reissue at all.

The policy identifier is a constant in `lib/claims/policy` that `lib/claims/nullifier` hashes in directly. It is not a public input, and the library header says so, so the circuit identity is what tells a verifier which uniqueness guarantee it received. An application must fix exactly one policy per domain, which with the shipped circuits means accepting exactly one nullifier verification key: accepting two lets one holder present two different values and defeats the point.

### 2.6 anchor_dsc_inclusion and anchor_csca_chain_rsa2048_sha256_tbs512

Passive Authentication proves a key signed the document. Whether that key belongs to a state is a separate question, and these two circuits are the two ways of answering it. Both are optional, both return the same `dsc_commitment` the Passive Authentication circuit returns, and the tie in each case is that equality, which the verifier checks and which requires the prover to use the same private salt in both proofs. Since the commitment is a Poseidon2 hash of the key hash and the salt, equality implies the same key hash and the same salt, short of a Poseidon2 collision. For the RSA variant that key hash is `modulus_hash`, which folds every limb, so equality pins the modulus as well. Every circuit binary asserts `domain != 0` as well as `context != 0`; an earlier revision asserted the domain only here, which is why older text singles the anchors out.

`bin/anchor/dsc_inclusion`, over `lib/trust/anchor` and `lib/core/commit`, is the cheap mode. Private: `pubkey_x [u8; 32]`, `pubkey_y [u8; 32]`, `salt Field`, `index u32`, `siblings [Field; 16]`. Public: `registry_root`, `domain`, `context`, then the returned `dsc_commitment`. Four field elements, the narrowest in the set. It proves `pubkey_hash(pubkey_x, pubkey_y)` is a leaf of a depth sixteen Merkle tree with the published root, and nothing else. It verifies no signature and reads no certificate. What it assumes is that whoever built the set checked the certificates behind it.

`bin/anchor/csca_chain_rsa2048_sha256_tbs512`, over `lib/trust/anchor`, `lib/core/x509`, `lib/core/rsa`, `lib/core/hash` and `lib/core/commit`, removes that assumption. Private: `tbs [u8; 512]`, `tbs_len u32`, `public_key_offset u32`, `not_before_offset u32`, `not_after_offset u32`, `authority_modulus [u128; 18]`, `authority_redc [u128; 18]`, `authority_signature [u128; 18]`, `authority_index u32`, `authority_siblings [Field; 10]`, `salt Field`. Public: `master_list_root`, `current_yyyymmdd u32`, `domain`, `context`, then the returned `dsc_commitment`. Five field elements.

It verifies an RSA PKCS#1 v1.5 signature by the authority over SHA-256 of the certificate body, asserts through `x509::assert_valid_at` that `current_yyyymmdd` falls inside the certificate validity period, asserts that `commit::modulus_hash` of the authority modulus is a leaf of a depth ten Merkle tree with the published master list root, and then reads the subject public key out of the signed body and commits to it. Reading the key out of the certificate rather than taking it as an input is what makes the commitment a commitment to the key the authority actually certified.

What stays trusted in this mode is the list of country signing keys. That list is the anchor of the system and cannot be derived from a document, so it has to come from outside.

What neither mode proves. Neither checks revocation. Neither checks issuer or subject names, key usage, or any certificate extension. The inclusion mode checks no validity period at all, and the chain mode checks only the Document Signer certificate's own period against a date the verifier supplies, not the authority certificate's. Offsets into the certificate body are supplied rather than searched for; the structure at each offset is constrained and the authority signature covers the whole encoding, so a wrong offset fails and no offset reaches outside what was signed, which is the same argument the data group extraction circuit rests on.

One pairing limit follows from the types. `x509::ec_public_key` is generic over the coordinate width and the chain anchor instantiates it at 32 bytes, so that mode reads an uncompressed elliptic curve point out of the certificate and commits to it through `pubkey_hash`. The RSA Passive Authentication variant derives its key hash with `modulus_hash` instead, and nothing in the chain mode can read an RSA subject key out of a certificate. There is therefore no combination today that chains an RSA Document Signer key to a country signing key, even though both halves exist. The inclusion mode carries the matching gap: it takes two 32 byte coordinate arrays, so a registry of RSA signer keys has no circuit to consume it, and `modulus_hash` is what such a registry would build leaves from.

### 2.7 registration_mrz_td3_ecdsa_p256_sha256_ec512_inclusion

Package `bin/registration/mrz_td3_ecdsa_p256_sha256_ec512_inclusion`, over the `bb_proof_verification` library from the Barretenberg tree, pinned in `TOOLCHAIN.md`.

Private: the verification key and proof of one inner proof from each of `sod_ecdsa_p256_sha256_ec512`, `dg_extract_sha256_ec512`, `attributes_mrz_td3_sha256` and `anchor_dsc_inclusion`, as 115 and 500 field elements each, plus `econtent_binding`, `dsc_commitment`, `secret_binding`, `dg_binding`, `commitment`, `current_yyyymmdd` and `registry_root`. Public: `domain`, `context`, then the returned `commitment`, `secret_binding`, `current_yyyymmdd` and `registry_root`. Six field elements.

It verifies the four proofs inside the circuit. The equalities of section 6.1 are not checked here, they are forced: each linking value is one witness placed into the public inputs of every inner proof that carries it, so two inner proofs cannot disagree about it and still prove. The extraction's data group number is the constant 1, which the off chain checklist can only ask a caller to check.

The verification key hashes are compile time constants in a generated `keys.nr`, written by `cargo run -- keys` in the fixture generator and committed, the same arrangement as `layout.manifest`. The keys themselves are witnesses the backend constrains against those hashes. Substituting a proof from another circuit into a slot was tried, as was a linking value the inner proofs did not commit to, and both make the registration proof fail to verify.

It publishes deliberately less than the four proofs publish. `econtent_binding`, `dg_binding` and `dsc_commitment` only link the inner proofs to each other and stay private. Signer trust is established inside, so the proof exposes which registry was used and not the salted signer commitment.

The per session proofs are not aggregated: predicates and the nullifier travel beside a registration proof, in the bundle form section 6.1 describes.

One property of the backend has to be understood by anyone consuming this. Producing a proof does not check the witness: bb produces a registration proof over a forged inner proof without complaint, and the forgery surfaces only when the registration proof is verified. Proving is not the check; verification is. The bundle command verifies every proof it produces for this reason.

Measured at this revision, on the author's machine: one recursive verification proves in 4.0 seconds at a 1.8 GiB peak, two in 7.5 seconds at 3.5 GiB, and the four here take 14.4 seconds at a 6.6 GiB peak. The registration proof is 16000 bytes with the same 500 field element shape as its inputs, so it can itself be verified recursively.

A second variant, `registration_mrz_td3_ecdsa_p256_sha256_ec512_csca_chain`, puts `anchor_csca_chain_rsa2048_sha256_tbs512` in the anchor slot: the country signing key certified the signer, checked in circuit rather than assumed of a curated registry. One sharing does the work the off chain date rule does. The chain anchor validates the certificate at a date and the attribute circuit resolves two digit years at a date, and here they are the same witness placed into both public input arrays, so resolving a birth year against one day and certificate validity against another cannot prove. The master list root is exposed where the registry root is, the six field layout is identical, and a verifier tells the variants apart by verification key alone.

### 2.8 session_compare_member

Package `bin/session/compare_member`, over the same recursion library. The rule it implements: a session that asks one question presents the bare predicate, and a session that asks more than one aggregates them, because a second proof in a bundle costs a verification and an aggregated pair costs one.

Private: the verification key and proof of one `predicate_compare` and one `predicate_member` proof, plus `commitment`. Public: `compare_field_id`, `minimum`, `maximum`, `member_field_id`, `set_root`, `domain`, `context`, then the returned `commitment`. Eight field elements.

The commitment, the domain and the context are single witnesses placed into both inner public input arrays, so the two predicates cannot be about different documents, applications or sessions and still prove. The statement values stay public: a verifier reads them off this proof exactly as off the bare predicates, and the returned commitment links against a registration the way a predicate's referenced commitment does. Nine ACIR opcodes; the inner verification key hashes come from the same generated `keys.nr` arrangement.

### 2.9 tools/mrz_opening

`tools/mrz_opening` returns the value, blinding factor and Merkle path a predicate needs for one field, from the same derivation the attribute circuit runs. It is executed to solve a witness and never proved: a proof would publish exactly what the commitment exists to hide. It sits outside `bin/` so it is not mistaken for a circuit.

## 3. Why the signature check and the extraction are separate circuits

They are separate because a document normally needs more than one data group, and folding the extraction into the signature circuit would repeat the signature check for each one. The signature check dominates the cost of a proof.

Measured with `nargo info` under the pinned compiler. Every figure below was reproduced at this revision, and each also appears in the commit that introduced the circuit: `60f7fef` for the first eight, `613231b` for `anchor_dsc_inclusion`, `ae0a9c8` for the RSA variant, `6244f20` for the chain anchor.

| Circuit | ACIR opcodes |
|---|---|
| sod_ecdsa_p256_sha256_ec1024 | 38034 |
| sod_ecdsa_p256_sha256_ec512 | 35098 |
| sod_rsa2048_v15_sha256_ec1024 | 11036 |
| sod_rsa2048_v15_sha256_ec512 | 8100 |
| anchor_csca_chain_rsa2048_sha256_tbs512 | 6841 |
| dg_extract_sha256_ec1024 | 6237 |
| dg_extract_sha256_ec512 | 3301 |
| attributes_mrz_td1_sha256 | 2449 |
| attributes_mrz_td3_sha256 | 2103 |
| anchor_dsc_inclusion | 340 |
| predicate_member | 230 |
| predicate_compare | 123 |
| predicate_reveal | 100 |
| nullifier_document_number | 58 |
| registration_mrz_td3_ecdsa_p256_sha256_ec512_inclusion | 17 |
| registration_mrz_td3_ecdsa_p256_sha256_ec512_csca_chain | 17 |
| session_compare_member | 9 |

Commit `8bfd6d1` recorded the same pair one change earlier, at the same 512 byte buffer: 35080 for the signature circuit and 3297 for the extraction. The extraction circuit re-hashes the same 512 byte buffer, which is what re-deriving `econtent_binding` costs instead of verifying the signature again.

The registration circuit is a special case in this table: its 17 opcodes are almost entirely the four recursive verification intrinsics, whose cost lives in the backend rather than in ACIR, so its economics are the proving times in section 2.7 and not this count.

The ratio is the argument. Against the extraction circuit, Passive Authentication costs about two and a half times as much in the RSA variant and about eleven times as much in the curve variant. Against the four circuits a verifier uses to ask a question, the curve variant costs between 154 and 627 times as much, and the RSA variant between 38 and 156 times. Asking one more question of a document that has already been authenticated costs between 56 and 228 opcodes.

The two Passive Authentication figures are also worth reading against each other. RSA is four times cheaper than ECDSA here, which inverts the usual expectation, and the reason is recorded in commit `ae0a9c8`: verifying RSA with a small exponent is seventeen modular multiplications, while an ECDSA verification is two scalar multiplications over a curve whose field is not the proving field, so it pays for non native arithmetic throughout.

Commit `c9a27c9` recorded end to end numbers for the Passive Authentication circuit on the author's machine, at a time when that circuit had four public inputs rather than the five it has now: proving 1.9 seconds, proof 16000 bytes, public inputs 128 bytes for four field elements, verification key 3680 bytes. Those figures come from one machine and one revision and should be re-measured before being relied on.

## 4. Derived values

Every binding value, leaf format and salt convention lives in `lib/core/commit`, and no circuit re-derives them. All are Poseidon2. Each starts with a role tag so a value produced for one role cannot stand in for another. The header of that library states a second rule on top of the tags: Merkle internal nodes are the single untagged hash and are two wide, while every tagged value is three wide or more, which is what stops a leaf or a seed being read as an internal node.

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

`modulus_hash` folds the limbs through a chain of two wide hashes and then finishes with a three wide tagged hash over the tag, the limb count and the accumulator. The intermediate values of the fold have the shape of Merkle internal nodes, but they never leave the function; the published value is three wide and tagged, so the width rule separates it from internal nodes, and hashing the limb count separates an 18 limb modulus from any other width. It shares `TAG_DSC_KEY` with `pubkey_hash`, which is five wide, and Poseidon2 separates the two by input length. An earlier revision finished the fold with a two wide hash, which broke the shape rule this paragraph used to flag.

`hash32_to_fields` splits a 32 byte digest into two big endian halves of 16 bytes. `pack_pair` splits two equal length byte strings in half and packs each half into one element, requiring an even length and at most 31 bytes per half. `normalize::pack_to_4` packs up to 124 bytes big endian into four elements of 31 bytes each.

Two properties of this table matter when integrating. Every derived value a verifier stores or compares across sessions takes `domain`, so the same document produces different values under different applications, and a binding from one domain cannot be chained to a proof from another. Disclosed values are not scoped that way: `predicate_reveal` publishes the field itself, so a holder who reveals the same field to two applications links those sessions whatever the domain. And there is one exception among the derived values: `dsc_commitment` takes a salt but not a domain. A holder who reuses one random salt across applications publishes an equal value in both, which links those sessions. A fresh salt per session avoids that. The zero salt is a deliberate convention for the case where the verifier compares the commitment against a table it precomputes from a public registry, and it gives up hiding: with a zero salt the commitment identifies the signer to anyone with the registry.

## 5. Variants

Circuit names encode the dimensions a circuit cannot be generic over. A Noir circuit is fixed size, so a buffer is part of the circuit identity, and the algorithm a document was signed with is part of the arithmetic.

Passive Authentication names three dimensions, `sod/<signature algorithm>_<CMS digest algorithm>_ec<eContent buffer bytes>`, where the first token carries whatever the algorithm needs to be pinned down: `ecdsa_p256` is a curve, `rsa2048_v15` is a modulus size and a padding scheme. Data group extraction names two, `dg_extract/<data group hash algorithm>_ec<eContent buffer bytes>`. Attribute profiles name the data group and layout plus the data group hash algorithm, `attributes/mrz_<layout>_<algorithm>`. Anchors name the mode first and then whatever that mode needs: inclusion needs nothing, while the chain mode names the authority algorithm, the digest and its certificate body buffer, `anchor/csca_chain_<authority algorithm>_<digest>_tbs<certificate buffer bytes>`. The predicates and the nullifier have no algorithm dimension at all, since they operate on committed field elements; the nullifier names its policy instead.

Doc 9303 allows the CMS digest algorithm and the Security Object data group hash algorithm to differ, which is why `lib/core/hash` treats them as separate dimensions rather than one.

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
| `anchor/csca_chain_rsa2048_sha256_tbs512` | RSA-2048 authority, master list depth ten |
| `registration/mrz_td3_ecdsa_p256_sha256_ec512_inclusion` | one inner variant set, pinned by verification key hash |
| `registration/mrz_td3_ecdsa_p256_sha256_ec512_csca_chain` | the same set with the chain anchor, date tied to the attributes |
| `session/compare_member` | two predicates of a session as one proof |

Not every fixed size is in a name. The Passive Authentication circuit fixes `signed_attrs` at 256 bytes and the attribute circuits fix the DG1 buffer at 128 bytes; neither appears in the package name. The membership tree depth of eight, the signer registry depth of sixteen and the master list depth of ten are likewise fixed in the circuit and absent from the name. If a second size of either is ever needed, the naming scheme has to grow before the package does.

A relying party pins the variant by verification key. `Policy::accepted_keys` in the prover maps a circuit kind to the key hashes it accepts, and a proof from any other variant is rejected before its public values are looked at. This is what prevents an algorithm downgrade, and it is also the only thing that distinguishes a TD3 attribute proof from a TD1 one, since the two share an ABI and a circuit kind in the verifier.

## 6. The two verification models

### 6.1 Off-chain: verify each proof, then check the bindings

This is the model that exists. `verify_bundle` in `prover/src/verify.rs` implements it once so that an integration does not carry its own copy of the rules. The crate has no dependencies and does not reimplement proof verification: it shells out to the `bb` binary, the same prover that produced the proof, writing the verification key, the proof and the serialized public inputs to a temporary directory and running `bb verify`. Public inputs are 32 byte big endian elements concatenated in layout order.

A relying party supplies a `Policy`: its `domain`, the `context` it issued for this exchange, the accepted verification key hashes per circuit kind, and optionally a required registry root for the trust anchor.

The order is fixed, and cryptographic verification comes first so that a rejection has a stated reason rather than resting on one proof. A bundle takes one of two forms: the leaf form, a Passive Authentication proof with extraction, attribute and anchor proofs beside it, and the aggregate form, a registration proof standing for those four.

1. Reject if the policy `context` is zero, then if its `domain` is zero, then if it requires a trust anchor without fixing a registry root, since that would accept an anchor against any registry, including one the prover published.
2. For each proof in the bundle, in order: reject if its verification key is not on the accepted list for its circuit kind, reject if `bb verify` fails, reject if its `domain` differs from the policy domain, reject if its `context` differs from the policy context. Acceptance is by the key bytes, not by a digest supplied alongside. Document proofs, Passive Authentication or registration, are collected while passing.
3. Require exactly one document proof of either kind. Zero means nothing establishes the document; more than one means the bundle describes more than one document, or the same document twice.
4. In the leaf form: every extraction proof must carry the `econtent_binding` the Passive Authentication proof published, every attribute proof must carry a `dg_binding` an extraction proof returned, and every anchor proof must carry a `dsc_commitment` equal to the Passive Authentication proof's. The extraction numbers become DataGroup statements and the attribute commitments are collected. If the policy fixes a registry root, an anchor proof's first public input must equal it; if it requires a trust anchor and none is present, reject.
5. In the aggregate form: no extraction, attribute or anchor proof may appear beside the registration proof, because it exposes none of the values they would have to be checked against. The statement that data group 1 was extracted is recorded, the returned commitment is collected, and the registry root must equal the policy's when one is fixed. A required trust anchor is satisfied by construction, since signer trust was proved inside.
6. Dates. Every proof that resolved dates, an attribute proof, a chain anchor proof or a registration proof, is checked against the policy's `date_window` when one is set, and every date carrying proof in one bundle must have used the same date, so a bundle cannot resolve a birth year against one date and certificate validity against another.
7. Every compare, member and reveal proof must reference a collected commitment. Each contributes a statement: the field identifier with the bounds, the set root, or the revealed value and its length.
8. A nullifier proof must reference a collected commitment and must carry the same `secret_binding` the document proof published, from `return[2]` of a Passive Authentication proof or `return[1]` of a registration proof. A second nullifier proof is rejected, so the stored value cannot depend on proof order.

The result is the nullifier if one was present, the salted signer commitment when the document proof exposes one, which a registration proof deliberately does not, the statements, the date the proofs resolved against, and the registry root the signer was shown to belong to.

The crate has 19 unit tests, and `tests/bundle.rs` runs 18 more over proofs produced by the circuits, gated behind `ZKICAO_BUNDLE` so an environment without the backend skips them rather than failing. Both bundle forms and the refusal paths above are covered there against real proofs.

What `verify_bundle` deliberately does not do, and what a relying party must therefore do itself:

- Decide that the asserted date is actually today. The checklist enforces the window the policy sets and nothing more; a policy without `require_date_within` constrains no date, and a stale date moves a century boundary and certificate validity.
- Read the statements. `dg_number`, the compare bounds, the member set root and the revealed values come back as statements now, and a verifier that ignores them knows that something was proved without knowing it was the question it asked.
- Do the nullifier bookkeeping. The checklist returns one value and stores nothing.
- Cap anchor proofs. Several anchor proofs are each checked, but the reported registry root is the last one seen.
- Issue a fresh `context` per exchange and never accept a reused one. Nothing inside a circuit can enforce freshness; the circuits only reject zero.
- Decide whether a bundle without signer trust is acceptable. A leaf bundle without an anchor proof establishes that some key signed the document and nothing about whose key it is; a registration bundle always carries trust in one fixed registry.

A second entry point covers the sessions after a registration. `verify_session(proofs, policy, registered)` takes the commitment and secret binding the relying party stored when a registration bundle verified, accepts only compare, member, reveal, nullifier and aggregated session proofs, requires each to link to those stored values, and enforces the accepted keys, the domain and the fresh context exactly as `verify_bundle` does; a document proof in a session is refused (`NotASessionProof`). Document trust and dates are not re-examined, because they were the registration's job and are the caller's stored decision. What makes this work on the holder's side is the session salt of the attribute proof: it blinds the registered commitment and every later opening needs it, so for a registered identity it is not a per session value but a secret the holder keeps. A holder who loses it registers again, and the stored nullifier is what makes that visible.

### 6.2 On chain: the reference registry

The second model verifies on a chain, and it exists in the zkICAO/contracts repository. `ZkIcaoRegistry` is the aggregate bundle form of section 6.1 as a contract: a holder registers with a registration proof and a nullifier proof, both re proved with bb's keccak oracle so the transcript is EVM friendly, and the contract holds the two to each other and to its own policy, its application domain, its signer registry root and its proving date window, then verifies both with Solidity verifiers generated by `bb write_solidity_verifier` and stores the nullifier. A second registration of the same document reverts. The context is the sender address, so a proof is bound to the transaction sender at proving time and reverts in anyone else's transaction.

Measured with forge over real proofs: `register()` costs 6,518,172 gas for the two verifications and storage; the keccak flavored registration proof is 11,072 bytes and the nullifier proof 7,616. Every rejection path is tested against real proofs: a duplicate document, another sender, a tampered proof of either kind, a nullifier from another document, another registry, a date outside the window.

What does not exist on this path: any deployment, any audit, and on chain session questions, which today are an off chain matter against the registered commitment.

## 7. What is not implemented

Signature algorithms. Two variants exist, ECDSA over P-256 and RSA-2048 with PKCS#1 v1.5 and exponent 65537. Nothing else can be proved. RSA-3072 and RSA-4096 have no variant, RSA-PSS has no implementation at all, and the public exponent is fixed at 65537 in the arithmetic, so a key that uses any other exponent cannot be proved. `lib/core/sig` exposes one entry point, `verify_ecdsa_p256`; another curve means another wrapper beside it, added with the circuit variant that needs it.

Digest algorithms. `lib/core/hash` exposes SHA-256 and nothing else. Documents whose CMS digest or data group hashes use any other algorithm are out of reach, and the variant naming has room for them but the packages do not exist.

Document layouts. `lib/emrtd/mrz` implements TD1 and TD3. Doc 9303 also defines TD2, which is not implemented. No profile exists for any data group other than DG1, so nothing reads a portrait, a state specific group such as DG13, or anything else, even though the extraction circuit will extract any data group number from 1 to 16.

Trust. The chain mode verifies one link, an RSA-2048 country signing signature over an elliptic curve Document Signer certificate. It does not walk further, does not check revocation, does not read names or extensions, and cannot certify an RSA Document Signer key, so the RSA Passive Authentication variant has no chain anchor to pair with. Beyond that link the list of country signing keys is trusted input, which is unavoidable and is what a master list is.

Chip presence. Nothing here proves a document was read from a genuine live chip. There is no Active Authentication or Chip Authentication circuit, and no equivalent. Every proof is over data a holder supplies, so a copy of a chip's data produces proofs indistinguishable from the original. This is a property of Passive Authentication, and the system inherits it.

On-chain deployment. The reference registry, its verifiers and its tests exist and pass, section 6.2; no network has them, and no audit has looked at them. Session questions on chain do not exist. Predicate aggregation covers the compare and member pair; other compositions are added as they are needed.

Supporting code. The structure checks that ship are fixed offset byte comparisons in `lib/emrtd/lds`, `lib/emrtd/cms`, `lib/emrtd/attributes` and `lib/core/x509`. A general DER decoder existed in `lib/tlv` with no package depending on it and was removed; a certificate parser that walks a structure would need one written for that job. Witness preparation does not exist as code: `lib/core/sig` documents that a caller has to normalize `s` to `n - s` when it exceeds `n/2`, and the only implementation of that rule is `ec::normalize_s` in the Rust fixture generator that builds synthetic documents. The prover crate verifies and does not prove. The noir_rs pin in `TOOLCHAIN.md` is recorded as intended and is not exercised; the Barretenberg pin is exercised, by the bundle command that proves and verifies every circuit and by the keys subcommand that writes the pinned verification key hashes.

Real documents. Every fixture in `lib/testdata` is generated by `fixtures/generator`, which builds synthetic Doc 9303 material over the specimen machine readable zones from the standard: DG1, a Security Object, CMS signed attributes, a signature under a generated Document Signer key, and a Document Signer certificate signed by a generated country signing key. No test in either repository runs against a document issued by a state.

The repository was bootstrapped on 2026-07-23 and the pinned revision is from 2026-07-26, so the whole set above is three days of work and is still growing. Three gaps this document originally listed as absent, RSA Passive Authentication, country signing certificate verification and recursive aggregation, were filled while it was being maintained. Re-read the inventory against the revision you are auditing.

## 8. Obligations on the prover

These follow from the circuits and are not enforced by them.

Use the same `domain` in every proof of a bundle. The bindings are domain scoped, so a mismatch breaks the chain cryptographically as well as failing the verifier's check.

Use the `context` the verifier issued, and never zero.

Use one salt value for both the `dsc_salt` of the Passive Authentication proof and the `salt` of the anchor proof, or the two commitments will not match. Use a fresh one per session unless the zero salt registry convention is deliberate, since a reused random salt is a value that links sessions.

Use a fresh non-zero `session_salt` per attribute proof. It is the only hiding input in the commitment chain. When the commitment is registered for use across sessions, keep that salt: it is the opening key of the registered commitment, later predicate proofs cannot be built without it, and it never travels to the verifier. A fresh salt would produce a new commitment rather than open the registered one.

Normalize ECDSA `s` to `n - s` when it exceeds `n/2` before building the witness. The backend aborts otherwise.

For the RSA variant, compute the Barrett reduction parameter the bignum backend takes alongside the modulus. Commit `ee6387b` records it as `floor(2^(2 * MOD_BITS + 6) / n)` and notes that the fixture generator carries a small big integer implementation because no shell tool exposes that division.

Compute `document_secret` from the same normalized signature the Passive Authentication proof used, since the nullifier circuit checks it against the binding that proof published.

## 9. State of the test suite

Re-run at this revision: `nargo test` reports 114 tests passing across the 39 workspace packages, and `cargo test` in `fixtures/generator` reports 31. The prover crate has 21 unit tests, one documentation test, and 25 integration tests in `tests/bundle.rs` that run the checklist over real proofs when `ZKICAO_BUNDLE` points at a bundle the circuits produced, covering both bundle forms, the session entry point and the aggregated session. The contracts repository runs 8 forge tests over the same real proofs, including the measured registration. The recursive circuits have no `#[test]`, because recursion cannot be exercised without the backend; their coverage is the bundle command, which proves and verifies every one of them, and the adversarial witnesses recorded in commit `b43d83b`.

The circuit tests cover both layouts end to end and rejections for a swapped signature, swapped signed attributes, a signature over another Security Object with the digest link repaired, a Security Object that was not the authenticated one, an entry read as the wrong data group, a card layout read as a passport, an opening from another document, a field claimed under another identifier, a value outside a published set, a disclosure that does not match, a secret the prover invented, openings supplied in the wrong order, a signer outside the published set, a tampered certificate, an expired certificate, an authority outside the published list, and an unset session context. That last case is tested in four circuits of the eleven, `attributes_mrz_td3_sha256`, `predicate_compare`, `anchor_dsc_inclusion` and `anchor_csca_chain_rsa2048_sha256_tbs512`, although all eleven contain the assertion.

CI in the circuits repository runs `nargo fmt --check`, `nargo compile` and `nargo test` on the pinned compiler. CI in the prover repository runs `cargo build --all-targets`, `cargo fmt --check` and `cargo test`.

## 10. Fixed by the protocol, chosen by the application, kept by the holder

zkICAO is infrastructure, so which values are the project's and which are an integrator's is part of the interface. Everything below was checked against the code at this revision, and nothing anywhere in the five repositories commits private key material: the fixture documents are synthetic and regenerated.

Fixed by the protocol, the same for everyone. The Poseidon2 role tags 1 through 12 and every derived value format in `lib/core/commit`; the nullifier policy identifiers in `lib/claims/policy`; the tree shapes a circuit compiles in, sixteen leaves for the document commitment, depth eight for membership sets, depth sixteen for the signer registry, depth ten for the master list; the RSA exponent 65537; the public input layouts recorded in `layout.manifest`. Changing any of these is a protocol revision, not a configuration.

Fixed by the toolchain, regenerated rather than configured. Verification keys and their hashes are functions of the compiled bytecode and the backend version, nothing else. The `keys.nr` files a recursive circuit compiles in are written by `cargo run -- keys`, and the Solidity verifiers by `bb write_solidity_verifier`; an integrator who changes a circuit or moves to another toolchain revision regenerates both and must never edit either by hand. On the pinned toolchain, building from source reproduces them.

Chosen by each application. The `domain`, non zero and distinct from every other application, since it scopes every stored value; the accepted verification keys per circuit kind, which is the variant policy and the downgrade gate; exactly one nullifier policy for that domain; the signer registry or master list it trusts, published as a Merkle root it builds itself with the witness tools; the date window; a fresh `context` per exchange. On chain, all of that arrives as constructor parameters of the registry contract, plus the addresses of the verifiers it should trust.

Kept by the holder, never sent anywhere. The session salt behind a registered commitment, which becomes the opening key for every later session; the DSC salt, fresh per session unless the zero salt registry convention is deliberate; the document secret, derived from the chip signature and proved against its binding without leaving the device.
