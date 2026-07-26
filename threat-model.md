# Threat model

This chapter states what the zkICAO circuits and the off-chain verifier defend against, what they leave to the parties around them, and what they do not address at all. It describes the code as it exists in `circuits/lib`, `circuits/bin` and `prover/src/verify.rs`. Where a protection is claimed here, a constraint in that code enforces it, and the assertion message is quoted so a reader can find it.

The code moves quickly, so this chapter is pinned to a state: circuits commit `ae0a9c8`, with an uncommitted `lib/core/x509` package in the working tree, and prover commit `204d352`, with a regenerated `layout.manifest` in the working tree. Claims below were checked against exactly that state. `nargo test` passes on the whole circuits workspace under the pinned toolchain, and `cargo test` in the prover crate passes twelve tests plus one doc test.

zkICAO is an independent project. It is not affiliated with, endorsed by, or certified by ICAO or any government.

## 1. Scope

In scope: the ten circuits under `circuits/bin` (`sod/ecdsa_p256_sha256_ec512`, `sod/rsa2048_v15_sha256_ec512`, `dg_extract/sha256_ec512`, `attributes/mrz_td3_sha256`, `attributes/mrz_td1_sha256`, `predicate/compare`, `predicate/member`, `predicate/reveal`, `nullifier/document_number`, `anchor/dsc_inclusion`), the libraries they are built from, and `verify_bundle` in `prover/src/verify.rs`.

Out of scope, because no code for it exists in this repository: reading the chip, building witnesses from a document that was read, transporting proofs, on-chain verification, and any credential or aggregation layer. The `README.md` design sketch lists `anchor/csca-chain` and `credential` as intended components; neither is implemented. A `lib/core/x509` package with certificate parsing helpers sits in the circuits working tree, uncommitted, and no binary circuit depends on it, so nothing in the proving flow reads a certificate.

Every library that ships has a circuit that uses it. Entry points without a circuit behind them, two unused curve wrappers and a country code packer among them, were removed rather than left as untested code paths in a cryptographic library.

Maturity matters to how this document should be read. Every end-to-end test runs against synthetic documents produced by `circuits/fixtures/generator`, which generates its own Document Signer keys through the openssl command line tool and signs the Doc 9303 specimen machine readable zones. The header of `circuits/fixtures/generator/src/main.rs` says so directly: "No genuine document is involved, and regenerating produces a fresh key, so the committed output is the fixture of record." No genuine issued document has been exercised through this pipeline.

## 2. The attacker

### 2.1 What the attacker can do

The attacker is assumed to have all of the following.

A complete copy of the data page. That means the full machine readable zone, character for character. This matters more than it first appears, because DG1 is exactly the machine readable zone under two DER templates (`61 len` then `5F1F len`, with the characters starting at `attributes::DG1_MRZ_OFFSET = 5`). An attacker with a photocopy therefore knows DG1 byte for byte and can compute `SHA-256(DG1)` and anything derived from it.

Unlimited observation of proofs. Every public input of every proof, from this holder and from every other holder, across sessions and across relying parties, is visible. Public inputs are enumerated per circuit in `prover/layout.manifest`.

Operation of a relying party. The attacker can stand up a verifier, choose the `domain` and `context` it issues, choose `set_root`, `minimum`, `maximum`, `field_id`, `dg_number`, `registry_root` and `current_yyyymmdd`, and record every proof presented to it.

Arbitrary witnesses. Every private input to every circuit is under the attacker's control, bounded only by the constraints. This includes `econtent`, `signed_attrs`, `digest_offset`, `oid_offset`, `dg_offset`, `pubkey_x`, `pubkey_y`, `signature_r`, `signature_s`, `modulus_limbs`, `redc_limbs`, `signature_limbs`, `dsc_salt`, `session_salt`, `dg1`, all Merkle `siblings`, `index`, `set_index`, `entropy`, `salt` and `secret`.

Their own signing keys. The attacker can generate a P-256 or RSA key pair, build a well formed Security Object and CMS signed attributes over data of their choosing, and sign them. Nothing prevents this, and the fixture generator demonstrates it costs nothing.

### 2.2 What the attacker cannot do

The attacker cannot find SHA-256 collisions or preimages, cannot find Poseidon2 collisions or preimages, cannot forge ECDSA signatures over P-256 or RSA PKCS#1 v1.5 signatures without the private key, and cannot produce an accepting UltraHonk proof for a false statement.

The attacker does not hold the private key of a genuine Document Signer.

The attacker does not control the holder's proving device. Compromise of that device is a separate failure discussed in section 5.9.

Physical possession of the chip is deliberately left open. Whether the attacker has it is the line that separates several of the protections below from several of the gaps.

## 3. What the circuits constrain

### 3.1 Passive Authentication

The chain has three links. `sod::link` checks the first two and the variant circuit checks the third. The Security Object content is hashed with `hash::sha256_bounded`. The messageDigest signed attribute is located and read by `cms::message_digest_sha256`, which refuses an attribute that is not messageDigest (`"cms: attribute is not messageDigest"`), a value that is not a 32 byte octet string (`"cms: digest is not an OCTET STRING"`, `"cms: digest is not 32 bytes"`), a set header that is absent (`"cms: attribute values are not a SET"`), an offset too small to hold the header (`"cms: digest offset too small"`), and a digest running past the declared length (`"cms: digest runs past the signed attributes"`). The two are then compared byte by byte, failing with `"sod: security object digest does not match the signed attribute"`. The signature is then checked over the hash of the signed attributes.

The consequence is that a modified Security Object cannot be presented. A single flipped bit anywhere in `econtent` changes its SHA-256, which no longer matches the signed messageDigest. The test `sod::rejects_a_tampered_security_object` flips one bit inside the DG1 hash entry and confirms the failure.

Two signature variants ship, both over a Security Object buffer of 512 bytes.

`sod/ecdsa_p256_sha256_ec512` calls `sig::verify_ecdsa_p256`, which fails with `"sig: ecdsa p256 verification failed"`. It also calls `validate_in_field()` on the decoded key coordinates and signature scalars, because, as the header of `circuits/lib/core/sig/src/lib.nr` records, byte deserialization in noir-bignum enforces only that a value is below `2^MOD_BITS`, not that it is reduced.

`sod/rsa2048_v15_sha256_ec512` calls `rsa::verify_pkcs1_v15_sha256`, which recovers the encoded message by raising the signature to 65537 and then constrains every byte of it: the leading zero (`"rsa: encoded message must start with zero"`), the block type (`"rsa: wrong block type"`), the whole padding run (`"rsa: padding must be all ones"`), the separator (`"rsa: missing padding separator"`), the SHA-256 digest info (`"rsa: digest info does not describe sha-256"`) and the digest itself (`"rsa: digest does not match"`). Constraining the full padding run is what stops a forger placing the digest info at another offset. Only the exponent 65537 is implemented, so a key with any other exponent cannot be verified here at all.

Both variants publish three values: `econtent_binding`, `dsc_commitment` and `secret_binding`. The Document Signer public key itself stays private.

The RSA variant derives its commitments with `commit::modulus_hash` and `commit::limbs_document_secret`, which fold every limb, so the signer key commitment and the document secret are functions of the whole modulus and the whole signature. An earlier revision kept three bytes of each limb, covering 432 bits of 2048; that was corrected in `98d7611` and is recorded here because anyone reading an older tree would meet it. An anchor registry holding RSA entries has to build leaves with the same helper.

### 3.2 Data group extraction

`dg_extract::extract_sha256` re-hashes the Security Object and requires the result to reproduce the binding the Passive Authentication proof published, failing with `"dg_extract: security object does not match the authenticated one"`. It then asserts the SHA-256 algorithm identifier is present (`"lds: wrong hash algorithm oid"`) and reads one entry through `lds::dg_entry_sha256`, which checks the DER header shape (`"lds: dg entry missing sequence"`, `"lds: dg entry wrong sequence length"`, `"lds: dg entry missing integer"`, `"lds: dg entry wrong integer length"`, `"lds: dg entry missing octet string"`, `"lds: dg entry wrong hash length"`), the data group number against the public input (`"lds: dg entry wrong dg number"`), the number's range (`"lds: dg number must be >= 1"`, `"lds: dg number must be <= 16"`) and the bounds (`"lds: dg entry out of bounds"`).

Because `dg_number` is a public input, a relying party states which data group a proof concerns rather than accepting the prover's later description of it. The test `dg_extract::rejects_reading_an_entry_as_the_wrong_data_group` covers the mismatch.

### 3.3 Attribute commitment

`attributes::td3` and `attributes::td1` re-hash the supplied DG1 and require the result to reproduce the data group binding the extraction proof published, failing with `"attributes: data group was not the authenticated one"`. The DER template is checked by `check_dg1_template`, which pins the total length (`"attributes: unexpected dg1 length"`), the outer tag (`"attributes: dg1 is missing its template tag"`), the inner tag (`"attributes: missing machine readable zone tag"`) and both declared lengths (`"attributes: dg1 template length mismatch"`, `"attributes: machine readable zone length mismatch"`).

The length check is what keeps the two document layouts apart. TD3 carries 88 machine readable zone characters and TD1 carries 90, so a card presented to the passport profile, or the reverse, fails at `"attributes: unexpected dg1 length"` rather than producing a commitment over fields read at the wrong offsets. Both `attributes::rejects_a_card_layout_read_as_a_passport` and the binary test `rejects_a_passport_read_as_a_card` cover this.

Check digits are verified by `mrz::td3_validate` and `mrz::td1_validate` over the document number, birth date, expiry date, optional data on TD3, and the composite. Dates are parsed strictly: non digits fail at `"mrz: invalid date digit"`, months outside 1 to 12 at `"mrz: month out of range"`, and impossible calendar days at `"mrz: day out of range for month"`, including leap year handling in `assert_day_in_month`.

`current_yyyymmdd` is a public input because it decides how a two digit birth year resolves. The comment on `mrz::birth_date_to_int` states the reason: "a prover free to choose it can move a birth date by a century".

The commitment is built over sixteen leaves with `commit::leaf`, each carrying its own field identifier, length, packed data and per-field entropy derived from `commit::entropy_seed` and `commit::field_entropy`. The seed rejects a zero session salt at `"commit: session salt must be non-zero"`. Only the commitment leaves the circuit. Birth and expiry dates are computed inside and never published.

### 3.4 Field predicates

Every predicate opens the field first, through the private `open` in `circuits/lib/claims/predicate/src/lib.nr`, which the nullifier reaches through the exported `predicate::open_field`. It bounds the field identifier (`"predicate: field identifier out of range"`), rebuilds the leaf, walks it to a root using `field_id - 1` as the Merkle index, and requires `commit::commitment(root, domain)` to equal the commitment the attribute circuit published, failing with `"predicate: field is not part of the committed document"`.

Deriving the index from the field identifier rather than accepting it separately is what stops a value being claimed under a different identifier. The test `predicate::rejects_a_field_claimed_under_another_identifier` changes only `field_id` and confirms the opening no longer reaches the committed root.

On top of that opening: `compare` requires a non-empty range (`"predicate: empty range"`), requires the value to fit one field element and to be an integer (`"predicate: value does not fit one element"`, `"predicate: value is not an integer"`), and bounds it (`"predicate: value below the minimum"`, `"predicate: value above the maximum"`). `member` requires a Merkle path from `commit::set_entry(opening.data)` to the published root (`"predicate: value is not in the set"`). `reveal` requires the published value and length to match the opened ones (`"predicate: revealed value does not match"`, `"predicate: revealed length does not match"`).

### 3.5 Nullifier

`nullifier::document_number` pins the two openings to specific fields (`"nullifier: first opening must be the issuing state"`, `"nullifier: second opening must be the document number"`), opens both against the attribute commitment, and requires `commit::secret_binding(secret, domain)` to equal the binding the Passive Authentication proof published, failing with `"nullifier: secret does not match the authenticated document"`.

The secret is `commit::document_secret` over the Security Object signature. The comment on that function gives the two properties required: it is fixed at issuance so a prover cannot choose it, and it is not printed on the data page so it cannot be guessed from a photocopy. `commit::nullifier` rejects a zero secret at `"commit: nullifier secret must be non-zero"`.

The resulting value is deterministic per document per `domain`, and unlinkable across domains because `domain` is hashed into it. Tests `the_same_document_gives_the_same_value_within_an_application` and `different_applications_give_unlinkable_values` cover both directions.

The policy identifier is `policy::DOCUMENT_NUMBER_V1`, passed as a constant inside `nullifier::document_number`. It is not a public input, so a relying party learns which policy produced a nullifier only from which verification key it accepted. Note that the header comment on `circuits/lib/claims/policy/src/lib.nr` says the identifier "is a public input", which does not match the shipped circuit; `prover/layout.manifest` records the nullifier public inputs as `commitment secret_binding domain context return[0]`. `policy::assert_supported` exists but is called by no circuit; the only callers are its own tests.

### 3.6 Document Signer trust

`anchor::prove_signer_is_trusted` hashes the signer key with `commit::pubkey_hash`, requires a Merkle path from that hash to a published registry root (`"anchor: signer key is not in the published set"`), and returns `commit::dsc_commitment(leaf, salt)`, the same value Passive Authentication publishes. `bin/anchor/dsc_inclusion` instantiates it at depth sixteen and requires both scoping inputs to be set (`"anchor: context must be set"`, `"anchor: domain must be set"`). Its tests pass under the pinned toolchain.

The off-chain verifier consumes this circuit; see section 4.1. What the circuit assumes is recorded in its own header: "whoever built the set checked the certificates behind it. Verifying the country signing certificate in circuit instead removes that assumption and is not implemented."

### 3.7 Session scoping

Every binary circuit asserts its session context is set: `"sod: context must be set"` in both Passive Authentication variants, then `"dg_extract: context must be set"`, `"attributes: context must be set"`, `"predicate: context must be set"`, `"nullifier: context must be set"` and `"anchor: context must be set"`. The comment in `bin/sod/ecdsa_p256_sha256_ec512/src/main.nr` explains why a non-zero assertion rather than nothing: it "puts a real constraint on it, rather than leaving it an input the circuit never reads". Commit `c9a27c9` in the circuits repository records that both circuits at the time carried `assert(context == context)`, which the compiler removed, leaving the input in the ABI but unread.

`context` deliberately enters no derived value. The header of `circuits/lib/core/commit/src/lib.nr` states the rule: `domain` enters every value a verifier stores or compares across sessions, `context` enters none, because mixing it in would change stored values every session.

## 4. What the bundle check constrains

### 4.1 What `verify_bundle` enforces

`verify_bundle` runs in a fixed order. It rejects a zero policy context (`Failure::ContextNotSet`). Then for every proof it requires the verification key to be one the policy accepts (`Failure::UntrustedVerificationKey`), requires `bb verify` to succeed (`Failure::ProofRejected`), requires the proof's `domain` to equal the policy domain (`Failure::WrongDomain`), and requires its `context` to equal the policy context (`Failure::WrongContext`).

The bytes handed to `bb` as public inputs are re-serialized from the same `PublicInputs` the equality checks later read, so the values compared below are the values the proof was verified against.

It then requires exactly one Passive Authentication proof (`Failure::NoSecurityObjectProof`, `Failure::MoreThanOneSecurityObjectProof`), requires every extraction proof to reference that proof's `econtent_binding` (`Failure::UnlinkedDataGroup`), requires every attribute proof to reference one of the extracted data group bindings (`Failure::UnlinkedDataGroup`), requires every predicate and the nullifier to reference a commitment an attribute proof published (`Failure::UnlinkedCommitment`), and requires the nullifier's `secret_binding` to equal the one the Passive Authentication proof published (`Failure::NullifierFromAnotherDocument`).

For each anchor proof in the bundle it requires the anchor's `dsc_commitment` to equal the one the Passive Authentication proof published (`Failure::AnchorForAnotherSigner`), and, when `Policy::registry_root` is set, requires the anchor's `registry_root` to equal it (`Failure::AnchorAgainstAnotherRegistry`). If `Policy::require_trust_anchor` is set and no anchor proof was seen, the bundle is rejected (`Failure::NoTrustAnchorProof`). The registry root that was proved against is returned as `Verified::signer_registry_root`.

Two failure modes this closes are named in the module header. A bundle whose proofs carry different domains "is several documents wearing one identity". A proof from a weaker circuit variant is a downgrade unless the verifier states which verification keys it accepts, which `Policy::accepted_keys` makes mandatory rather than optional: a circuit with no entry in the map is rejected outright.

### 4.2 What `verify_bundle` does not enforce

A relying party integrating against this crate must handle all of the following itself. None of it is checked.

The verifier surfaces `dg_number` as a `Statement::DataGroup` and compares it to nothing, so a leaf bundle establishes which data group was extracted only if the relying party reads the statements. The registration circuit pins the number to 1 in circuit, so the aggregate form does not carry this obligation.

The verifier does not read `current_yyyymmdd`. `PublicInputs::attributes_current_date` exists and is called only by the layout tests. A bundle can carry an attribute proof built against any date the prover chose, which moves birth dates by a century.

The verifier never reads `minimum`, `maximum` or `set_root`. It reads `field_id` only from a `reveal` proof, and only to label the value in `disclosed_fields`. `Policy` has no field that names a required statement, and `Verified` returns `nullifier`, `dsc_commitment`, `disclosed_fields` and `signer_registry_root`. A bundle containing only a Passive Authentication proof verifies successfully and returns an empty `disclosed_fields`. "Verified" therefore means a signed document exists and the bundle is internally consistent, not that any question the relying party asked was answered.

The trust anchor check is opt-in and is off unless asked for. `Policy::new` sets `require_trust_anchor` to false and `registry_root` to `None`, so a bundle with no anchor proof verifies and `dsc_commitment` is returned to the caller unchecked. `Policy::require_anchor` sets both together, but the fields are public, so a policy built field by field can end up requiring an anchor without naming a registry, in which case any registry root satisfies the check.

The verifier does not recompute `Proof::verification_key_hash` from `Proof::verification_key`. Acceptance is decided on the caller-supplied hash while `verify_one` writes the caller-supplied key bytes to disk for `bb`. Nothing in the crate hashes anything. An integration that deserializes both from an untrusted source, and trusts the transmitted hash, loses the downgrade protection the policy is meant to provide. The integration must derive the hash from the bytes it actually passes to the verifier.

The verifier does not return `revealed_length`. `disclosed_fields` carries the four packed elements from indices 2 through 5 but not index 6, so a caller cannot distinguish a short value from a value with leading zero bytes without reading the public inputs itself.

If a bundle contains more than one nullifier proof, `Verified::nullifier` holds the last one seen; there is no rejection for the duplicate. The same is true of `signer_registry_root` when several anchor proofs are present, though each of those must still match the signer commitment.

`Policy::domain` is not required to be non-zero. Only the context is. Among the circuits, only `bin/anchor/dsc_inclusion` asserts a non-zero domain in circuit.

## 5. What the system does not protect against

### 5.1 A cloned chip

There is no active authentication circuit anywhere in the repository, and no chip authentication or terminal authentication of any kind. Nothing in any circuit involves a challenge, a response, or a key held by the chip. A search of `circuits/lib` and `circuits/bin` for any of those terms returns nothing.

Everything the circuits check is a property of static data. An attacker who obtains a complete copy of a genuine document's chip contents, by any means, holds everything needed to produce a valid bundle: `econtent`, `signed_attrs`, the Document Signer public key and signature, and DG1. All of it is signed data that copies exactly. The proofs will verify. Nothing distinguishes the copy from the original.

This is the core limitation of Passive Authentication as a standalone mechanism, and it is not mitigated here. A deployment that needs chip liveness must obtain it outside these circuits.

The same copy also yields the document secret, since that is derived from the Security Object signature, so nullifier uniqueness offers no protection here either: the copy produces the genuine holder's nullifier.

### 5.2 A Document Signer that is not checked against a trust anchor

The `anchor/dsc_inclusion` circuit exists, works, and can be demanded through `Policy::require_anchor`. It is not demanded by default. In a deployment that leaves `require_trust_anchor` false, a bundle proves the document was signed by some key and proves nothing about whose key.

An attacker who generates their own key, builds a Security Object over data of their choosing and signs it, exactly as `circuits/fixtures/generator` does, produces a bundle that such a `verify_bundle` call accepts and that carries entirely fabricated attributes. This is not a subtle attack; it is the default outcome of not asking for the anchor.

With the anchor required, two gaps remain. The trust set is a Merkle root the verifier publishes, and the circuit assumes whoever built that set validated the certificates behind it. No code in this repository builds such a set. There is no circuit that verifies a Document Signer Certificate against a Country Signing Certificate Authority, so certificate validity periods, key usage, and revocation are outside the constraint system entirely. `README.md` lists `anchor/csca-chain` as intended; it does not exist. A `lib/core/x509` package with certificate parsing helpers exists in the working tree, uncommitted, and no circuit depends on it.

### 5.3 A relying party that does not run the verifier honestly

`verify_bundle` runs inside the relying party's own process. Nothing observes it. A relying party can call it and ignore the result, call it with a permissive policy, skip it entirely, or accept a bundle whose predicates prove nothing it asked for. No party other than that relying party learns whether verification happened.

This is inherent to off-chain verification and is stated here because the failure modes in section 4.2 make it easy to reach accidentally rather than maliciously: an integration that treats `Ok(Verified)` as an answer to its question, without inspecting the predicate public inputs, has effectively not verified.

The verifier also shells out to `bb` resolved through `PATH`, writing the key, proof and public inputs into `std::env::temp_dir().join(format!("zkicao-verify-{}", std::process::id()))`. That path is predictable and shared, so two concurrent `verify_bundle` calls in the same process collide on the same files, and a local process able to write into the temp directory between the write and the `bb` invocation can substitute them. Verification is only as trustworthy as the host it runs on and the binary it finds.

### 5.4 Anything the holder chooses to disclose

`predicate/reveal` publishes `revealed[0]` through `revealed[3]` and `revealed_length` as public inputs. Whatever field is revealed is revealed, in full, to whoever receives that proof and to anyone they pass it to. The circuit's own header says so: "unlike the other predicates this one hands the verifier the field itself".

The same applies at coarser grain to every predicate. A `compare` proof discloses that the value falls in the published range; a `member` proof discloses that the value is in the published set. A relying party that publishes a single element set learns the value exactly. A relying party that issues a sequence of narrowing `compare` bounds across sessions performs a binary search on a private field, and nothing in the circuits limits how many statements a holder is asked for.

The system constrains what a proof means, not what a holder agrees to prove. Consent is the wallet's responsibility, and no wallet exists in this repository.

### 5.5 Correlation through the Document Signer commitment

`commit::dsc_commitment(dsc_pubkey_hash, salt)` does not include `domain`, and the test `sod::outputs_change_with_the_domain` asserts exactly that: the commitment is identical across applications. `dsc_salt` is an unconstrained private input to both Passive Authentication circuits.

The comment on `commit::dsc_commitment` records the trade-off. With `salt = 0`, the public registry convention, the commitment is a deterministic function of the signer key alone, so it is a stable cross-application identifier of the issuing state and issuing batch, and every holder whose document shares a signer is linkable to every other. With a random salt, that linkage is closed but a verifier can no longer match a precomputed table and needs an anchor proof instead, which `Policy::require_anchor` makes it able to demand.

### 5.6 Linkage the wallet chooses to create

`entropy_seed` constrains `session_salt` to be non-zero and nothing more. A prover that reuses a salt produces the same commitment in every session, which links those sessions. A prover that uses a predictable salt is worse: the comment on `entropy_seed` explains that the salt is the only hiding input in the chain, that `dg_hash` for the MRZ profiles is SHA-256 over DG1, which is the printed machine readable zone wrapped in a TLV template, and that without real hiding "a party holding a photocopy of the data page could recompute the holder's commitment for a domain and test it against a registry".

Similarly, `domain` separation only works if distinct applications use distinct domains. Two relying parties that agree to use the same domain receive the same nullifier for the same holder and can link their records.

### 5.7 Uniqueness that is weaker than one value per person

The nullifier is unique per document per domain, not per person. `nullifier::document_number`'s header states it: a replacement document produces a different value, both because the document number usually changes and because the secret is tied to this document's signature. A person holding a passport and a national identity card, or a person holding documents from two states, produces two distinct nullifiers under the same domain. Nothing detects that.

`policy::MRZ_STABLE_V1` and `policy::NATIONAL_IDENTIFIER_V1` are declared as constants but no circuit implements either, so no reissue-stable policy ships.

An application must fix exactly one policy per domain. The header of `circuits/lib/claims/policy/src/lib.nr` notes that accepting two policies within one domain "lets one holder present two different nullifiers, which defeats the uniqueness the nullifier exists to provide". Since the policy identifier is not a public input, enforcing this means accepting exactly one nullifier verification key per domain.

### 5.8 Freshness, expiry and revocation

Nothing checks that a document is currently valid. The expiry date is committed as field 7 and a relying party can prove a bound on it with `compare`, but `verify_bundle` neither requires such a proof nor checks its bounds. There is no revocation mechanism of any kind, and a stolen or reported document produces valid proofs indefinitely.

Replay across sessions is prevented only to the extent the relying party issues a fresh, unpredictable `context` per exchange and rejects reuse. The circuits require the value to be non-zero; they cannot enforce that it is fresh.

### 5.9 The proving device

Side channel, fault and malware attacks on the device that holds the document data and builds witnesses are out of scope. A compromised device leaks the document contents and the document secret, which is sufficient to impersonate the holder to every application, permanently, since the secret is fixed at issuance.

### 5.10 Denial of service

Nothing here addresses resource exhaustion, either against a relying party asked to verify many bundles or against a prover.

## 6. Assumptions

### 6.1 On the issuing state

The Document Signer private key has not been compromised and the issuing state's signing process does not sign false data. Passive Authentication proves what the state signed; it cannot distinguish a correctly signed lie from a correctly signed truth.

The machine readable zone in DG1 matches the document that was actually issued. The check digits in `mrz::td3_validate` and `mrz::td1_validate` do not help here, and the test `check_digits_miss_multiple_of_ten_substitutions` demonstrates why: the 7-3-1 weighting is taken modulo 10, so substituting a character whose value differs by a multiple of ten leaves every check digit unchanged. The comment above that test states the conclusion: "Check digits therefore detect transcription mistakes, not tampering: integrity of the MRZ rests entirely on the Security Object signature over DG1."

The document number is not reused across documents within an issuing state, since the document number policy derives uniqueness from the issuing state and document number pair.

Certificate validity is established outside the circuits. Whoever assembles the anchor registry root is trusted to have validated the certificates it contains, and to have derived each leaf the way `commit::pubkey_hash` derives it, including the byte mapping the RSA variant applies to a modulus.

### 6.2 On witness preparation

Nothing in this repository builds a witness from a document read off a chip. The fixture generator writes a `Prover.toml` for the elliptic curve Passive Authentication circuit from its own synthetic document, and nothing more, so the following are obligations on whatever builds witnesses for real documents.

The signature `s` value must be normalized to `n - s` whenever it exceeds `n / 2`. The header of `circuits/lib/core/sig/src/lib.nr` explains that the ECDSA backend aborts rather than returning false for high `s`, that RFC 5280 and RFC 5480 place no such restriction so roughly half of genuine documents carry high `s`, and that the normalization is sound because verification accepts `(r, s)` exactly when it accepts `(r, n - s)`. That header also states plainly that "no such code exists yet: until it does, every caller has to normalize for itself." The fixture generator does normalize, and the header of `circuits/lib/testdata/src/lib.nr` records it, but that code serves the fixtures alone.

For the RSA variant the Barrett reduction parameter has to be supplied alongside the modulus. The header of `circuits/lib/core/rsa/src/lib.nr` records that a wrong hint cannot make a bad signature verify, because the bignum backend constrains every multiplication against it, so this is a liveness obligation rather than a soundness one.

`session_salt` must be freshly sampled with real entropy per session, and `dsc_salt` must be chosen consistently with whatever trust check the deployment uses.

Offsets must be correct. `digest_offset`, `oid_offset` and `dg_offset` are private inputs that the structure checks validate locally but do not derive.

### 6.3 On the proving toolchain

`circuits/TOOLCHAIN.md` pins nargo 1.0.0-beta.19, Barretenberg 4.2.0-aztecnr-rc.2 and noir_rs v1.0.0-beta.19-4, and pins the Noir dependencies: sha256 v0.3.0, poseidon v0.2.6, bignum v0.9.2-1, bigcurve v0.13.2-1 and ecdsa v0.3.0. A sha1 pin went with the build probe that was its only user, and the eleven circuits compiling under the pin is now what checks the dependency graph resolves.

Trusting a proof means trusting the Noir compiler to lower the source in `circuits/lib` and `circuits/bin` into an equivalent constraint system, trusting those dependency implementations of SHA-256, Poseidon2, ECDSA and big integer arithmetic to be correct, and trusting Barretenberg's prover and verifier along with whatever setup its proving system requires. `verify_one` delegates the cryptographic check to `bb` rather than reimplementing verification, so the verifier inherits every assumption the prover carries.

The public input indices in `prover/src/layout.rs` are defined by circuit signatures in a different repository. `prover/layout.manifest` is generated from the compiled ABIs and four tests check the table against it. `kind_of` covers all eight circuit kinds, and both Passive Authentication variants map through the `sod_` prefix, so drift in any shipped circuit fails a test. What those tests still cannot catch is a compiled package whose name matches no prefix: `kind_of` returns `None` and the manifest line is dropped without comment.

### 6.4 On the relying party

The relying party issues a fresh, unpredictable `context` per exchange and rejects reuse, uses a `domain` distinct from other applications, and accepts exactly one nullifier verification key per domain. It calls `Policy::require_anchor` with the registry root it trusts rather than leaving the anchor check off. It pins the verification key hash of every circuit variant it accepts, derived from the key bytes it actually verifies against, and it inspects the public inputs of predicate proofs to confirm they answer the question it asked.

## 7. Measured sizes

The measured numbers in the repository are all in commit messages.

RSA costs about a quarter of the elliptic curve variant, which inverts the usual assumption: an RSA verification with a small exponent is seventeen modular multiplications, while an ECDSA verification pays for non native arithmetic throughout. Opcode counts are in `architecture.md`, which is the only place they are recorded.

Commit `c9a27c9` records, for the Passive Authentication circuit and on a machine its message does not name, proving in 1.9 s, a 16000 byte proof, 128 bytes of public inputs for four field elements, and a 3680 byte verification key. Those figures predate the current signature: at that commit the circuit returned two values and carried four public inputs, where it now returns three and carries five. Nothing in the repository re-measures them.

These numbers are relevant to the threat model in one respect. The signature check dominates and runs once, and the predicate circuits sit two orders of magnitude below it, so asking additional questions of an already authenticated document is comparatively cheap. That is what makes the relying party obligations in section 4.2 practical: reading a few more public inputs costs nothing, and requiring one more small proof costs a small fraction of the bundle.

## 8. Summary of open gaps

The gaps below are the ones a deployment must close before the system provides what its structure implies. They are stated as absent rather than planned.

Trust anchoring is reachable but off by default, and it rests on a registry built outside the constraint system. `Policy::new` leaves `require_trust_anchor` false, and a policy that requires an anchor without naming a registry root accepts any root. No code in this repository builds a registry, and no circuit verifies a Document Signer Certificate against a Country Signing Certificate Authority. A `lib/core/x509` package with certificate parsing helpers exists in the circuits working tree, uncommitted, and no binary circuit depends on it.

Chip liveness has no circuit. Active authentication is absent.

The verifier does not carry a statement of what the relying party asked of the document, so it cannot check that the bundle answers it. `Policy` holds accepted keys, a domain, a context, a trust anchor requirement and a registry root, and nothing that names a field or a bound.

`Proof::verification_key_hash` is trusted rather than derived, which weakens the downgrade protection it exists to provide.

Four Passive Authentication variants ship: ECDSA over P-256 and P-384, and RSA PKCS#1 v1.5 at 2048 and 4096 bits, all with SHA-256. Other digests have no circuit, and `circuits/lib/core/hash/src/lib.nr` states only SHA-256 ships. Brainpool curves have no wrapper. All three machine readable zone layouts are implemented.

For the RSA variant, `dsc_commitment` and the document secret come from `modulus_hash` and `limbs_document_secret`, which fold every limb. An anchor registry holding RSA entries has to use the same helper for its leaves, and no inclusion circuit takes a modulus yet.

`lds::dg_entry_sha256` validates the DER header at the offset it is given and nothing about how that offset was reached. Its header records the limit and the mitigation: it "cannot tell a genuine entry from a byte sequence elsewhere in the buffer that happens to match the same seven header bytes", though "the hash read out is still covered by the signature over the Security Object, so a match on arbitrary bytes only yields data the issuer signed".

`mrz::birth_date_to_int` resolves two digit years against the current two digit year, so holders older than one hundred years resolve to the wrong century. The comment records this as "a limit of two digit years in the machine readable zone itself".

No genuine issued document has been proved end to end. All fixtures are synthetic and self-signed by `circuits/fixtures/generator`.
