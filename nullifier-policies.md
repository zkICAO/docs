# Nullifier policies

This document specifies the scoped uniqueness value zkICAO circuits produce, the policy identifier scheme that labels it, and the guarantees it does and does not carry. It is normative for the identifiers and derivations; where the shipped code differs from the intent stated elsewhere in the repository, this document records the shipped behaviour and says so.

zkICAO is an independent project. Nothing here is affiliated with, endorsed by or approved by ICAO or any government.

## 1. What a nullifier is for

An application that wants "one registration per person" has to recognise a returning holder without learning who the holder is. The nullifier is that handle: one field element, deterministic for a given document within a given application, and different in every other application. The application stores it and refuses a second registration under the same value.

It is not an identifier of a person. It is a value derived from one document, one policy and one application domain, and every property below is a property of that triple.

Two scoping public inputs appear across the circuit chain. `domain` is the application identity, fixed by the relying party. It enters `entropy_seed`, `dg_binding`, `econtent_binding`, `commitment`, `secret_binding` and the nullifier itself. `dsc_commitment` is the one derived value that does not take it: it is scoped by a salt instead, and it is about the signer rather than the holder. `context` is a per session freshness value that enters no derived value, so it cannot make a stored nullifier change between sessions. The nullifier circuit rejects `context == 0` (`"nullifier: context must be set"`).

No circuit in the nullifier chain rejects `domain == 0`; only `bin/anchor/dsc_inclusion` asserts one, with `"anchor: domain must be set"`. The verifier does not close the gap either: `verify_bundle` in `prover/src/verify.rs` tests `policy.context.is_zero()` and returns `ContextNotSet`, and makes no equivalent test on the domain. Two applications that both left the domain unset would share nullifiers, so a relying party must set a distinct non-zero domain itself.

## 2. Derivation

All values are Poseidon2 hashes over the BN254 scalar field, defined once in `circuits/lib/commit/src/lib.nr`. Every derived value starts with a role tag so a value produced for one role cannot be replayed as another. `commit::hash_pair`, the Merkle internal node, is the one exception: it is deliberately untagged and two wide, and `lib/commit` records that every tagged value is three wide or more, which is what stops a leaf or a seed being read as an internal node.

```
document_secret = Poseidon2([11, r_hi, r_lo, s_hi, s_lo], 5)          # TAG_DOCUMENT_SECRET
secret_binding  = Poseidon2([12, document_secret, domain], 3)          # TAG_SECRET_BINDING
nullifier       = Poseidon2([7, policy_id, p0, p1, p2, p3,
                             document_secret, domain], 8)              # TAG_NULLIFIER
```

`r_hi, r_lo, s_hi, s_lo` come from `pack_pair`, a private helper in `lib/commit` reachable only through `pubkey_hash` and `document_secret`. It splits each component in half and packs each half big endian into one field element. It asserts the component length is even (`"commit: length must be even"`) and that each half is at most 31 bytes (`"commit: half does not fit a field element"`), so a component may not exceed 62 bytes.

`p0..p3` is the packed payload the policy defines. For `DOCUMENT_NUMBER_V1` it is

```
p = [issuing_state.data[0], number.data[0], number.data[1], number.data[2]]
```

taken from two field openings passed through `predicate::open_field`, which rebuilds each leaf with `commit::leaf`, walks it to the root and requires `commit::commitment(root, domain)` to equal the commitment the attribute circuit published. The identifiers are field id 2 (issuing state) and field id 3 (document number), fixed as `FIELD_ISSUING_STATE` and `FIELD_DOCUMENT_NUMBER` in `circuits/lib/attributes/src/lib.nr`.

`commit::nullifier` asserts `secret != 0` (`"commit: nullifier secret must be non-zero"`). It does not check the policy identifier: `policy::assert_supported` exists and is tested but is called by no circuit, because the identifier is a compile time constant inside each nullifier circuit rather than an input. The only use of the policy crate in circuit code is the constant `policy::DOCUMENT_NUMBER_V1` at line 61 of `circuits/lib/nullifier/src/lib.nr`.

The value is stable for one document in one domain because nothing in the preimage varies between sessions. That is deliberate and it is also the source of the linkability discussed in section 9.

## 3. The two properties the secret must have

The other inputs to the nullifier are a public policy identifier, a public domain, and fields printed on the data page. Without a secret the value would be a hash of things an adversary can hold, so anyone with a copy of a document could compute that holder's nullifier for any domain and test it against an application's stored set. That is an enumeration oracle over the whole registered population. The secret is what closes it.

The secret must be unguessable to a party that has not read the chip. This is the property that closes the oracle. Note the boundary precisely: it defeats a photocopy or a photograph of the data page, not a chip read (section 9).

The secret must not be choosable by the prover. If a holder can pick the secret, the same holder can pick a second one and register twice, which destroys the only thing a nullifier is for. Unguessability alone is not enough; a random value the holder generates is unguessable and useless here.

The two properties are established at different points. Unguessability comes from where the material lives. Non choosability has two parts, and both have to hold, which section 4 sets out.

## 4. The secret as shipped, and what it costs

`commit::document_secret` takes the Document Signer's signature `(r, s)` over the CMS signed attributes of the Security Object. `sod::outputs` publishes `secret_binding(document_secret(r, s), domain)` as the third return value of the Passive Authentication circuit; the secret itself never becomes public. The nullifier circuit takes the secret as a private input and asserts `secret_binding(secret, domain)` equals that published value (`"nullifier: secret does not match the authenticated document"`).

The signature fits the two properties, subject to what follows. It is fixed at issuance, so a prover who is bound to a genuine document cannot choose it, and it is not printed on the data page, so it cannot be guessed from a copy of one.

Non choosability requires a trust anchor, and the shipped verifier does not require one by default. The Passive Authentication circuit constrains the secret to material that verifies under the Document Signer's public key, and the verifier checks that the nullifier proof carries the same `secret_binding` the Passive Authentication proof published. That is not sufficient on its own. In `bin/sod/ecdsa_p256_sha256_ec512` the public key is a private input, and the circuit publishes only `dsc_commitment(pubkey_hash(pubkey_x, pubkey_y), dsc_salt)` with a prover supplied salt, so the proof says some key signed the document and nothing about whose key it is. `prover/src/verify.rs` says the same in the doc comment on `Verified::signer_registry_root`. A relying party that does not call `Policy::require_anchor` gets `require_trust_anchor: false` from `Policy::new`, and a prover can then generate its own key pair, sign a Security Object it built, choose `(r, s)` and mint as many secrets as it likes. Non choosability therefore holds only against a verifier that requires a trust anchor proof against a registry it published, using `bin/anchor/dsc_inclusion`. That circuit proves the signer key is in a published set and, as `lib/anchor` states, assumes whoever built the set checked the certificates behind it; verifying the country signing certificate in circuit is not implemented.

Non choosability also depends on one thing an auditor should verify against the ECDSA dependency, not against this repository. ECDSA verification accepts `(r, s)` exactly when it accepts `(r, n - s)`, so two representations of the same signing act exist and they hash to two different secrets. `circuits/lib/sig/src/lib.nr` documents that the backend rejects any `s` above `n/2` and aborts rather than returning false, which would force the low `s` representative and make the secret canonical. That is a claim in a module comment about the external `ecdsa` and `bigcurve` libraries, and nothing in this repository tests it. If it were ever untrue, a prover could choose between two secrets for one document and produce two nullifiers in one domain.

`lib/sig` also states that normalization of `s` before witness building is the caller's job and that no such code exists yet. That is true of the path a real document would take: the `prover` crate is verification only (`field.rs`, `layout.rs`, `verify.rs`) and builds no witnesses. It is not true of the whole repository. `circuits/fixtures/generator/src/ec.rs` defines `normalize_s`, applies it to every signature it generates in `sign_sha256`, and tests it. The test fixtures are therefore already low `s`, which is why the circuit tests pass and why the gap would only show against a real document.

The cost is reissue. A replacement document carries a different signature, so it produces a different secret and a different nullifier. Whatever the policy says about which fields it uses, no value derived from this secret survives document replacement. `commit::document_secret` documents this, and it is why only the document number policy is built on it.

There is also a size limit. `pack_pair` rejects components longer than 62 bytes, so `document_secret` as written covers the ECDSA curves the repository wraps (P-256, P-384, brainpoolP384r1) and cannot take an RSA signature. Only one Passive Authentication variant exists today, `bin/sod/ecdsa_p256_sha256_ec512`. `circuits/lib/rsa` implements PKCS#1 v1.5 with SHA-256 and is a workspace member, but no circuit depends on it, so what is missing for RSA is a circuit and a secret derivation, not the signature check. That derivation is a new specification, not a new caller.

## 5. Policy identifiers

A policy fixes which document fields derive the payload, and therefore what uniqueness the value carries. The identifier is hashed into the nullifier preimage, so two policies cannot produce the same value for the same holder.

Identifiers encode a family and a version as `family * 1000 + version`. The constants in `circuits/lib/policy/src/lib.nr` are:

| Constant | Value |
|---|---|
| `FAMILY_DOCUMENT_NUMBER` | 1 |
| `FAMILY_MRZ_STABLE` | 2 |
| `FAMILY_NATIONAL_IDENTIFIER` | 3 |
| `DOCUMENT_NUMBER_V1` | 1001 |
| `MRZ_STABLE_V1` | 2001 |
| `NATIONAL_IDENTIFIER_V1` | 3001 |

Family numbers are not identifiers. `assert_supported` accepts only the three identifier values and rejects anything else with `"policy: unsupported policy identifier"`, including a bare family number and an unminted version; its tests cover 9999 and `FAMILY_MRZ_STABLE`.

A revision takes a new version and therefore a new identifier. The consequence is operational, not cosmetic: values derived under the old identifier and the new one are unrelated, so revising a policy is a migration for every application that used it, and every existing registration has to be re-established or carried forward by some other means. There is no upgrade path built into the scheme.

A policy identifier must pin the packing as well as the field selection. Two profiles that select "the same" fields but pack them differently produce different payloads and therefore different nullifiers for the same holder. `attributes::td3` commits `FIELD_NAME` with length 39 and `attributes::td1` commits it with length 30, so a name based policy defined for both profiles has to specify a payload construction the two agree on, or it is not one policy.

## 6. Which policies are defined and which exist in a circuit

Only `DOCUMENT_NUMBER_V1` is implemented. It has a derivation function, `nullifier::document_number` in `circuits/lib/nullifier/src/lib.nr`, and a circuit, `circuits/bin/nullifier/document_number/src/main.nr`.

`MRZ_STABLE_V1` and `NATIONAL_IDENTIFIER_V1` are reserved identifiers only. No derivation function, no payload definition and no circuit exists for either. The comments in `lib/policy` describe what those families are intended to mean; they are intent, not implementation.

`MRZ_STABLE_V1` in particular cannot be implemented as described on top of the shipped secret. Its stated point is stability across reissue, and the shipped secret changes on reissue, so a circuit that combined the two would produce a value that fails the promise its identifier makes. A reissue stable policy needs a secret that is not chip bound, and no such source is specified or implemented here. Section 9 sets out what that would cost.

The circuit's public inputs, taken from the generated `layout.manifest` in the prover crate, are:

```
nullifier_document_number  commitment  secret_binding  domain  context  return[0]
```

The policy identifier is not among them. The module comment in `circuits/lib/policy/src/lib.nr` says the identifier is a public input; that is not true of the shipped circuit. A verifier learns which policy it received from the verification key it accepted, and from nothing else. Either the circuit should publish the identifier or that comment should be corrected; until then, verification key selection is load bearing and must be treated as such.

Measured with `nargo info` and recorded in the message of commit `60f7fef` in the circuits repository, `nullifier_document_number` is 56 ACIR opcodes, against 35096 for `sod_ecdsa_p256_sha256_ec512` in the same measurement. Neither has been re-measured for this document. The one commit since, `613231b`, added files only (the anchor library and circuit, quoted at 340 ACIR opcodes in its own message) and touched neither circuit named here. The nullifier is cheap; the document authentication it depends on is not.

## 7. One domain, exactly one policy

This is the rule an integrator is most likely to break.

An application domain must fix exactly one policy, and must accept exactly one nullifier circuit variant for that domain.

The reason is direct. The identifier is inside the hash preimage, so the same holder under two policies produces two unrelated values. An application that accepts both gets two registrations from one person and has no way to tell that they belong together, since neither value reveals anything about the other. Accepting two policies does not weaken uniqueness at the margin, it removes it: whatever the stricter policy would have prevented, the looser one now permits.

The same applies to a policy accepted alongside a revision of itself, because a revision is a different identifier by construction.

Two mechanical gaps in the shipped verifier (`prover/src/verify.rs`) make this easy to get wrong, and an integrator has to close both.

`Policy::accept` pushes onto a `Vec` of accepted verification key hashes per circuit, and `Circuit::Nullifier` is one circuit in that map. Once a second nullifier circuit exists, accepting two key hashes for `Circuit::Nullifier` silently admits two policies in one domain, and `Circuit::name` returns the same string `"nullifier"` for every variant, so no failure message would distinguish them. (The `Policy` struct in the prover crate is the verifier's acceptance list; it is unrelated to the policy identifiers in this document, despite the name.)

`verify_bundle` rejects a bundle with more than one Passive Authentication proof (`MoreThanOneSecurityObjectProof`), but has no equivalent check for nullifier proofs. It processes each one and assigns to the same `nullifier` variable, so a bundle carrying several nullifier proofs is accepted and every value but the last is dropped without an error. A relying party should require exactly one.

## 8. What a verifier must check

The nullifier circuit alone does not prove that the fields and the secret came from the same document. It opens fields against `commitment` and checks the secret against `secret_binding`, and those two public inputs are independent within the circuit. What links them is the set of equalities across the bundle, implemented in `prover/src/verify.rs`.

The nullifier proof's `secret_binding` (public input index 1) must equal the Passive Authentication proof's `return[2]`, which `prover/src/layout.rs` reads through `sod_secret_binding` at index 4. Without this check, the prover supplies any secret it likes and can mint unlimited nullifiers; the failure is reported as `NullifierFromAnotherDocument`.

The nullifier proof's `commitment` must be one an attribute proof in the bundle published, and that attribute proof must chain through a data group binding to the same Security Object. Without this check, a prover holding one document's secret can pair it with field openings from any commitment it can construct and produce many values from one document. The failure is `UnlinkedCommitment`.

Every proof in the bundle must carry the verifier's `domain` and its issued `context`, and the context must be non-zero. The domain is inside the commitment, the secret binding and the nullifier itself, so a mismatch means the values were derived for someone else's application.

Every proof must be verified under a verification key the relying party accepts in advance. This is what states which policy, which profile and which algorithm variant were used, since none of those are public inputs of the nullifier circuit.

A trust anchor must be required. `Policy::require_anchor` sets `require_trust_anchor` and the registry root the anchor proof has to be against; `Policy::new` leaves it off. Without it the bundle establishes that some key signed the document and nothing about whose key it is, which as section 4 explains means the secret is prover choosable and the uniqueness property does not hold at all.

## 9. Limits that remain

Anyone who has read the chip can compute the holder's nullifier. The secret is static data stored on the document, so a party that has ever performed a full chip read (a border, a hotel, an earlier application that read more than it needed) retains the ability to derive that document's secret and, with the printed fields, the holder's nullifier in any domain. It can also produce a valid proof and register in the holder's place, because nothing in this repository proves the chip was physically present at proving time: `circuits/bin` contains no Active Authentication or Chip Authentication circuit. For Doc 9303 documents, chip access is normally gated by keys derived from printed data or by a printed card password, so physical possession of the document is usually enough to obtain that dump. That is a statement about the standard, not about this repository: no access control protocol appears anywhere in these circuits, and nothing here can be used to check it. The honest statement of the unguessability property is therefore "not derivable from a photocopy of the data page", and not "requires the holder's consent" or "requires the document at the time of proving".

There is no deduplication across documents. Every implemented value is per document. A holder with a passport and a national identity card registers twice, and the two values are unrelated. A holder whose document is replaced registers again, and the application cannot connect the new registration to the old one, nor detect that the old one should be retired. Applications that need one registration per person across documents cannot get it from what is implemented here.

Withholding the nullifier proof does not make a bundle unlinkable within a domain. `sod::outputs` publishes `econtent_binding` and `secret_binding`, both deterministic functions of document data and the public domain with no session salt, so both are stable per document per domain across sessions. Any relying party can deduplicate on either one without a nullifier proof at all, which also means an application can bypass the policy scheme entirely and silently break the one domain, one policy rule while appearing to follow it. This is a consequence of the values needing to be stable enough to link proofs; it is not a defect in the nullifier, but it must be in the threat model.

Any policy built on printed fields carries a collision risk, and reissue stability is what forces a policy onto printed fields. Under the shipped policy a collision between two distinct holders is infeasible rather than impossible: it needs either a Poseidon2 collision at the width `commit::nullifier` uses or two documents carrying the same Document Signer signature. The payload fields contribute separation, but the secret is what carries the argument. A policy that promises stability across reissue cannot use a secret that changes on reissue, so both its payload and its secret would have to be functions of data that survives reissue, which is printed identity data. Then two holders who share those values produce the same nullifier, and the second is refused registration as a duplicate: a denial of service against a real person, with no evidence available to either party about why. The MRZ makes this worse than "full name plus date of birth" suggests. The fixed widths are in the code: `attributes::td3` commits `FIELD_NAME` with length 39 and `attributes::td1` with length 30. That long names are truncated to fit those widths, and that transliteration varies by issuer, comes from the standard and from practice, not from anything in this repository. Such a policy would also stop being unguessable from a photocopy unless a keyed service stood between the printed fields and the output, at which point that service is a trusted party and its availability is a dependency of every registration. No such service is specified or implemented here. And it would not be fully stable either: a legal name change or a corrected birth date breaks it exactly as a reissue would.

The payload construction has edges. `nullifier::document_number` packs `number.data[0]`, `number.data[1]` and `number.data[2]` and drops `number.data[3]`. `normalize::pack_to_4` puts 31 bytes in each element, so what survives is the first 93 bytes of the field, and `normalize::MAX_FIELD_BYTES` allows 124. Both shipped MRZ profiles commit a nine byte document number, so today only `data[0]` is ever non-zero and nothing is lost. A profile that committed a document number field longer than 93 bytes would truncate silently. The same construction takes only `issuing_state.data[0]`, which covers the three byte code both profiles commit.

`mrz::check_digit_ok` accepts the filler character 0x3C in place of a check digit, and `td3_validate` and `td1_validate` call it with that allowance for the document number and the optional data. The comment above it gives the reason: Doc 9303 lets a document number longer than nine characters continue into the optional data field and leave its own check digit position as filler. That reading of the standard should be checked against Doc 9303 itself. What the code fixes either way is that the committed document number field holds nine characters.

The field identifiers are duplicated rather than imported. `lib/nullifier` asserts `field_id == 2` and `field_id == 3` as literals, with the messages `"nullifier: first opening must be the issuing state"` and `"nullifier: second opening must be the document number"`, and `bin/nullifier/document_number/src/main.nr` builds both `FieldOpening` values with the same literals inline. `lib/nullifier/Nargo.toml` lists commit, policy and predicate as dependencies and not attributes, so `attributes::FIELD_ISSUING_STATE` and `attributes::FIELD_DOCUMENT_NUMBER` are copied in three places with no compile time link. A renumbering in `lib/attributes` would not break the build.

Everything above rests on Poseidon2 over BN254 being collision resistant and preimage resistant at the widths used, and on the domain separation tags being unique per role. `TAG_NULLIFIER` is 7, `TAG_DOCUMENT_SECRET` is 11 and `TAG_SECRET_BINDING` is 12; new roles must take new tags, and no tag may be reused at the same width.

## 10. Test coverage as it stands

The tests that exist for this area are in `circuits/lib/policy/src/lib.nr` (three, covering acceptance of the three identifiers and rejection of an unknown value and of a bare family number), `circuits/lib/nullifier/src/lib.nr` (six, covering determinism within a domain, unlinkability across domains, dependence on the secret, a guessed secret, openings in the wrong order and a field taken from another document), and `circuits/bin/nullifier/document_number/src/main.nr` (two, covering a stable value and a secret the prover invented). Running `nargo test` on each of the three packages gives 3, 6 and 2 tests respectively, all passing.

No test covers the one domain, one policy rule, because a second policy does not exist to violate it with. No test covers a bundle carrying two nullifier proofs, and `prover/src/verify.rs` has no tests of `verify_bundle` at all: the twelve tests in that crate are in `field.rs` and `layout.rs`, and the `layout.rs` tests check the public input table against `layout.manifest` rather than exercising the bundle equalities.
