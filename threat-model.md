# Threat model

This chapter states what the zkICAO circuits, the off chain verifier and the reference contract defend against, what they leave to the parties around them, and what they do not address at all. It describes the code as it exists across the organization's repositories. Where a protection is claimed here, a constraint in the code enforces it, and the assertion message or failure variant is quoted so a reader can find it.

The code moves quickly, so this chapter is revised with the code rather than pinned to a commit: every claim below was checked against the trees that the revision introducing it shipped with, and a claim that stops being true is a defect in this document. The paths named here are checked mechanically by this repository's own checker against a circuits checkout; the behavioral claims are not, which is why each quotes the string that a search of the code finds.

zkICAO is an independent project. It is not affiliated with, endorsed by, or certified by ICAO or any government.

## 1. Scope

In scope: the circuits workspace (the libraries under `circuits/lib` and every binary under `circuits/bin`, currently twenty three instantiations across Passive Authentication, data group extraction, attribute commitment, predicates, nullifier, trust anchoring, chip presence, recursive registration and recursive session aggregation), the Groth16 mirror of the predicate layer under `circuits/groth16`, the off chain bundle verifier in `prover/src/verify.rs`, and the reference registry contract in `contracts/src/ZkIcaoRegistry.sol` with the verifiers it calls.

Out of scope, because no code for it exists in these repositories: reading a chip over a radio, building witnesses from a genuine document, transporting proofs between parties, wallet software and any consent interface, and custody of the holder's secrets between sessions.

Maturity matters to how this document should be read. Every end to end test runs against synthetic documents produced by `circuits/fixtures/generator`, which generates its own Document Signer keys through the openssl command line tool and signs the Doc 9303 specimen machine readable zones. No genuine issued document has been exercised through this pipeline, and no third party security audit has taken place.

## 2. The attacker

### 2.1 What the attacker can do

The attacker is assumed to have all of the following.

A complete copy of the data page. That means the full machine readable zone, character for character. This matters more than it first appears, because DG1 is exactly the machine readable zone under two DER templates (`61 len` then `5F1F len`, with the characters starting at `attributes::DG1_MRZ_OFFSET = 5`). An attacker with a photocopy therefore knows DG1 byte for byte and can compute `SHA-256(DG1)` and anything derived from it.

Unlimited observation of proofs. Every public input of every proof, from this holder and from every other holder, across sessions and across relying parties, is visible. Public inputs are enumerated per circuit in `prover/layout.manifest`.

Operation of a relying party. The attacker can stand up a verifier, choose the `domain` and `context` it issues, choose `set_root`, `minimum`, `maximum`, `field_id`, `dg_number`, `registry_root` and `current_yyyymmdd`, and record every proof presented to it. On a chain, the attacker can operate any number of accounts and call `register` with any calldata.

Arbitrary witnesses. Every private input to every circuit is under the attacker's control, bounded only by the constraints. This includes every buffer, every offset, every limb, every Merkle sibling, every salt and the claimed secret. It includes presenting a genuine signature in its non canonical high `s` form, which section 3.1 addresses.

Their own signing keys. The attacker can generate elliptic curve or RSA key pairs, build a well formed Security Object and CMS signed attributes over data of their choosing, and sign them. Nothing prevents this, and the fixture generator demonstrates it costs nothing.

### 2.2 What the attacker cannot do

The attacker cannot find SHA-256 collisions or preimages, cannot find Poseidon2 collisions or preimages, cannot forge ECDSA or RSA signatures without the private key, and cannot produce an accepting UltraHonk or Groth16 proof for a statement the constraint system rejects.

The attacker does not hold the private key of a genuine Document Signer or Country Signing Certification Authority.

The attacker does not control the holder's proving device. Compromise of that device is a separate failure discussed in section 7.

Physical possession of the chip is deliberately left open. Whether the attacker has it is the line that separates several of the protections below from several of the gaps, and section 3.7 is about moving that line.

## 3. What the circuits constrain

### 3.1 Passive Authentication

The chain has three links. `sod::link` checks the first two and the variant circuit checks the third. The Security Object content is hashed with `hash::sha256_bounded`. The messageDigest signed attribute is located and read by `cms::message_digest_sha256`, which refuses an attribute that is not messageDigest (`"cms: attribute is not messageDigest"`), a value that is not a 32 byte octet string (`"cms: digest is not an OCTET STRING"`, `"cms: digest is not 32 bytes"`), a set header that is absent (`"cms: attribute values are not a SET"`), an offset too small to hold the header (`"cms: digest offset too small"`), and a digest running past the declared length (`"cms: digest runs past the signed attributes"`). The two are then compared byte by byte, failing with `"sod: security object digest does not match the signed attribute"`. The signature is then checked over the hash of the signed attributes.

The offsets into the signed attributes and the Security Object are supplied by the prover, and their flexibility buys the attacker nothing: every byte window they can point at lies inside data fixed by the issuer's signature, so making a chosen digest appear at one of them is a preimage problem, not a parsing problem.

Eight signature variants ship: ECDSA over P-256 (with Security Object buffers of 512 and 1024 bytes), P-384 and Brainpool P-384r1, and RSA PKCS#1 v1.5 at 2048 (both buffer sizes), 3072 and 4096 bits, all over SHA-256. Each calls the matching wrapper in `lib/core/sig` or `lib/core/rsa`.

The elliptic curve wrappers call `validate_in_field()` on the decoded coordinates and scalars, because byte deserialization in noir-bignum enforces only that a value is below `2^MOD_BITS`, not that it is reduced. The ECDSA backend additionally rejects any signature whose `s` exceeds `n/2` rather than returning false. That rejection carries a load beyond hygiene: the document secret of section 3.5 is derived from the signature bytes, and ECDSA accepts `(r, s)` exactly when it accepts `(r, n - s)`, so if both forms verified, one document would yield two secrets and therefore two nullifiers per application. With high `s` rejected, exactly one form satisfies the circuit, and the header of `lib/core/sig` records both the rule and the witness preparation obligation it creates.

The RSA path recovers the encoded message by raising the signature to 65537 and then constrains every byte of it: the leading zero (`"rsa: encoded message must start with zero"`), the block type (`"rsa: wrong block type"`), the whole padding run (`"rsa: padding must be all ones"`), the separator (`"rsa: missing padding separator"`), the SHA-256 digest info (`"rsa: digest info does not describe sha-256"`) and the digest itself (`"rsa: digest does not match"`). Constraining the full padding run is what stops a forger placing the digest info at another offset. Only the exponent 65537 is implemented, so a key with any other exponent must be rejected rather than silently verified against the wrong arithmetic. RSA signatures are unique per message and key, so the canonical form question ECDSA raises does not arise.

Every variant publishes three values: `econtent_binding`, `dsc_commitment` and `secret_binding`. The Document Signer public key itself stays private. The RSA variants derive their commitments with `commit::modulus_hash` and `commit::limbs_document_secret`, which fold every limb, so the signer key commitment and the document secret are functions of the whole modulus and the whole signature.

### 3.2 Data group extraction

`dg_extract::extract_sha256` re-hashes the Security Object and requires the result to reproduce the binding the Passive Authentication proof published, failing with `"dg_extract: security object does not match the authenticated one"`. It then asserts the SHA-256 algorithm identifier is present (`"lds: wrong hash algorithm oid"`) and reads one entry through `lds::dg_entry_sha256`, which checks the DER header shape, the data group number against the public input (`"lds: dg entry wrong dg number"`), the number's range and the bounds.

Because `dg_number` is a public input, a relying party states which data group a proof concerns rather than accepting the prover's later description of it. Two buffer sizes ship, 512 and 1024 bytes; the smaller holds Security Objects of up to twelve SHA-256 entries and the larger holds a full sixteen.

### 3.3 Attribute commitment

`attributes::td3`, `attributes::td2` and `attributes::td1` re-hash the supplied DG1 and require the result to reproduce the data group binding the extraction proof published, failing with `"attributes: data group was not the authenticated one"`. The DER template is checked by `check_dg1_template`, which pins the total length (`"attributes: unexpected dg1 length"`), both tags and both declared lengths. The three layouts carry 88, 72 and 90 machine readable zone characters, so a document presented to the wrong profile fails at the length check rather than producing a commitment over fields read at the wrong offsets.

Check digits are verified over the document number, birth date, expiry date, the optional data where the layout has its own digit, and the composite. Dates are parsed strictly: non digits, months outside 1 to 12 and impossible calendar days all fail, including leap year handling in `assert_day_in_month`. Doc 9303's own filler conventions are honored where the standard requires them and nowhere else.

`current_yyyymmdd` is a public input because it decides how a two digit birth year resolves. The comment on `mrz::birth_date_to_int` states the reason: "a prover free to choose it can move a birth date by a century", and a test demonstrates the attack the public input closes: a holder born in 2010 reads as born in 1910 under a prover chosen date and passes an adult check.

The commitment is built over sixteen leaves with `commit::leaf`, each carrying its own field identifier, length, packed data and per field entropy derived from `commit::entropy_seed` and `commit::field_entropy`. The seed rejects a zero session salt at `"commit: session salt must be non-zero"`. Only the commitment leaves the circuit. Birth and expiry dates are computed inside and never published.

### 3.4 Field predicates

Every predicate opens the field first, through `open` in `lib/claims/predicate`, which the nullifier reaches through the exported `predicate::open_field`. It bounds the field identifier, rebuilds the leaf, walks it to a root using `field_id - 1` as the Merkle index, and requires `commit::commitment(root, domain)` to equal the commitment the attribute circuit published, failing with `"predicate: field is not part of the committed document"`. Deriving the index from the field identifier rather than accepting it separately is what stops a value being claimed under a different identifier.

On top of that opening: `compare` requires a non empty range, requires the value to fit one field element and to be an integer, and bounds it. `member` requires a Merkle path from `commit::set_entry(opening.data)` to the published root (`"predicate: value is not in the set"`). `reveal` requires the published value and length to match the opened ones. Every value in the binding chain starts with a role tag, and Merkle internal nodes are the one untagged hash at the one width no tagged value uses, so no value produced for one role can stand in for another.

### 3.5 Nullifier

`nullifier::document_number` pins the two openings to specific fields (`"nullifier: first opening must be the issuing state"`, `"nullifier: second opening must be the document number"`), opens both against the attribute commitment, and requires `commit::secret_binding(secret, domain)` to equal the binding the Passive Authentication proof published, failing with `"nullifier: secret does not match the authenticated document"`.

The secret is `commit::document_secret` over the Security Object signature, or its limb folding twin for RSA. The comment on that function gives the two properties required: it is fixed at issuance so a prover cannot choose it, and it is not printed on the data page so it cannot be guessed from a photocopy. `commit::nullifier` rejects a zero secret. Together with the canonical `s` rule of section 3.1, one document yields exactly one nullifier per application.

The resulting value is deterministic per document per `domain`, and unlinkable across domains because `domain` is hashed into it. The policy identifier is `policy::DOCUMENT_NUMBER_V1`, hashed in as a constant rather than published, so a relying party learns which policy produced a nullifier from which verification key it accepted, and an application must accept exactly one nullifier verification key per domain. The header of `lib/claims/policy` states why: accepting two "lets one holder present two different nullifiers, which defeats the uniqueness the nullifier exists to provide".

### 3.6 Document Signer trust

Two anchor modes ship, and they differ in who is trusted to have checked what.

`anchor::prove_signer_is_trusted` hashes the signer key, requires a Merkle path from that hash to a published registry root (`"anchor: signer key is not in the published set"`), and returns the same salted commitment Passive Authentication publishes. What it assumes is recorded in its own header: whoever built the set checked the certificates behind it.

`anchor::prove_signer_is_certified` removes that assumption for the Document Signer certificate. It verifies the country signing key's RSA PKCS#1 v1.5 signature over the certificate, checks the certificate is valid on the supplied date through `x509::assert_valid_at` (`"x509: certificate is not yet valid"`, `"x509: certificate has expired"`), requires the country signing key to sit in the published master list (`"anchor: country signing key is not in the published list"`), and reads the certified key out of the signed certificate rather than taking it as an input. What remains trusted is the list of country signing keys, which is the trust anchor of the whole system and cannot be derived from the document. The instantiation covers an RSA-2048 authority and a certificate of up to 512 bytes; a state whose authority signs with another algorithm has no chain circuit yet. Validity times are read as UTCTime only, the form RFC 5280 requires below 2050, and a GeneralizedTime fails rather than being read as something else.

### 3.7 Chip presence

`bin/chip/active_p256_sha256` is the one statement in the protocol that a copy of a document's data cannot make. Doc 9303 Part 11 Active Authentication gives the chip a key pair whose public half sits in DG15, covered by the Security Object like any other data group, and whose private half never leaves the chip. The circuit checks the data group binding against the one the extraction proof published (`"chip: data group was not the authenticated one"`), reads the public key out of the signed data group rather than taking it as an input, and verifies the chip's ECDSA P-256 answer over SHA-256.

The challenge is eight bytes, because the chip's INTERNAL AUTHENTICATE command takes exactly eight, so anything wider could never be signed by real hardware. It is bound to the session by derivation rather than by transport: the circuit requires the challenge to equal the first eight bytes of SHA-256 over the context's 32 byte big endian form (`"chip: the challenge is not this session's context"`), and the terminal derives the same bytes when it issues the challenge, so the two sides share nothing beyond the context itself. An answer kept from an earlier exchange fails because its challenge derived from an earlier context.

The freshness this buys is exactly the freshness of the context. A relying party that issues a fresh unpredictable context per exchange gets presence at this exchange. The on chain registry uses the sender address as the context, which is stable, so there a chip proof would mean the chip answered for this sender at some point, not at this block; the registry accordingly does not take one. The derived challenge is a 64 bit value, so an attacker replaying recorded answers needs a recorded challenge to collide with the current derivation, which is negligible across any realistic number of recorded sessions and does not help against the signature itself.

What this does not rule out is a relay: a terminal that forwards the challenge to a genuine chip somewhere else. Nothing in a proof can, since ruling that out is a distance bound and therefore a property of the reader's radio. It also does not cover chips whose Active Authentication key is RSA, which answer under ISO 9796-2 with SHA-1, neither of which is carried; and Chip Authentication, the Diffie Hellman variant of Part 11, is not implemented.

### 3.8 Recursive aggregation

Two registration circuits verify a whole document chain in one proof: Passive Authentication, a data group 1 extraction, the attribute commitment, and one of the two anchors. Their linkage is not a checklist: each shared value appears once as a witness and is placed into the public inputs of every inner proof that carries it, so the equalities the off chain verifier enforces between separate proofs hold by construction. The extraction is pinned to data group 1, and the four exposed values are the commitment, the secret binding, the date and the registry root. The session circuit does the same for a compare and a member predicate over one commitment.

The verification key hashes of the inner circuits are compiled in from a generated `keys.nr`, so a registration circuit's identity fixes exactly which variants it aggregates. The keys themselves stay private witnesses; the backend constrains each against its pinned hash. A stale pin is not a build error but a proof that fails to verify, which is why continuous integration regenerates the hashes and fails on drift.

The backend property this rests on has to be stated: `bb` produces a proof over an unsatisfied witness without complaint, so executing and even proving a recursive circuit means nothing on its own. A forged inner proof surfaces only when the outer proof is verified. Verification is the only outcome that carries information, on this stack and equally on the Groth16 stack of section 6.

### 3.9 Session scoping

Every binary circuit asserts both scope values are set, with its own message, `"sod: context must be set"` through `"registration: domain must be set"`. `domain` enters every value a verifier stores or compares across sessions; `context` enters none of them, so a proof is scoped to one session without changing any stored value between sessions. The header of `lib/core/commit` states the rule, and the on chain registry closes the loop by taking the sender address as the context, so a proof prepared for one sender reverts in any other sender's transaction.

## 4. What the off chain verifier enforces

`verify_bundle` in `prover/src/verify.rs` runs the whole checklist in a fixed order. It rejects a zero context (`ContextNotSet`) and a zero domain (`DomainNotSet`), and rejects a policy that requires a trust anchor without fixing a registry (`RegistryRootNotSet`), which closes the configuration where any registry the prover built would satisfy the requirement. For every proof it requires the verification key to be one the policy accepts for that circuit (`UntrustedVerificationKey`), requires `bb verify` to succeed (`ProofRejected`), and requires the proof's domain and context to equal the policy's (`WrongDomain`, `WrongContext`). Acceptance is decided on the key bytes the proof is actually verified against, not on a digest supplied beside them.

A bundle must establish exactly one document, either a Passive Authentication proof or a registration proof (`NoSecurityObjectProof`, `MoreThanOneSecurityObjectProof`). Around a Passive Authentication proof, every extraction must reference its `econtent_binding` (`UnlinkedDataGroup`), every attribute proof must reference an extracted data group binding, every predicate and the nullifier must reference a committed document (`UnlinkedCommitment`), the nullifier's secret binding must equal the document's (`NullifierFromAnotherDocument`), at most one nullifier proof may appear (`MoreThanOneNullifierProof`), and a chip proof must attach to a data group this document's Security Object committed to (`ChipFromAnotherDocument`). Anchor proofs must be about the key that signed the document (`AnchorForAnotherSigner`) and against the policy's registry (`AnchorAgainstAnotherRegistry`), and a required anchor must be present (`NoTrustAnchorProof`).

Beside a registration proof, leaf proofs of the kinds it aggregates are rejected outright (`NotLinkableToRegistration`), because the aggregate deliberately does not expose the values they would have to match. Signer trust is proved inside the registration, so the anchor requirement is satisfied by construction and the proved root is still checked against the policy's.

Dates are read from every proof that resolves them, checked against the policy window when one is set (`DateOutsideWindow`), and required to agree across the bundle (`InconsistentDates`), so the date that resolved a birth year is the date the certificate was checked against.

What the verifier returns is as load bearing as what it rejects. `Verified::statements` lists what was actually proved, one `Statement` per claim: which data group was extracted, `ChipPresent`, and the field, bounds, set root or revealed value of each predicate. A relying party that does not read the statements knows only that a signed document exists and that the bundle is internally consistent, not that any question it asked was answered. `verify_session` covers the later exchanges: it accepts predicate, session and chip proofs against a stored registration, requires the commitment to match the stored one, and rejects document establishing proofs (`NotASessionProof`).

## 5. What the contract enforces

`ZkIcaoRegistry.register` takes a registration proof and a nullifier proof and performs the aggregate bundle checklist in Solidity: input counts (`MalformedInputs`), the domain on both proofs (`WrongDomain`), the context, which is the sender address, on both proofs (`WrongContext`), the pinned signer registry root (`WrongRegistry`), the date window fixed at deployment (`DateOutsideWindow`), the commitment linkage between the two proofs (`UnlinkedCommitment`), the secret binding linkage (`NullifierFromAnotherDocument`), nullifier uniqueness (`AlreadyRegistered`), and then verifies both proofs (`RegistrationProofRejected`, `NullifierProofRejected`) before storing the nullifier and the commitment.

The contract compares field elements and stores one; it derives nothing. Every Poseidon2 in the protocol is computed inside a proof and reaches the chain as a public input, which is the design constraint that keeps the contract affordable on chains with no Poseidon2 precompile, and a test measures the contract's own cost with verification removed so that giving the constraint up would show as a number.

What the deployer is trusted for is explicit and immutable: the two verifier contracts, the domain, the signer registry root and the date window are constructor parameters, and there is no owner, no upgrade path and no setter. A deployment with a wrong or malicious verifier is a wrong deployment, not an attack on a correct one; the deploy script takes every value from the environment and refuses to invent defaults. The date window also means an honest deployment goes stale: past `latestDate` every registration reverts until a new deployment exists, which is a liveness property the deployer chooses, not a defect.

The generated UltraHonk verifier sits a few hundred bytes under the EIP-170 size limit only at the optimizer setting pinned in `foundry.toml`, which is why that file calls the pin load bearing; at the Foundry default the verifier does not deploy at all. A test measures the deployed sizes so the margin cannot regress silently.

## 6. The second proving stack

The predicate layer exists a second time under `circuits/groth16`, as circom circuits proved with rapidsnark and verified by a generated Groth16 contract, for the case where a verifier lives on chain and proof size is what costs. Three properties carry the security story.

The Poseidon2 the circom side computes is the Poseidon2 the Noir side computes. This is not assumed from shared constants, it is tested: the agreement check opens a commitment the Noir circuits produced inside the circom predicate, across every sponge width the protocol uses, and adversarial variants are refused.

Neither the witness calculator nor the prover checks a constraint. rapidsnark produces a proof over an unsatisfied witness exactly as `bb` does, and the repository keeps a forged fixture to demonstrate it: snarkjs answers `Invalid proof` and the on chain verifier refuses it. Verification is the only check, stated in both stacks' documentation.

The proving key shipped for tests came from a local phase 2 contribution, so it belongs to a development ceremony and to nothing else. A deployment that wants Groth16's verification price must run its own ceremony and export its own verifier; UltraHonk needs no ceremony, which is the other side of the trade the two stacks exist to offer.

## 7. What the system does not protect against

A copy of a chip's data, wherever no chip statement is demanded. Everything except the chip circuit checks static data, so an attacker who read a genuine chip holds everything needed to produce valid proofs, including the genuine holder's nullifier, since the document secret is derived from the Security Object signature that same read yields. A relying party that needs liveness has to demand `ChipPresent` in the statements and issue fresh contexts; one that does not has chosen Passive Authentication's limits.

A relay of the chip itself, as section 3.7 states.

Correlation through the signer commitment where the public registry convention is used. `dsc_commitment` with a zero salt is a deterministic function of the signer key, stable across applications, and identifies the issuing state and batch, linking every holder who shares a signer. A random salt closes this and costs the verifier an anchor proof instead of a table lookup. The salt is the prover's choice and the deployment's convention, not a circuit guarantee.

Linkage the wallet creates. A reused or predictable `session_salt` links sessions or worse: the salt is the only hiding input in the commitment chain, and the comment on `commit::entropy_seed` spells out that with a guessable salt a photocopy suffices to recompute a commitment and test it against a registry. Distinct applications must also use distinct domains, or their nullifiers become linkable by construction.

Uniqueness beyond one document. The nullifier is unique per document per domain, not per person. A holder with a passport and an identity card, or documents from two states, is two registrations. A replacement document is a new registration, because the secret dies with the old chip. A reissue stable policy would need a secret source that survives reissue without becoming guessable or service dependent, and no such source ships; the policy library deliberately declares only what is implemented.

Revocation and validity beyond the date window. The expiry date is committed and can be bounded with `compare`, and the chain anchor checks certificate validity at the proving date, but nothing checks that a document was not reported lost, and no revocation list of any kind exists in the system.

Context freshness. The circuits require a non zero context; they cannot require an unpredictable one. A relying party that reuses contexts invites replay of whole bundles, and one that derives them predictably weakens the chip statement to the same degree.

The proving device. A compromised device leaks the document data and the document secret, which is sufficient to impersonate the holder to every application permanently. Side channels, faults and malware on that device are out of scope.

Denial of service, either against a relying party asked to verify many bundles or against a prover.

## 8. Assumptions

On the issuing state: the Document Signer key is not compromised, and the signed data is true. Passive Authentication cannot distinguish a correctly signed lie from a correctly signed truth. Check digits do not strengthen this: the 7-3-1 weighting misses substitutions differing by a multiple of ten, a test demonstrates it, and integrity rests entirely on the signature over DG1. The document number policy additionally assumes an issuing state does not reuse a document number across concurrently valid documents.

On witness preparation: the signature `s` must be normalized to `n - s` when it exceeds `n/2`, offsets must be located correctly, `session_salt` must be fresh entropy per session, and the RSA reduction parameter must be supplied correctly, which is a liveness obligation rather than a soundness one since the bignum backend constrains every multiplication against the modulus. The fixture generator does all of this for the synthetic documents; anything that reads real documents has to do the same.

On the toolchain: `circuits/TOOLCHAIN.md` pins the compilers, the proving backends and every circuit dependency for both stacks. Trusting a proof means trusting the Noir and circom compilers to lower the source into equivalent constraint systems, the pinned implementations of SHA-256, Poseidon2, ECDSA and bignum arithmetic, and the provers and verifiers behind them, along with whatever setup each proving system requires. The layout table in `prover/src/layout.rs` is guarded by the generated `layout.manifest` and the tests that read it.

On the relying party: it issues a fresh unpredictable context per exchange and rejects reuse, uses a domain distinct from other applications, accepts exactly one nullifier verification key per domain, requires the anchor with the registry root it trusts, sets a date window, and reads the returned statements to confirm the bundle answers what it asked. Off chain verification runs in the relying party's own process and nobody else observes it; a party that ignores the result has not verified.

On the deployer of a registry contract: the verifier addresses and policy values baked into the constructor are correct, and the signer registry root it pins was assembled from validated certificates using the same leaf derivation the circuits use.

## 9. Where the measured numbers live

Every performance and size number is measured, not estimated, and each lives where regeneration re-measures it: opcode counts per circuit in `architecture.md` reproduced by `nargo info`, gas and byte sizes printed by the contracts test suite under `forge test -vv`, and the registration proving figures in the commit messages that introduced them. Two of them are load bearing for this chapter: the UltraHonk verifier's margin under the EIP-170 limit, which section 5 covers, and the roughly hundredfold gap between verifying on chain with UltraHonk and with Groth16, which is the entire reason the second stack and its ceremony trade exist.

## 10. Summary of open gaps

The gaps below are stated as absent rather than planned.

No genuine issued document has been proved end to end; every fixture is synthetic and self signed. No third party audit has taken place. Digests other than SHA-256 have no circuit, which excludes documents whose Security Object or signatures use SHA-1, SHA-384 or SHA-512, and the chain anchor covers only an RSA-2048 authority over a certificate of up to 512 bytes. RSA public exponents other than 65537 are not verified. Certificates dated with GeneralizedTime, which RFC 5280 mandates from 2050, do not parse. Active Authentication for RSA chips and Chip Authentication are not implemented. Holders older than one hundred years resolve to the wrong century, a limit of two digit years in the machine readable zone itself. There is no revocation mechanism, no reissue stable nullifier policy, no wallet, and nothing that reads a physical chip.
