# Document profiles

A profile is the code that turns one data group of an ICAO Doc 9303 document into a commitment over its individual fields. It fixes three things: which bytes of the data group each field occupies, how those bytes become a canonical value, and which numeric identifier each field carries. Everything above the profile (range checks, set membership, disclosure, nullifiers) speaks in terms of those identifiers and that commitment, with the nullifier circuit additionally taking a document secret and the binding to it that the Passive Authentication circuit published. The profile is the single place where a document layout is interpreted.

Two profiles exist, both over DG1: `attributes::td3` for the passport layout and `attributes::td1` for the card layout, in `lib/attributes/src/lib.nr`. They are instantiated by the circuits `bin/attributes/mrz_td3_sha256` and `bin/attributes/mrz_td1_sha256`.

## Why the machine readable zone is the portable core

Doc 9303 makes DG1 mandatory on every compliant document and defines its content as the machine readable zone in a small fixed set of layouts. The field positions in those layouts are set by the standard and not by the issuing state. That is what lets one profile serve documents from any state: the offsets in `lib/mrz` are constants, not configuration.

Data a state defines for itself does not live in DG1. It lives in other data groups (DG13 is the usual example), where both the presence of the group and its internal structure are state specific. Those need their own profiles, which do not exist. See "What is not implemented" below.

## The DG1 container

DG1 is the machine readable zone wrapped in two nested DER templates, `61 len` then `5F1F len`. `check_dg1_template` asserts the whole header explicitly rather than decoding it generically:

```
dg1_len <= N                          // N is the circuit buffer, 128 bytes
dg1_len == DG1_MRZ_OFFSET + mrz_len
dg1[0] == 0x61
dg1[1] == mrz_len + 3
dg1[2] == 0x5f
dg1[3] == 0x1f
dg1[4] == mrz_len
```

The failure messages are `attributes: dg1 length exceeds buffer`, `attributes: unexpected dg1 length`, `attributes: dg1 is missing its template tag`, `attributes: dg1 template length mismatch`, `attributes: missing machine readable zone tag` for both tag bytes, and `attributes: machine readable zone length mismatch`.

`DG1_MRZ_OFFSET` is 5, so the characters begin at byte 5. Both length bytes are single byte short form values, which is sufficient because no defined machine readable zone reaches 128 characters, and it means a DG1 encoded with a long form length is rejected. The equality also fixes what gets hashed: `dg1_len` is the bound passed to `sha256_bounded` over a 128 byte buffer, so a prover cannot stretch the hashed prefix past the template or cut it short.

Because `dg1_len` is pinned to `5 + mrz_len` and the two layouts have different lengths (93 bytes for TD3, 95 for TD1, matching `TD3_DG1_LEN` and `TD1_DG1_LEN` in `lib/testdata`), a card DG1 cannot be read by the passport profile or the reverse. The test `rejects_a_card_layout_read_as_a_passport` in `lib/attributes` covers that direction and `rejects_a_passport_read_as_a_card` in `bin/attributes/mrz_td1_sha256` covers the other. Both expect `attributes: unexpected dg1 length`.

The only thing separating the layouts is length, checked in three places: `dg1_len`, the outer length byte `dg1[1]` and the inner length byte `dg1[4]`. No tag says which layout a DG1 holds. The document code at offset 0 is committed but never constrained, so the profile does not check that a TD3 document actually says `P`.

The profile itself verifies no signature. It computes `sha256_bounded(dg1, dg1_len)`, folds the digest into two field elements with `hash32_to_fields`, derives `dg_binding(dg_hash_fields, domain)` and asserts that this equals the `expected_dg_binding` public input, failing with `attributes: data group was not the authenticated one`. That input is the value published by the data group extraction proof, which in turn read the DG1 hash out of the Security Object using `lds::dg_entry_sha256`. The integrity of the machine readable zone rests entirely on that chain, and specifically on the Document Signer signature over the Security Object. `lib/lds` states its own caveat plainly: `dg_entry_sha256` checks the seven byte DER header (`30 25 02 01 <dg_number> 04 20`, `DG_ENTRY_SHA256_BYTES` = 39) at the offset it is given and does not walk the Security Object from its start, so the calling circuit is responsible for establishing that offset.

Only SHA-256 is implemented, in `lib/hash`. The circuit names carry the suffix `_sha256` because Doc 9303 lets the data group hash algorithm differ from the CMS digest algorithm. A document whose Security Object hashes data groups with anything else needs a different profile instance, which does not exist.

## Field identifiers

Identifiers are global constants in `lib/attributes` (`FIELD_DOCUMENT_CODE` through `FIELD_OPTIONAL_DATA`, and `FIELD_COUNT`). The predicate and nullifier layers do not import them: `lib/predicate` bounds the identifier to 1 through 16 with plain numbers, and `lib/nullifier` asserts `issuing_state.field_id == 2` and `document_number_field.field_id == 3` as literals. The numbering is a convention that has to hold in both places.

The identifier is bound into the leaf by `commit::leaf` and is a public input to every predicate circuit (`prover/layout.manifest` lists `field_id` first for `predicate_compare`, `predicate_member` and `predicate_reveal`), which is what stops a proof about one field being presented as a proof about another. The leaf index in the sixteen leaf tree is `field_id - 1`, from `walk_path(value, opening.field_id - 1, opening.siblings)`.

| Id | Constant | TD3 committed length | TD1 committed length |
| --- | --- | --- | --- |
| 1 | `FIELD_DOCUMENT_CODE` | 2 | 2 |
| 2 | `FIELD_ISSUING_STATE` | 3 | 3 |
| 3 | `FIELD_DOCUMENT_NUMBER` | 9 | 9 |
| 4 | `FIELD_NATIONALITY` | 3 | 3 |
| 5 | `FIELD_BIRTH_DATE` | 8 | 8 |
| 6 | `FIELD_SEX` | 1 | 1 |
| 7 | `FIELD_EXPIRY_DATE` | 8 | 8 |
| 8 | `FIELD_NAME` | 39 | 30 |
| 9 | `FIELD_OPTIONAL_DATA` | 14 | 11 |

`FIELD_COUNT` is 16. Identifiers 10 through 16 are committed as empty leaves: identifier set, length 0, data all zero, and per field entropy derived from the same seed. The tree is therefore always sixteen leaves wide whatever the profile, and a future profile can define fields at those identifiers without changing the shape or the path length. The opening check that every predicate runs (`predicate::open_field`, and the internal `open` behind it) accepts any identifier in 1 through 16, so an empty leaf can be opened successfully. It proves length 0 and a zero value, which asserts nothing useful, but a verifier is responsible for asking about an identifier its chosen profile defines.

The lengths for identifiers 5 and 7 are 8 because the value is the canonical `YYYYMMDD` integer, not the six machine readable zone characters. `predicate::reveal` asserts `opening.length == revealed_length`, so a verifier asking for a revealed date supplies 8 and receives an integer rather than ASCII. For the generated specimen the value is 19740812, which `reads_the_specimen_passport_dates` asserts.

## TD3 layout

Two lines of 44 characters, concatenated with no separator into the 88 bytes of `TD3_MRZ_BYTES`. Line 2 begins at offset 44. Offsets are zero based into that array.

| Offset | Length | Content | Constant |
| --- | --- | --- | --- |
| 0 | 2 | document code | literal `0` in the profile |
| 2 | 3 | issuing state | `TD3_ISSUING_STATE` |
| 5 | 39 | name | `TD3_NAME` |
| 44 | 9 | document number | `TD3_DOC_NUMBER` |
| 53 | 1 | document number check digit | literal in `td3_validate` |
| 54 | 3 | nationality | `TD3_NATIONALITY` |
| 57 | 6 | birth date | `TD3_BIRTH_DATE` |
| 63 | 1 | birth date check digit | literal in `td3_validate` |
| 64 | 1 | sex | `TD3_SEX` |
| 65 | 6 | expiry date | `TD3_EXPIRY_DATE` |
| 71 | 1 | expiry date check digit | literal in `td3_validate` |
| 72 | 14 | optional data | `TD3_OPTIONAL` |
| 86 | 1 | optional data check digit | literal in `td3_validate` |
| 87 | 1 | composite check digit | literal in `td3_validate` |

## TD1 layout

Three lines of 30 characters, concatenated into the 90 bytes of `TD1_MRZ_BYTES`. Line 2 begins at offset 30 and line 3 at offset 60.

| Offset | Length | Content | Constant |
| --- | --- | --- | --- |
| 0 | 2 | document code | literal `0` in the profile |
| 2 | 3 | issuing state | `TD1_ISSUING_STATE` |
| 5 | 9 | document number | `TD1_DOC_NUMBER` |
| 14 | 1 | document number check digit | literal in `td1_validate` |
| 15 | 15 | optional data 1 | `TD1_OPTIONAL1` |
| 30 | 6 | birth date | `TD1_BIRTH_DATE` |
| 36 | 1 | birth date check digit | literal in `td1_validate` |
| 37 | 1 | sex | `TD1_SEX` |
| 38 | 6 | expiry date | `TD1_EXPIRY_DATE` |
| 44 | 1 | expiry date check digit | literal in `td1_validate` |
| 45 | 3 | nationality | `TD1_NATIONALITY` |
| 48 | 11 | optional data 2 | `TD1_OPTIONAL2` |
| 59 | 1 | composite check digit | literal in `td1_validate` |
| 60 | 30 | name | `TD1_NAME` |

TD1 carries two optional data fields. `FIELD_OPTIONAL_DATA` on TD1 is the second one, at `TD1_OPTIONAL2`, because that is where states put a personal number when they use one. `TD1_OPTIONAL1` is declared in `lib/mrz` and never referenced by any function. The bytes it points at, offsets 15 to 29, do enter the composite check digit because `td1_validate` copies 25 bytes starting at offset 5, but no field is committed from them. Nothing can be proved about that data. It is still covered by the DG1 hash and therefore by the Document Signer signature.

## Normalization

Byte fields go through `normalize::pack_to_4`, which packs big endian into four field elements of up to 31 bytes each. `MAX_FIELD_BYTES` is 124, and the function asserts both that bound (`normalize: field too long`) and that the range lies inside the buffer (`normalize: field out of bounds`). Bytes beyond `len` are skipped by the inner condition `idx < len`, so a field of L bytes occupies the first `ceil(L / 31)` elements and the rest stay zero. The final element holds only its remaining bytes and is not padded out to 31, so the packed value depends on the field length as well as its content. The length stored in the leaf is what disambiguates.

Filler characters are packed verbatim. The 39 byte TD3 name field includes every trailing `<`, so a committed name is byte exact machine readable zone text and not a trimmed string. A verifier building a set for `predicate::member` has to construct its entries with the same padding, and a disclosed value arrives padded.

Date fields do not go through `pack_to_4`. They are parsed to a `YYYYMMDD` integer by `mrz::birth_date_to_int` and `mrz::expiry_date_to_int` and stored as `[value as Field, 0, 0, 0]` with length 8. That single element form is what makes them usable by `predicate::compare`, which rejects any opening whose elements 1 through 3 are non zero (`predicate: value does not fit one element`) and any value that does not round trip through `u64` (`predicate: value is not an integer`). An age check is a range on identifier 5 and an expiry check is a range on identifier 7.

Country codes keep the three letter form. `lib/normalize` documents why: the Doc 9303 Part 3 list extends ISO 3166-1 alpha-3 with codes for issuing organizations and for holders without a nationality, such as XXA for refugees and UTO for the specimen state used in the standard's examples, so validating against the ISO list would reject compliant documents. `normalize::pack_alpha3` exists and does check that each character is A to Z or the filler, but nothing outside its own tests calls it, and neither machine readable zone profile does. Issuing state and nationality go through `pack_to_4` like every other byte field.

That leads to an audit relevant consequence. Character class validation happens only inside `mrz::char_value`, which is reached only by bytes that enter a check digit computation. On TD3 that is offsets 44 to 53, 57 to 63 and 65 to 86. On TD1 it is offsets 5 to 29, 30 to 36, 38 to 44 and 48 to 58. Everything else, meaning the document code, the issuing state, the name, the sex character and the nationality on both layouts, is committed as raw bytes with no character check at all. What stops arbitrary content there is not the profile, it is that the bytes have to hash to the value the issuer signed.

## Check digits

`mrz::char_value` assigns `<` the value 0, digits their face value, and A to Z the values 10 to 35 by `c - 0x37`. Anything else fails with `mrz: invalid character`. `mrz::check_digit` sums the character values under the repeating weights 7, 3, 1 starting at the first character of the range, takes the sum modulo 10, and returns it as an ASCII digit (`0x30 + sum % 10`).

`td3_validate` checks five digits: the document number over offsets 44 to 52 against byte 53, the birth date over 57 to 62 against byte 63, the expiry date over 65 to 70 against byte 71, the optional data over 72 to 85 against byte 86, and a composite over the concatenation of offsets 44 to 53, 57 to 63 and 65 to 86 (39 bytes) against byte 87.

`td1_validate` checks four: the document number over offsets 5 to 13 against byte 14, the birth date over 30 to 35 against byte 36, the expiry date over 38 to 43 against byte 44, and a composite over the concatenation of offsets 5 to 29, 30 to 36, 38 to 44 and 48 to 58 (50 bytes) against byte 59.

### The filler cases

`check_digit_ok(chars, actual, filler_allowed)` passes when the computed digit equals the actual byte, or when `filler_allowed` is set and the actual byte is the filler `0x3C`. Doc 9303 puts a filler in a check digit position in two routine cases:

A document number longer than nine characters does not fit its field. It continues into the optional data field and the document number check digit position is left as filler. This is why the document number check is called with `filler_allowed = true` on both layouts.

An unused optional data field carries a filler check digit rather than a computed one, which is why the TD3 optional data check is also called with `filler_allowed = true`.

The date check digits are called with `filler_allowed = false`, and the composite check digit has no filler path at all: `td3_validate` and `td1_validate` compare `check_digit(comp)` to the byte directly. `accepts_filler_check_digit_for_overflowing_document_number` pins both directions by calling `check_digit_ok` itself: with the filler in position 53 it passes when `filler_allowed` is set and fails when it is not.

The overflow case has a consequence the profile does not resolve. When a document number runs past nine characters, `FIELD_DOCUMENT_NUMBER` still holds only the nine characters at the field offset. No code in this repository reassembles the continuation from the optional data field, and the truncation is not detected. A policy that treats identifier 3 as a full document number will be reading a prefix on those documents. The continuation bytes are committed, as part of `FIELD_OPTIONAL_DATA`, so a future profile can address this without a format change.

### What check digits are for

Check digits detect transcription mistakes. They are not an integrity mechanism and must not be treated as one. The 7-3-1 sum is taken modulo 10, and the character values include A at 10, K at 20, U at 30 and the filler at 0, so substituting a character for one whose value differs by a multiple of ten leaves the digit unchanged at every position. The test `check_digits_miss_multiple_of_ten_substitutions` is written to demonstrate exactly that: it replaces byte 48 of the TD1 specimen, a filler, with `A`, and `td1_validate` still passes.

The reason the profile computes them anyway is that they are cheap and they catch a class of malformed input early. The property a verifier actually relies on is the Security Object signature over DG1, reached through `expected_dg_binding`.

## Two digit year resolution

The machine readable zone carries years as two digits, so the century has to be supplied from outside.

Birth dates pivot on the current two digit year, taken as `(current_yyyymmdd / 10000) % 100`. A two digit year greater than the current one resolves to 1900 plus that year, otherwise to 2000 plus it. With a current date in 2026, `74` resolves to 1974, `26` to 2026 and `27` to 1927. `birth_date_century_pivot` pins those cases against a current date of 20260723.

Expiry dates take a fixed century of 2000, because a valid document expires in 2000 through 2099.

Both parsers reject a month outside 1 to 12, a day of 0, and a day beyond the length of that month, with February corrected for leap years by the Gregorian rule in `assert_day_in_month`. Rejecting impossible calendar dates matters because these values feed numeric predicates and nullifier derivation, where a date like the 31st of February would otherwise look well formed.

Two limits follow, and both are properties of two digit years rather than of this implementation.

A holder older than one hundred years resolves to the wrong century. There is no signal available in DG1 to detect it, so the profile cannot compensate.

A document expiring in 2100 or later resolves to the 2000s. That is not reachable today but it is a hard end date for the fixed century in `expiry_date_to_int`.

There is a third property specific to the pivot rule. A birth date whose two digit year equals the current one resolves to the current year even when its month and day are still in the future, and nothing asserts that a birth date is in the past. A verifier that cares should express it as a range on identifier 5.

`current_yyyymmdd` is a public input of both attribute circuits, and it must be. A prover free to choose it can move a birth date by a century. The circuits do not validate that the value is a well formed date, and they read nothing from it but the two digit year, so supplying and checking a sane value is the verifier's responsibility.

## What the attribute circuits publish

`attributes::td3` and `attributes::td1` return an `Attributes` struct carrying `dg_binding`, `commitment`, `birth_date` and `expiry_date`. The circuits `mrz_td3_sha256` and `mrz_td1_sha256` return only `out.commitment`. Their public inputs, in the order `prover/layout.manifest` records, are `dg_binding`, `current_yyyymmdd`, `domain`, `context` and the returned commitment; `dg1`, `dg1_len` and `session_salt` stay private. Dates are read to build the commitment and never leave the circuit, so a verifier receives a statement about an age rather than a birth date.

The commitment is built from the sixteen leaves under `commit::root16` and then `commit::commitment(root, domain)`. Each leaf carries per field entropy from `field_entropy(seed, field_id)`, where `seed` is `entropy_seed(dg_hash_fields, domain, session_salt)`. `entropy_seed` rejects a zero salt with `commit: session salt must be non-zero`. That is not a stylistic check: the seed feeds every leaf, the root and the commitment, and the DG1 hash is SHA-256 over the printed machine readable zone under a fixed five byte template, so with a zero salt anyone holding a photocopy of the data page could rebuild DG1, recompute a holder's commitment for a domain and test it against a registry. `the_commitment_hides_behind_the_session_salt` checks that a fresh salt gives a fresh commitment while the binding stays the same.

Both circuits also assert `context != 0`, with the message `attributes: context must be set`, rejecting an unset session context.

## What is not implemented

Doc 9303 defines a third layout, TD2, of two lines of 36 characters. It is not implemented. `lib/mrz` has no TD2 offsets, no `td2_validate` and no field count constants for it, `lib/attributes` has no TD2 function, and there is no TD2 circuit; the only mention of TD2 anywhere in the repository is a line in `circuits/README.md` saying so. Adding it means a new set of offsets, a new validate function following the same check digit pattern, a new profile function and a new circuit instance. The identifier table above is intended to carry over unchanged.

Country specific data groups are opt-in enrichment on top of the machine readable zone core, and no profile for any of them is implemented. `lib/attributes` covers DG1 only. The extraction layer below it is general in the sense that `lds::dg_entry_sha256` accepts a `dg_number` from 1 through 16, so a hash for another group can already be pulled out of the Security Object, but nothing parses the contents of such a group into fields. Any profile added there defines its own meaning for identifiers 10 through 16 and has to say so explicitly, because the predicate circuits accept those identifiers today and prove nothing about which profile produced the tree.

## Measured sizes

The attribute circuits are the cheapest part of the chain after the predicates; Opcode counts are in `architecture.md`, which is the only place they are recorded.

Nothing in the repository breaks those counts down by component, so the difference between the two profiles is not attributed here. The two layouts differ in that TD1 carries 90 characters against 88 and a 50 byte composite check digit input against 39.
