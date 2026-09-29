# Evidence bundle, format 0.3

Status: normative, phase 1 of the bundle conformance suite. This document states the
rules a Histor evidence bundle follows and the rules a verifier applies to it, as the
reference implementation applies them at `bundle_version` 0.3. Revision 2 adds the
anchors and checks that close the verifier review's residual risks (the ledger head,
head checkpoints, HPC centre keys, the TSA's revocation status, email-only parties)
and the report's languages (sections 20 to 25), all with optional fields inside 0.3.
Revision 3 adds hardware attestation of the key release (section 26) and the
notified body's own tests (AI Act Annex VII point 4.4, section 27), also optional
inside 0.3. Where the reference
verifier does not enforce a rule, the requirement says so, and the coverage table
(section 19) lists it as a gap.

Companion documents: [`check-registry.md`](check-registry.md) (the check ids a
verifier emits), [`run-attestation.md`](run-attestation.md) (the run statement),
[`dataset-commitment.md`](dataset-commitment.md) (the dataset commitment value),
[`plan.schema.json`](plan.schema.json) and [`predicate.schema.json`](predicate.schema.json).

## 0. Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD
NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to
be interpreted as described in BCP 14 (RFC 2119, RFC 8174) when, and only when, they
appear in all capitals, as shown here.

Sections marked **(informative)** state no requirements. Every other section is
normative.

Each requirement has an id, **B-n**, and holds one rule that a single test can show
held or broken. Below it, *Check* names the verifier check that enforces it (see the
registry) and the verdict it gives when the rule is broken:

- **fail**: the check fails and the bundle is not verified (exit code 1);
- **warn**: the check warns and the bundle can still be verified (exit code 0);
- **fail (anchored)**: warn when the verifier was given no external anchor, fail when
  it was given any (section 16);
- **exit 2**: no verdict is given at all;
- **none**: no check enforces the rule. The requirement binds producers, and a
  conforming bundle meets it, but a bundle that breaks it is not caught today.

**Terms.** A *producer* writes bundles. A *verifier* checks them. The *operator* runs
the sandbox and produces the bundle; the verifier trusts nothing the operator alone
controls. An *anchor* is a value the verifier holds from outside the bundle (section
16). A *participation* is one sandbox participation: one `sandbox_id`, one ledger.
`sha256:<hex>` means the string `sha256:` followed by 64 lowercase hexadecimal digits.

### 0.1 Overview (informative)

A bundle is a directory the verifier reads offline. The ledger is the spine: an
append-only hash chain in which every consequential act of a participation is an entry,
each entry stamped by an RFC 3161 timestamp authority when it is written. Every other
file is evidence only as far as the ledger binds it: attestations and harness
statements must be the ones the ledger recorded, signing keys come from the ledger or
from anchors, the plan files must hash to the digests the ledger records as signed,
and the manifest's format must be the one the ledger's report entry records. The end
of the ledger is anchored by a head someone outside the operator holds (section 20).
The threat model is the operator as adversary (`docs/threat-model.md`); findings F1 to
F12 of the verifier security review are cited where a requirement closes one.

## 1. Canonical forms

Two serialisations are used for digests. Each is Python's `json.dumps` with
`sort_keys=True` and `separators=(",", ":")`, applied to the parsed JSON value.

- **CJ-A** (ASCII): additionally `ensure_ascii=True`: every non-ASCII character is
  written as `\uXXXX` (astral characters as a surrogate pair).
- **CJ-U** (UTF-8): additionally `ensure_ascii=False`: non-ASCII characters are
  written as themselves; the result is encoded as UTF-8.

In both, object members are ordered by code point of their keys; strings escape `"`,
`\` and control characters (`\n`, `\r`, `\t`, `\b`, `\f`, otherwise `\u00XX`) and do
not escape `/`; integers are written in decimal; non-integer numbers are written as
Python's `repr` of the IEEE 754 double (shortest round-trip form, in exponent form
below `1e-4` and from `1e16`, as `1e-05`, `1e+16`). These are not RFC 8785 (JCS):
the key order can differ from JCS for keys holding characters outside the Basic
Multilingual Plane, and the number form differs for exponents. An implementation in
another language MUST reproduce the Python output byte for byte.

**B-1.** A producer MUST NOT write `NaN`, `Infinity` or `-Infinity` anywhere in a
bundle's JSON.
*Check:* none.

**B-2.** A producer SHOULD NOT write non-integer numbers in ledger entry bodies, since
their canonical form depends on the float printing rules above.
*Check:* none.

## 2. Versions, identifiers and compatibility

**B-3.** `manifest.json` MUST state `bundle_version` as a string. A bundle written to
this specification states `"0.3"`.
*Check:* `bundle_version` (exit 2 when absent or unknown).

**B-4.** A verifier MUST refuse a bundle whose `bundle_version` it does not support:
it MUST give no verdict (exit code 2) and MUST NOT check the bundle as if it were a
format it knows.
*Check:* `bundle_version` (exit 2).

**B-5.** A verifier conforming to this specification MUST read `bundle_version` 0.1
and 0.2 as legacy formats (section 18), and MUST warn that a legacy format carries
weaker guarantees.
*Check:* `bundle_version` (warn).

**B-6.** The payload of each run attestation MUST have `predicateType`
`https://historlabs.eu/run/v0.1`.
*Check:* `statement_types` (fail).

**B-7.** The payload of each envelope in `harness-statements.jsonl` MUST have
`predicateType` `https://historlabs.eu/harness-measurement/v0.1` or
`https://historlabs.eu/driver-observation/v0.1`.
*Check:* `statement_types` (fail).

**B-8.** A producer MUST NOT write a type URI under the legacy namespace
`https://sandbox-mvp.dev/`. A verifier MUST read a URI under the legacy namespace as
the type with the same path under `https://historlabs.eu/`, and MUST warn that it
does.
*Check:* `statement_types` (warn).

**B-9.** (Compatibility.) A new version of a statement type MUST change only the last
path segment of its URI (`v0.1` to `v0.2`), never the host. A verifier MUST keep
reading every type version it has read before.
*Check:* none (a rule for later versions of this specification).

**B-10.** (Compatibility.) Any change to the layout, the ledger, or what a verifier
checks that makes a bundle valid under one version invalid under the other MUST take a
new `bundle_version`. A verifier that adds support for a new `bundle_version` MUST
keep reading every earlier one (at worst as legacy, with a warning).
*Check:* none (a rule for later versions of this specification).

**B-11.** (Compatibility.) Check ids (see the registry) MUST NOT be renamed or reused
for another meaning. A check whose meaning changes takes a new id.
*Check:* none (a rule for later versions of this specification).

## 3. Layout and file types

A bundle is one directory:

| Path | Presence | Content |
|---|---|---|
| `manifest.json` | REQUIRED | Section 4 |
| `ledger.jsonl` | REQUIRED | Section 5 |
| `attestations.jsonl` | REQUIRED | Section 9 |
| `public-keys.json` | REQUIRED | Key id to PEM (B-17) |
| `plan.json` | REQUIRED | The plan version last put in force (B-58) |
| `plans/<hex>.json` | REQUIRED (B-60) | Every signed plan version, named by its digest's hex (section 7) |
| `harness-statements.jsonl` | when any run cites one | Section 9.3 |
| `runs/<n>/<log>` | OPTIONAL | Run logs (section 13) |
| `policies/<name>` | OPTIONAL | Network and gate policy files, informative for the reader |
| `i18n/<lang>/report.mo` | when the report is rendered in a language other than English | The compiled catalogue that language's renderings were made with (section 25) |

**B-12.** Every path under the bundle directory MUST be a regular file or a directory.
A bundle MUST NOT contain a symbolic link, a FIFO, a socket or a device. A verifier
MUST NOT follow or read such a path, and MUST fail the bundle without reading any of
it.
*Check:* `bundle_files` (fail; no other check runs).

**B-13.** A bundle transported as an archive MUST be a gzip-compressed tar with
exactly one top-level directory, whose members are regular files and directories only,
none with an absolute path or a `..` segment. A reader MUST refuse any other archive
whole rather than extract part of it.
*Check:* none in the verifier; enforced by the unpacking code (`ledger/bundle.py`,
`unpack`).

**B-14.** `manifest.json`, `ledger.jsonl`, `attestations.jsonl`, `public-keys.json`
and `plan.json` MUST be present.
*Check:* the CLI exits 2 without `manifest.json`; `hash_chain` (fail) without the
ledger or `public-keys.json`, or without `plan.json` in a bundle with no `plans/`;
`signatures` (fail) without attestations; `plan_versions` (fail) without a readable
`plan.json` in a bundle with `plans/`, and the other checks still run.

**B-15.** A producer MUST NOT place any file in a bundle other than those in the table
above.
*Check:* none, except that a catalogue under `i18n/` no rendering records fails
`i18n_catalogues` (B-169). Other extra files are covered by the bundle digest and
scanned for personal data, but not refused.

**B-16.** A JSON Lines file (`ledger.jsonl`, `attestations.jsonl`,
`harness-statements.jsonl`) MUST be UTF-8 text holding one JSON object per line, each
line ending in LF (U+000A). Blank lines are ignored. A producer SHOULD escape every
non-ASCII character (CJ-A style), so that no line contains a character another reader
could take as a line break.
*Check:* `hash_chain` (fail) for the ledger; `signatures` (fail) for attestations;
`statement_types` (fail) for harness statements.

**B-17.** `public-keys.json` MUST be a JSON object whose every value is a string (a
PEM public key or certificate), keyed by key id. It carries, as applicable:
`control-plane` (and its versions `control-plane@<v>`), `harness`, `scorer`,
`provider`, `regulator`, `timestamp-authority` (development timestamps),
`tsa-root:<name>` (each RFC 3161 authority's root certificate), `hpc-centre`,
`sandbox-operator`.
*Check:* `hash_chain` (fail, "not an object of key id to PEM").

**B-18.** A run log in `runs/<n>/` MUST have one of the names `relay-log.jsonl`,
`model-stdout.log`, `drop-log.jsonl`, `job-record.txt`, `node-config.json`. A
producer MUST refuse to write any other name there.
*Check:* none in the verifier; enforced by the producer (`ledger/bundle.py`,
`export`).

## 4. The manifest and the bundle digest

**B-19.** `manifest.json` MUST be a JSON object with the members `bundle_version`,
`sandbox_id`, `files` (an object describing each file present), `plan_versions` (the
sorted list of the plan digests carried in `plans/`), `entry_count` (the number of
ledger entries), `attestation_count` (the number of attestations), `personal_data`
(section 14) and `bundle_digest`.
*Check:* `bundle_version` (exit 2, when the manifest is not a JSON object);
`personal_data` and `bundle_digest` (fail) for their members. The members files,
plan_versions, entry_count and attestation_count are not checked.

The **bundle digest** D of a bundle is computed as follows. Take every regular file
under the bundle directory except the top-level `manifest.json`. Order them by their
relative path's components, compared component by component by code point (so
`a/b` sorts before `a-c`). Feed SHA-256 with, for each file in turn, the UTF-8 bytes of
its relative path with `/` separators, followed by the 32-byte SHA-256 of the file's
bytes. D is `sha256:` followed by the hex of the result. Directories contribute
nothing. D(n) is the same computation with `ledger.jsonl` replaced by its first n
lines, each line including its LF.

**B-20.** `manifest.bundle_digest` MUST equal D.
*Check:* `bundle_digest` (fail).

**B-21.** (F8.) The manifest is signed by nobody, so its `bundle_version` MUST equal
the `bundle_version` recorded in the last `report_generated` entry that records one.
*Check:* `bundle_format` (fail).

**B-22.** A producer of format 0.3 MUST record `bundle_version` in every
`report_generated` entry it writes.
*Check:* `bundle_format` (fail, when the last `report_generated` entry of a bundle
stating a current version records none).

**B-23.** (F5.) The `bundle_digest` in the last `report_generated` entry MUST equal
D(k), where k is the number of ledger entries before that entry. That is, no file
other than the ledger changed after the report was generated, and the ledger only
grew.
*Check:* `completeness` (fail, with or without anchors).

**B-24.** A producer MUST write each ledger entry as the same line in every export
(`json.dumps(entry, sort_keys=True)` followed by LF), so that D(k) can be recomputed
from a later export.
*Check:* `completeness` (fail, through B-23).

**B-25.** Every ledger entry's `sandbox_id`, every plan version's `sandbox_id` and
every run predicate's `sandbox_id` MUST equal `manifest.sandbox_id`.
*Check:* `anchor_sandbox_id` (fail), only when the verifier holds the sandbox id as an
anchor. Without it, not checked.

## 5. The ledger

### 5.1 Entries

**B-26.** Each line of `ledger.jsonl` MUST be a JSON object with the members `seq`
(integer), `sandbox_id` (string), `entry_type` (string), `recorded_at` (string),
`body` (object), `prev_hash` and `entry_hash` (`sha256:<hex>`), and, per section 6, a
`timestamp` object. A verifier MUST fail a ledger with any line that is not such an
object without running the later checks.
*Check:* `hash_chain` (fail; later checks are skipped).

**B-27.** The ledger MUST hold at least one entry.
*Check:* `hash_chain` (fail).

**B-28.** `seq` MUST be 1 on the first line and increase by exactly 1 on each
following line.
*Check:* `hash_chain` (fail).

**B-29.** `prev_hash` MUST be `sha256:` followed by 64 zeros on the first entry, and
the previous entry's `entry_hash` on every other.
*Check:* `hash_chain` (fail).

**B-30.** `entry_hash` MUST be `sha256:` and the hex SHA-256 of the CJ-A form of the
object `{seq, sandbox_id, entry_type, recorded_at, body, prev_hash}` of that entry.
The `timestamp` member is not covered.
*Check:* `hash_chain` (fail).

**B-31.** `entry_type` MUST be one of the types in Appendix A.
*Check:* none. The ledger writer refuses other types; the verifier ignores entries of
types it does not read.

**B-32.** `recorded_at` MUST be an ISO 8601 UTC instant with millisecond precision and
the suffix `Z` (`2026-09-28T01:07:59.983Z`), the time the writer appended the entry.
*Check:* `timestamps` (fail when it does not parse, and see B-51).

### 5.2 What a complete participation records

The body members named below are the ones a verifier reads. Appendix A lists the
others.

**B-33.** The ledger MUST hold at least one `plan_signed` entry, whose body carries
`plan_digest`.
*Check:* `plan_versions` (fail).

**B-34.** A 0.3 ledger MUST hold a `signing_key_registered` entry
(`{"key_id": "control-plane", "public_key": <PEM>, "signs": "attestations"}`) for the
control plane's key, and one for each version of it (`control-plane@<v>`) that signs
an attestation.
*Check:* `signing_keys` (fail (anchored) when only `public-keys.json` holds the key;
fail when no source holds it).

**B-35.** The control plane's key MUST be recorded before the first `run_attestation`
entry.
*Check:* `signing_keys` (fail).

**B-36.** On the local backend, a 0.3 ledger MUST record the harness's key as
`signing_key_registered` (`key_id` `harness`) before the first run; on other backends
the key broker records it as `harness_key_provisioned` (and the scorer's as
`scorer_key_provisioned`).
*Check:* `signing_keys` (fail (anchored) when only `public-keys.json` holds the key;
fail when no source holds it). That the harness key precedes the runs is not checked.

**B-37.** Each run MUST have exactly one `run_started` entry, with `run_number` in its
body.
*Check:* `run_numbers` (fail).

**B-38.** The run numbers started MUST be 1, 2, …, n with no gap.
*Check:* `run_numbers` (fail).

**B-39.** (F6.) Each `run_started` MUST be followed by a `run_attestation` or
`run_halted` entry for the same run number. Only the last run of a participation that
has not exited MAY be open, and then the verifier warns.
*Check:* `run_numbers` (fail; warn for the open last run before exit).

**B-40.** Each run MUST have at most one `run_attestation` entry, and it MUST come
after that run's `run_started`.
*Check:* `run_numbers` (fail).

**B-41.** The ledger MUST hold at least one `run_attestation` entry, and the run
numbers the ledger attests MUST be the run numbers of the attestations the bundle
carries.
*Check:* `signatures` (fail, no attestations); `run_numbers` (fail).

**B-42.** A participation that has ended MUST record, in this order: the regulator's
exit (`gate_decision` with `action` `exit` and `allow` true); after it,
`keys_destroyed`; after that, `report_generated` (with `report_sha256`,
`bundle_digest` and `bundle_version`); after that, a `report_signature` by the
regulator over that `report_sha256`.
*Check:* `completeness` (fail (anchored); warn with `--in-progress`).

**B-43.** `keys_destroyed` MUST NOT appear without an exit before it. Only an exit
the gate allowed (`allow` true) counts; a refused request to exit is not an exit.
*Check:* `deletion` (fail).

**B-44.** After an allowed exit, `keys_destroyed` MUST follow it.
*Check:* `deletion` (fail).

**B-45.** (F5.) A verifier MUST fail a ledger that lacks any part of B-42 when it was
given any anchor, unless it was told the participation is in progress; otherwise it
MUST warn.
*Check:* `completeness`.

### 5.3 Truncation (informative)

The hash chain detects an entry edited, removed or moved in the middle. It cannot
detect a ledger cut after its last entry. B-42 to B-45 make a cut visible unless it
falls after the report signature; B-23 makes files changed after the report visible;
the timestamps fix when each entry was written. The regulator's report signature
commits to the ledger head when they sign (B-148 to B-151), which fixes every entry
before it. A cut after that point, or in a participation checked `--in-progress`, is
visible only against a head the verifier holds from outside the bundle: a head given
with `--expect-head` (B-152) or a head checkpoint (B-153 to B-156).

## 6. Timestamps

The `timestamp` member of an entry is an object `{authority, kind, timestamp, digest,
token}`. For `kind` `rfc3161`, `token` is `{"url": <the authority's URL>, "der":
<base64 of the DER TimeStampToken>}`. For `kind` `dev`, `token` is a DSSE envelope
(section 9.1) signed under key id `timestamp-authority` over CJ-A of
`{digest, timestamp, authority, external: false, warning}`.

**B-46.** Every ledger entry MUST carry a `timestamp`. A ledger in which any entry,
or every entry, lacks one fails.
*Check:* `timestamps` (fail).

**B-47.** `timestamp.kind` MUST be `rfc3161` or `dev`.
*Check:* `timestamps` (fail).

**B-48.** `timestamp.digest` MUST equal the entry's `entry_hash`.
*Check:* `timestamps` (fail).

**B-49.** An `rfc3161` token MUST be a CMS SignedData over a TSTInfo whose message
imprint is SHA-256 and equals the entry's `entry_hash`; it MUST have exactly one
SignerInfo; its signed attributes MUST carry content type `id-ct-TSTInfo` and the
message digest of the TSTInfo; and the signature over them MUST verify (RSA PKCS #1
v1.5 or ECDSA, with SHA-256, SHA-384 or SHA-512) under a certificate the token
carries.
*Check:* `timestamps` (fail); `anchor_tsa_root` (fail).

**B-50.** (F2.) The `timestamp.timestamp` string MUST denote the same instant as the
time the token signs (the TSTInfo `genTime`; for a `dev` token, the signed
`timestamp`).
*Check:* `timestamps` (fail).

**B-51.** (F2.) The signed time MUST be within 10 minutes of the entry's
`recorded_at`.
*Check:* `timestamps` (fail).

**B-52.** (F2.) The signed time of an entry MUST NOT be earlier than the latest signed
time of the entries before it by more than 5 seconds.
*Check:* `timestamps` (fail).

**B-53.** (F9.) The signer's certificate MUST be valid at `genTime`, MUST NOT be a CA
certificate, and MUST have an extended key usage extension that is marked critical and
holds `id-kp-timeStamping` and nothing else (RFC 3161 §2.3).
*Check:* `timestamps` (fail); `anchor_tsa_root` (fail).

**B-54.** (F9.) Every issuer in the chain from the signer's certificate to a trusted
root, the root included, MUST have basicConstraints `cA` true; MUST have `keyCertSign`
when it has a key usage extension; MUST have no more CA certificates below it than its
path length constraint allows; and MUST be valid at `genTime`. The chain MUST end at a
trusted root within 8 certificates. For the `timestamps` check the trusted roots are
the bundle's `tsa-root:*` keys; for `anchor_tsa_root`, only the roots the verifier was
given. Revocation is section 23 (B-160 to B-162).
*Check:* `timestamps` (fail); `anchor_tsa_root` (fail).

**B-55.** A bundle whose ledger is stamped by an RFC 3161 authority MUST carry that
authority's root certificate in `public-keys.json` under `tsa-root:<name>`.
*Check:* `timestamps` (fail, "the bundle pins no timestamp authority root").

**B-56.** A `dev` token MUST verify under the `timestamp-authority` key in
`public-keys.json` and no other key. A verifier MUST warn on a ledger stamped only by
`dev` tokens, and MUST warn on a ledger stamped by both kinds; it MUST NOT report
either as anchored in time.
*Check:* `timestamps` (fail when it does not verify; warn otherwise).

**B-57.** The digest inside a `dev` token's signed payload MUST equal the entry's
`entry_hash`.
*Check:* `timestamps` (fail).

## 7. Plans and amendments

The **plan digest** of a plan is `sha256:` and the hex SHA-256 of its CJ-U form. The
**unsigned digest** is the plan digest of the plan without its `signatures` member.
The ledger records and runs cite plan digests; parties sign unsigned digests.

**B-58.** `plan.json` MUST be the plan version the last `plan_signed` entry put in
force: its plan digest MUST equal that entry's `plan_digest`.
*Check:* `plan_versions` (fail).

**B-59.** Each file `plans/<hex>.json` MUST have the plan digest `sha256:<hex>`. The
verifier MUST recompute it from the file's content, with or without an anchor.
*Check:* `plan_versions` (fail); `anchor_plan_digest` (fail).

**B-60.** Every `plan_digest` named by a `plan_signed` entry MUST be carried as a plan
version. (A bundle without `plans/`, as a legacy bundle may be, carries `plan.json` as
its only version.)
*Check:* `plan_versions` (fail).

**B-61.** Each plan version SHOULD validate against `plan.schema.json`.
*Check:* none.

**B-62.** Each run's `predicate.plan_digest` MUST name a plan version the bundle
carries.
*Check:* `artifact_digests` (fail).

**B-63.** The plan version a run cites MUST have been put in force by a `plan_signed`
entry before that run's first `run_started` entry (before its `run_attestation` entry
when the ledger records no `run_started` for it). A plan put in force while a run was
under way did not govern it.
*Check:* `plan_signatures` (fail).

**B-64.** (F4.) If the first `plan_signed` entry was preceded by `plan_signature`
entries of both the provider and the regulator over its digest, then every later
`plan_signed` entry (every amendment) MUST also be preceded by `plan_signature`
entries of both parties over its own digest.
*Check:* `plan_signatures` (fail).

**B-65.** (F4.) A `plan_signed` entry whose body says `"method": "idp"` MUST be
preceded by `plan_signature` entries of both parties over its digest.
*Check:* `plan_signatures` (fail).

**B-66.** (F4.) When the verifier holds IdP keys (`--idp-keys`), every `plan_signed`
entry MUST be preceded by `plan_signature` entries of both parties over its digest.
*Check:* `plan_signatures` (fail).

**B-67.** (F4.) A `plan_signed` entry not covered by B-64 to B-66 MUST carry in
`signatures`, for each of `provider` and `regulator`, either an object whose `seq`
names a `plan_signature` entry by that party over this digest, or the base64 of an
Ed25519 signature, under that party's key in `public-keys.json`, over the DSSE PAE
(type `application/vnd.in-toto+json`) of the CJ-A form of `{"plan_digest": d}`, where
d is the version's unsigned digest or, as bundles before 0.3 signed amendments, the
plan digest of the version with an earlier version's `signatures` in place of its own.
*Check:* `plan_signatures` (fail).

**B-68.** A verifier MUST warn when no plan version was signed through the parties'
identity providers.
*Check:* `plan_signatures` (warn).

**B-69.** Each run's `model-image`, `harness-image` and `relay-image` subjects MUST
equal the `model_image_digest`, `harness_image_digest` and `relay_image_digest` the
plan version it cites pins.
*Check:* `artifact_digests` (fail).

## 8. Identity signatures

A `plan_signature` or `report_signature` entry records one person's signature made by
logging in at their own identity provider (`identity/signature.py`). Its body carries
`party`, the signed digest (`plan_digest` or `report_sha256`), and `method`
(`oidc_id_token`), `idp`, `issuer`, `sub`, `email`, `salt`, `max_age_seconds`,
`id_token` (the compact JWS), `jwk` (the key that verified it), `jwk_thumbprint` and
`development`.

**B-70.** `method` MUST be `oidc_id_token`.
*Check:* `plan_signatures`, `report_signature` (fail).

**B-71.** `id_token` MUST verify under `jwk`. Its `alg` MUST be one of RS256, RS384,
RS512, PS256, PS384, ES256, ES384 or EdDSA (never `none` or HS*), MUST equal the
`jwk`'s `alg` when the `jwk` has one, and MUST suit the key type. A token whose header
has `crit` MUST be refused.
*Check:* `plan_signatures`, `report_signature` (fail).

**B-72.** The token's `nonce` MUST equal `prefix || b64url(SHA-256(domain || digest ||
"\n" || salt))`, where b64url has no padding and, for a plan, prefix is `sbx-plan.`
and domain is `sandbox-plan-signature/v1\n`, and for a report, prefix is `sbx-report.`
and domain is `sandbox-report-signature/v1\n`, or, for a report signature whose body
carries `ledger_head` (B-148), `sandbox-report-signature/v2\n<seq>:<entry_hash>\n`.
The document is a report exactly when the body has `report_sha256`.
*Check:* `plan_signatures`, `report_signature` (fail).

**B-73.** The token's `iss`, without a trailing `/`, MUST equal the body's `issuer`,
and the body's `sub` MUST equal the token's `sub` or `oid`.
*Check:* `plan_signatures`, `report_signature` (fail).

**B-74.** The token's `iat` minus its `auth_time` (or `iat` when absent) MUST NOT
exceed the body's `max_age_seconds` (default 300) plus 60 seconds.
*Check:* `plan_signatures`, `report_signature` (fail).

**B-75.** (F2.) The token's `iat` MUST NOT be more than 10 minutes after the recording
entry's `recorded_at`, nor more than one hour before it.
*Check:* `plan_signatures`, `report_signature` (fail).

**B-76.** (F3.) A `plan_signature`'s `party` MUST be `provider` or `regulator`, and
the token MUST name a member the signed plan version lists under `roles.<party>`: a
string member matches the token's `email` (case-insensitively); an object member with
`issuer` matches only a token with that `iss`, then by `subject` against `sub` or
`oid`, or by `email` against `email`.
*Check:* `plan_signatures` (fail).

**B-77.** (F3.) A plan's `roles` SHOULD name each signer as `{issuer, subject}`. A
verifier MUST warn when a signer is matched by email alone (a member with no
`subject`), and MUST fail it under anchors as B-163 says.
*Check:* `plan_signatures`, `report_signature` (warn; fail (anchored) per B-163).

**B-78.** (F3.) For each plan digest, no principal (`iss`, `sub`) MUST sign both as
the provider and as the regulator.
*Check:* `plan_signatures` (fail).

**B-79.** (F3.) A `report_signature`'s `party` MUST be `regulator`, and its token MUST
name a member of `roles.regulator` in the plan version the last `plan_signed` entry
put in force, matched as in B-76.
*Check:* `report_signature` (fail).

**B-80.** A `report_signature` entry MUST NOT appear in a ledger with no
`report_generated` entry.
*Check:* `report_signature` (fail).

**B-81.** (F3.) When the verifier holds the console's client ids (`--expect-audience`),
each token's `aud` MUST name one of them, and a token with several audiences MUST name
one of them in `azp`.
*Check:* `plan_signatures`, `report_signature` (fail). Without the anchor, `aud` is
checked only where the plan names an audience for the signer (B-164).

**B-82.** A verifier MUST warn when a plan or report signature was made through the
development IdP (`development` true, or the development issuer), and when the last
report has no regulator signature.
*Check:* `plan_signatures`, `report_signature` (warn).

**B-83.** When the verifier holds IdP keys, the RFC 7638 SHA-256 thumbprint of every
`plan_signature` and `report_signature` entry's `jwk` MUST be the thumbprint of a key
in the anchored set, and at least one such entry MUST exist.
*Check:* `anchor_idp_keys` (fail).

## 9. Run attestations and harness statements

### 9.1 Envelopes

A **DSSE envelope** is `{payloadType, payload, signatures: [{keyid, sig}]}` with
`payload` and `sig` in standard base64. `sig` is Ed25519 over
`"DSSEv1 " || len(type) || " " || type || " " || len(payload) || " " || payload`
(lengths in decimal ASCII), the DSSE pre-authentication encoding. The **envelope
digest** is `sha256:` and the hex SHA-256 of the envelope's CJ-A form.

**B-84.** Each line of `attestations.jsonl` MUST be a DSSE envelope whose payload is
an in-toto Statement v1 (`_type` `https://in-toto.io/Statement/v1`) with
`payloadType` `application/vnd.in-toto+json`.
*Check:* `signatures` (fail when it is not an envelope that verifies). `payloadType`
and `_type` are not checked.

**B-85.** Each run predicate SHOULD validate against `predicate.schema.json`.
*Check:* none. A field a check reads that is missing or of the wrong type fails that
check (B-144), but the schema as a whole is not validated.

### 9.2 Binding to the ledger (F1)

**B-86.** `attestations.jsonl` MUST hold exactly as many envelopes as the ledger has
`run_attestation` entries.
*Check:* `signatures` (fail; later checks are skipped).

**B-87.** The i-th envelope in `attestations.jsonl` MUST have the same envelope digest
as the `envelope` in the body of the i-th `run_attestation` entry.
*Check:* `signatures` (fail; later checks are skipped).

**B-88.** Each attestation's `predicate.run_number` MUST equal the `run_number` of the
`run_attestation` entry that records it.
*Check:* `signatures` (fail).

**B-89.** Each envelope in `harness-statements.jsonl` MUST have the envelope digest of
a `harness_statement` or `driver_statement` in the body of some `run_attestation`
entry.
*Check:* `harness_statements` (fail).

### 9.3 Keys

A signer is `control-plane` (signs attestations), `harness` (the harness's
measurements, and at a centre the driver's observations) or `scorer` (measurements
scored off a centre). A key id is a signer or a version of one, `<signer>@<version>`.

**B-90.** The keys a signer's statements are checked under MUST come from the first
of these sources that holds any key for that signer: the verifier's anchors
(`--signing-key`, `--control-plane-keys`); the ledger (`signing_key_registered` by
`key_id`, or `harness_key_provisioned` / `scorer_key_provisioned`); `public-keys.json`.
*Check:* `signing_keys`, `signatures`, `harness_statements`.

**B-91.** A key recorded in the ledger MUST be an Ed25519 public key in PEM, and the
ledger MUST NOT record two different keys under one key id.
*Check:* `signing_keys` (fail).

**B-92.** Where the ledger or `public-keys.json` holds a key under a key id that the
chosen source also holds, the two MUST be the same key.
*Check:* `signing_keys` (fail).

**B-93.** A verifier MUST warn when a signer's key came from `public-keys.json` alone,
and MUST fail when it was also given any anchor.
*Check:* `signing_keys` (fail (anchored)).

**B-94.** (F1.) Each attestation MUST verify under the control plane's keys and no
other key: the signature names a key id among them, and verifies under the key that
key id names.
*Check:* `signatures` (fail).

**B-95.** An attestation made under a rotated key MUST name the version it was made
with (`control-plane@<v>`). When the verifier holds control-plane keys, an attestation
under a key id it was not given fails.
*Check:* `signatures` (fail).

**B-96.** (F1.) A harness statement MUST verify under the `harness` key and no other,
except that a measurement statement cited by a run that also cites a driver statement
MUST verify under the `scorer` key and no other.
*Check:* `harness_statements` (fail).

### 9.4 Harness statements

**B-97.** A run's `predicate.harness_statement_digest`, when present, MUST be the
envelope digest of an envelope in `harness-statements.jsonl`.
*Check:* `harness_statements` (fail).

**B-98.** The harness statement's `sandbox_id`, `plan_digest`, `run_number` and
`relay_log_digest` MUST equal the attestation's.
*Check:* `harness_statements` (fail).

**B-99.** Every result in the harness statement MUST appear unchanged in the
attestation's `results`, in the same order, and every other result there MUST be of
type `decision_logging`.
*Check:* `harness_statements` (fail).

**B-100.** When the harness statement's outcome is `halted`, the attestation's MUST
be `halted`.
*Check:* `harness_statements` (fail).

**B-101.** A `decision_logging` result's `log_coverage` MUST equal, within 1e-5, the
share of the harness's (or driver's) signed `request_ids` that appear as
`request_id` in `runs/<n>/model-stdout.log`, when that log is carried.
*Check:* `harness_statements` (fail).

**B-102.** (F10.) Every run SHOULD cite a harness statement. A verifier MUST warn on a
run that does not, and MUST fail when it was given any anchor.
*Check:* `harness_statements` (fail (anchored)).

**B-103.** A driver statement a run cites MUST be carried, MUST verify under the
`harness` key and MUST be of the driver-observation type.
*Check:* `harness_statements` (fail).

**B-104.** The driver statement's `sandbox_id`, `plan_digest`, `run_number` and
`relay_log_digest` MUST equal the attestation's; the scorer's statement MUST name the
same `driver_statement_digest`, and the driver's non-empty `responses_digest` and
`work_digest`, and the same `request_ids`; a driver that halted MUST give a halted
attestation.
*Check:* `harness_statements` (fail).

**B-105.** Each scored result MUST name its segments, each completed by the driver;
an `adversarial_robustness` or `fail_safe` result's `queries_sent` MUST equal the sum
of `relay_records` of its segments; any other result's `items_evaluated` MUST NOT
exceed the sum of `answered`.
*Check:* `harness_statements` (fail).

### 9.5 External anchors for runs

**B-106.** When the verifier holds a plan digest set, every plan version (rehashed),
every digest a `plan_signed` or `plan_signature` entry names, and every run's
`plan_digest` MUST be in it.
*Check:* `anchor_plan_digest` (fail).

**B-107.** When the verifier holds a network policy digest, every plan version's
`artifacts.network_policy_digest` and every run's recorded
`isolation_evidence.network_policy_digest` MUST equal it.
*Check:* `anchor_policy_digest` (fail).

**B-108.** When the verifier holds a harness image digest, every plan version's
`artifacts.harness_image_digest` and every run's `harness-image` subject MUST equal it.
*Check:* `anchor_harness_digest` (fail).

## 10. Results

**B-109.** Each `thresholds_evaluated` item's `comparison` MUST be `lte`, `gte`, `lt`
or `gt`, and its `held` MUST equal the comparison of `observed` with `limit`.
*Check:* `thresholds` (fail).

**B-110.** A result with thresholds MUST have `outcome` `pass` exactly when every
threshold held, and `fail` otherwise.
*Check:* `thresholds` (fail).

**B-111.** A predicate with `outcome` `pass` MUST NOT hold a result with `outcome`
`fail`.
*Check:* `thresholds` (fail).

**B-112.** For `adversarial_robustness` and `fail_safe` results, each rate MUST be a
count over its `n` (within 2e-6), each interval MUST be that count's Wilson interval,
the groups MUST add up to the headline rate (for attacks, the union lies between the
largest attack and the sum), each `observed` MUST follow from the reported
measurements, and no threshold the test type does not define MAY appear.
*Check:* `thresholds` (fail).

**B-113.** A verifier MUST warn when any group was below the plan's minimum sample
(`insufficient_sample`).
*Check:* `sample_sizes` (warn).

**B-114.** A predicate with `outcome` `halted` MUST carry `halt_reason`.
*Check:* none (the predicate schema requires it; the verifier does not validate the
schema).

## 11. Dataset commitments

The commitment value and its two schemes, v1 and v2, are defined in
[`dataset-commitment.md`](dataset-commitment.md). The bundle never carries the data,
so a verifier compares commitment values; it cannot recompute one.

**B-115.** Every `dataset:<id>` subject of a run MUST have a `dataset_committed` entry
with that `dataset_id`.
*Check:* `dataset_commitments` (fail).

**B-116.** The `commitment` of the last `dataset_committed` entry for a dataset MUST
equal `sha256:` followed by the subject's `digest.sha256`.
*Check:* `dataset_commitments` (fail).

**B-117.** (F7.) The `dataset_committed` entry MUST come before the first
`run_started` entry of every run that uses the dataset.
*Check:* `dataset_commitments` (fail).

**B-118.** A commitment value MUST have the form `sha256:<hex>`, and a producer MUST
compute a new one under scheme v2. A value computed under v1 remains valid where a
plan signed before 2026-09-28 pins it.
*Check:* none (the data is not in the bundle).

**B-119.** When the plan version a run cites lists `datasets[]`, the `commitment` of
the last `dataset_committed` entry for each dataset the run used MUST equal the
`commitment` that plan pins for that dataset.
*Check:* `dataset_commitments` (fail). The gate also refuses a mismatched commitment
when it is made.

**B-165.** When the plan version a run cites lists `datasets[]`, every dataset the run
used (every `dataset:<id>` subject) MUST be listed there by `id`.
*Check:* `dataset_commitments` (fail).

## 12. Isolation evidence

`predicate.isolation_evidence.type` selects one of three arms. The backend fixes the
arm: `kubernetes` gives `cilium`, `slurm` gives `hpc_centre`, `local` gives
`local_process`.

**B-120.** `predicate.backend` MUST be `kubernetes`, `slurm` or `local`, and
`isolation_evidence.type` MUST be the arm that backend produces.
*Check:* `isolation` (fail).

**B-121.** A `cilium` arm's `network_policy_digest` MUST equal the
`artifacts.network_policy_digest` of the plan version the run cites.
*Check:* `isolation` (fail).

**B-122.** A `cilium` arm MUST carry a non-empty `drop_log_digest`.
*Check:* `isolation` (fail).

**B-123.** A verifier MUST warn on any `local_process` run that no isolation was
enforced, and MUST say when `model_egress` shows the test data was sent to a hosted
model.
*Check:* `isolation` (warn).

**B-124.** An `hpc_centre` arm's `signed_by` MUST be `centre` or `sandbox_operator`
(absent is read as `centre`), and its `signature` (for the centre, also
`centre_signature`) MUST be the base64 of a DSSE envelope, under key id `hpc-centre`
or `sandbox-operator` respectively, whose payload is the arm without its signature
members.
*Check:* `isolation` (fail).

**B-125.** The signer's key MUST be the one the last `hpc_centre_key` or
`hpc_operator_key` entry records (for the centre, the entry naming that centre or no
centre), or, without such an entry, `public-keys.json`'s `hpc-centre` or
`sandbox-operator`; when both exist they MUST be the same key. When the verifier
holds centre keys, B-157 replaces this rule for the centre.
*Check:* `isolation` (fail).

**B-126.** For each of the plan's `model_image_digest`, `relay_image_digest` and
`harness_image_digest`, the ledger MUST hold an `image_converted` entry whose
signature (by the rule of B-124) verifies over `{oci_digest, sif_digest}` and whose
body names the same digests.
*Check:* `isolation` (fail).

**B-127.** For an `hpc_centre` run, the ledger MUST hold exactly one `key_released`
entry for the run, before its `run_attestation`, whose measured SIF digests equal the
conversions of the pinned images, whose probes from the model's namespace were all
`blocked`, whose `netns_links` is `["lo"]`, and whose `slurm_job_id` is that of the
run's last `job_submitted` entry, when there is one. A run refused its keys that ended `halted` is exempt.
*Check:* `isolation` (fail).

**B-128.** When the plan pins encrypted weights, the ledger MUST hold exactly one
`weights_key_released` entry for the run, before its attestation, whose `receipt`
verifies under the plan's `releaser_public_key` (key id `provider-releaser`), agrees
with the entry, names the pinned ciphertext and plaintext digests, counts no more runs
than the plan's `max_runs`, and answers the same `request_digest` and
`job_public_key_digest` as the data keys' release.
*Check:* `isolation` (fail).

**B-129.** The run's `run_started` entry MUST name an `agreement` and the `centre` the
evidence names, and the plan MUST pin that agreement with the same `centre` and
`document_sha256`.
*Check:* `isolation` (fail).

**B-130.** A verifier MUST NOT pass a sound `hpc_centre` run: it MUST warn, naming who
signed. It MUST report every `key_release_refused` and `weights_key_release_refused`
entry as an incident.
*Check:* `isolation` (warn).

**B-131.** An `hpc_centre` arm without `signed_by`, in a ledger with no `key_released`
entry, is legacy: a verifier MUST read it without B-127 and B-128, and MUST say what
it lacks.
*Check:* `isolation` (warn).

**B-132.** `isolation_evidence.type` MUST be one of the three arms.
*Check:* `isolation` (fail).

Each arm MAY carry `tee`: the summary of the hardware attestation report the run's
keys were released on (`platform`, `report_digest`, `measurement`,
`init_data_digest`, `tcb`, optional `gpu`, `collateral_digest`). The report itself is
in the ledger, and section 26 states what is required of it.

## 13. Run logs

**B-133.** For each run log name in B-18 whose digest the run predicate carries
(`relay_log_digest`, `model_stdout_digest`, and under `isolation_evidence`
`drop_log_digest`, `job_record_digest`, `node_config_digest`), a carried
`runs/<n>/<name>` MUST be valid UTF-8 and its SHA-256 MUST equal that digest.
*Check:* `run_logs` (fail).

**B-134.** A verifier MUST warn when a log whose digest a run carries is not in the
bundle.
*Check:* `run_logs` (warn).

## 14. The personal-data manifest

From format 0.2, `manifest.personal_data` states what personal data the bundle holds.
It is derived from the files, and the verifier derives it again:

1. For every regular file except `manifest.json`, decode its bytes as UTF-8
   (replacing invalid sequences); append the decoded `payload` of every line of it that
   parses as a JSON object with a string `payload`. Every match of
   `[\w.+-]+@[\w-]+(?:\.[\w-]+)+` (leftmost, non-overlapping) is a staff identifier.
   The file is listed as its name, or as `<top directory>/` for a file in a
   subdirectory.
2. In `ledger.jsonl`, each entry whose body has a non-empty `id_token` counts one IdP
   ID token and adds the identifier `<issuer> <sub>`, and lists `ledger.jsonl`.
3. `categories.staff_identifiers` is present when there is any identifier:
   `{description, count: <distinct identifiers>, files: <sorted list>}`.
   `categories.idp_id_tokens` is present when any token was counted:
   `{description, count, files: ["ledger.jsonl"]}`.
4. The whole object is `{present: <any category>, categories, test_subject_data:
   false, test_subject_data_basis}`.

The `description` and `test_subject_data_basis` strings are fixed; Appendix B gives
them.

**B-135.** In a 0.2 or 0.3 bundle, `manifest.personal_data` MUST be exactly the object
derived above, fixed strings included.
*Check:* `personal_data` (fail).

**B-136.** A bundle MUST NOT carry test-subject data: no image, no ground-truth label
or age, no group label of an item, no item id of any dataset.
*Check:* none. `test_subject_data: false` is stated by the producer, not found.

**B-137.** In a 0.1 bundle, `contains_personal_data` MUST be `true` when the bundle
holds personal data. A verifier MUST warn, not fail, when it is not.
*Check:* `personal_data` (warn).

## 15. Deletion and the report (informative cross-reference)

Deletion is B-42 to B-44; the report and its signature are B-23, B-42, B-72, B-79,
B-80 and B-82.

## 16. External anchors

A verifier accepts these anchors, as options or in one anchors file: `plan_digest`
(one or more), `sandbox_id`, `tsa_root` (PEM certificates), `idp_keys` (a JWKS),
`policy_digest`, `harness_digest`, `signing_keys` (key id to Ed25519 PEM;
`control_plane_keys` for every version of the control plane's key), `audience`
(client ids), `ledger_head` (`<seq>:sha256:<hex>`, option `--expect-head`),
`checkpoints` (head checkpoint files, option `--checkpoint`, repeatable) and
`centre_keys` (option `--centre-keys`: a JWKS whose `kid` is a centre's name, a JSON
object of name to PEM, or one PEM for any centre) and `vendor_roots` (option
`--vendor-roots`, repeatable: PEM files of self-signed root certificates, from the TEE
vendors; section 26). "Anchored" in this document means at least one of them was
given.

**B-138.** A verifier MUST NOT fall back to the bundle's own value for an anchor it
was given but cannot read. An anchor that is missing, malformed, empty, or given under
an unknown name in an anchors file MUST end the run with exit code 2.
*Check:* the CLI (exit 2); no check id.

**B-139.** A verifier MUST report which anchors were given and which came from the
bundle, and MUST warn when any came from the bundle. `ledger_head` and `checkpoints`
count as one anchor (either anchors the ledger's end); `centre_keys` counts only for a
bundle holding isolation evidence a centre signed; `vendor_roots` only for a bundle
holding TEE evidence or a plan that pins a `tee_policy`.
*Check:* `anchors` (warn).

**B-140.** When the verifier holds TSA roots, every entry's timestamp MUST be of kind
`rfc3161` and MUST chain to one of those roots; the bundle's own roots MUST be ignored.
*Check:* `anchor_tsa_root` (fail).

**B-141.** (F8.) When the verifier holds TSA roots, a bundle stating legacy version
0.1 or 0.2 MUST fail if its last entry's `genTime` is on or after the date that
version was superseded (0.1: 2026-09-27T00:00:00Z; 0.2: 2026-09-28T00:00:00Z).
*Check:* `bundle_format` (fail).

Anchors that bind other requirements: B-25 (`sandbox_id`), B-66 and B-83
(`idp_keys`), B-81 (`audience`), B-90, B-93 and B-95 (`signing_keys`), B-106 to B-108,
B-152 (`ledger_head`), B-153 to B-156 (`checkpoints`), B-157 and B-158
(`centre_keys`), B-161 (`tsa_root`), B-176 (`vendor_roots`), and B-158 and B-163 (any
anchor).

## 17. Verdict and exit codes

**B-142.** A verifier MUST emit one result per check it runs, each with its check id
(see the registry) and an outcome `pass`, `fail` or `warn`. The bundle is verified
exactly when no result is `fail`. With `--json` the output is an object with
`verified`, `counts`, `results` (`{id, question, outcome, detail}`), `caveats` and
`anchors` (`{external, from_bundle}`).
*Check:* the verifier's output (the CLI); no check id.

**B-143.** A verifier MUST exit 0 when the bundle is verified, 1 when any check
failed, and 2 when it gives no verdict: the directory has no `manifest.json`, the
`bundle_version` is unknown or the manifest unreadable, an anchor cannot be read, or
the command line is invalid.
*Check:* the CLI.

**B-144.** Input a check cannot read (a missing field, a wrong type, a token that does
not parse) MUST fail that check, under its own id, and MUST NOT end the verifier
without a verdict.
*Check:* every check ("malformed"); the CLI's last-resort `malformed` result.

**B-145.** A verifier MUST NOT make network requests while verifying.
*Check:* none (the reference verifier makes none; `make showcase` runs it with the
network off).

## 18. Legacy formats 0.1 and 0.2

A verifier reads a legacy bundle as it was written and warns (B-5). What differs:

| | 0.1 | 0.2 | 0.3 |
|---|---|---|---|
| Personal data in the manifest | `contains_personal_data` (a constant) | `personal_data` (B-135) | `personal_data` |
| Statement signing keys in the ledger | no | no | `signing_key_registered` (B-34) |
| `bundle_version` in `report_generated` | no | no | yes (B-22) |
| `plans/` | may be absent | present | present |
| Amendment signed over | the plan with the earlier version's signatures | the same | the unsigned digest (B-67) |
| Namespace | may be `sandbox-mvp.dev` | may be `sandbox-mvp.dev` | `historlabs.eu` |

**B-146.** A bundle stating 0.1 or 0.2 MUST NOT hold a `signing_key_registered` entry
or a `report_generated` entry that records `bundle_version`.
*Check:* `bundle_format` (fail).

**B-147.** In a legacy bundle, statement signing keys taken from `public-keys.json`
MUST warn, and MUST fail when any anchor is given (B-93).
*Check:* `signing_keys` (fail (anchored)).

## 19. Coverage

The tests named here are in the engine's test suite, under its `tests/`, and are
published with the engine; this repository's `tests/` holds only the tests of the
package it ships. Abbreviations: VA `test_verifier_adversarial.py`,
LV `test_ledger_and_verifier.py`, CLI `test_verifier_cli.py`,
TS `test_timestamps_rfc3161.py`, PD `test_bundle_personal_data.py`,
HPC `test_hpc_evidence.py`, SLURM `test_slurm_backend.py`,
SOC `test_scoring_off_centre.py`, PW `test_provider_weights.py`,
ID `test_identity.py`, CA `test_console_actions.py`, CAU `test_console_auth.py`,
AFS `test_adversarial_and_fail_safe.py`, SP `test_sample_participation.py`,
E2E `test_demo_end_to_end.py`,
DC `test_dataset_commitment.py`, RR `test_verifier_residual_risks.py`,
VI `test_verifier_i18n.py`, VR `test_verifier_renderings.py`,
TEE `test_tee_attestation.py`, TR `test_tee_release.py`.
In the engine's suite, `tests/test_check_registry.py` holds this table to the code: every test it names
exists, and every requirement has a row.

<!-- COVERAGE -->

### 19.1 Requirement to check to test

| Req | Check(s) | Tests |
|---|---|---|
| B-1 | none | **none** |
| B-2 | none | **none** |
| B-3 | `bundle_version` | CLI `TestBundleVersion::test_the_version_this_code_writes_is_one_it_reads` |
| B-4 | `bundle_version` | CLI `TestBundleVersion::test_an_unknown_version_is_refused_before_anything_is_checked`<br>CLI `TestBundleVersion::test_the_cli_exits_2_on_an_unknown_version` |
| B-5 | `bundle_version` | VA `TestF8FormatDowngrade::test_a_genuine_legacy_bundle_says_its_guarantees_are_weaker`<br>VA `TestLegacyBundles::test_a_genuine_0_2_bundle_still_verifies_and_says_its_keys_are_unanchored` |
| B-6 | `statement_types` | LV `TestStatementTypes::test_a_current_bundle_passes`<br>LV `TestStatementTypes::test_a_statement_of_another_type_fails` |
| B-7 | `statement_types` | LV `TestStatementTypes::test_a_legacy_harness_statement_verifies_with_a_warning` |
| B-8 | `statement_types` | LV `TestStatementTypes::test_a_legacy_run_attestation_verifies_with_a_warning`<br>LV `TestStatementTypes::test_a_legacy_harness_statement_verifies_with_a_warning` |
| B-9 | none | **none** |
| B-10 | none | **none** |
| B-11 | none | **none** |
| B-12 | `bundle_files` | VA `TestLows::test_a_symbolic_link_is_refused_and_not_followed`<br>VA `TestLows::test_a_fifo_is_refused_rather_than_read` |
| B-13 | none | an out-of-tree consumer's unpacking tests (paths outside the destination, links) |
| B-14 | `hash_chain`, `signatures`, `plan_versions` | RR `TestFoundWritingTheSpec::test_an_unreadable_plan_json_fails_its_check_and_the_rest_still_run` |
| B-15 | none | **none** |
| B-16 | `hash_chain`, `signatures`, `statement_types` | **none** |
| B-17 | `hash_chain` | VA `TestLows::test_public_keys_that_are_not_an_object_fail` |
| B-18 | none | LV `TestRunLogs::test_only_known_logs_are_accepted` |
| B-19 | `bundle_version`, `personal_data`, `bundle_digest` | **none** |
| B-20 | `bundle_digest` | LV `TestTampering::test_flipping_one_byte_anywhere_is_caught`<br>E2E `test_flipping_one_byte_breaks_verification` |
| B-21 | `bundle_format` | VA `TestF8FormatDowngrade::test_relabelling_it_as_an_older_format_fails` |
| B-22 | `bundle_format` | RR `TestFoundWritingTheSpec::test_a_current_format_report_that_records_no_format_fails` |
| B-23 | `completeness` | VA `TestF5Truncation::test_a_file_changed_after_the_report_fails` |
| B-24 | `completeness` | VA `test_the_honest_bundle_verifies_with_every_anchor` |
| B-25 | `anchor_sandbox_id` | CLI `TestEachAnchor::test_a_wrong_value_fails_its_named_check`<br>CLI `TestAnchorsFile::test_a_wrong_value_in_the_file_fails` |
| B-26 | `hash_chain` | LV `TestTampering::test_a_renamed_ledger_field_fails_rather_than_crashing` |
| B-27 | `hash_chain` | **none** |
| B-28 | `hash_chain` | LV `TestTampering::test_removing_a_ledger_entry_breaks_the_chain` |
| B-29 | `hash_chain` | LV `TestTampering::test_reordering_entries_breaks_the_chain` |
| B-30 | `hash_chain` | LV `TestTampering::test_altering_a_ledger_body_breaks_the_chain` |
| B-31 | none | **none** |
| B-32 | `timestamps` | **none** |
| B-33 | `plan_versions` | **none** |
| B-34 | `signing_keys` | VA `TestF1AttestationsBoundToTheLedger::test_keys_only_in_public_keys_json_warn_and_fail_under_anchors` |
| B-35 | `signing_keys` | **none** |
| B-36 | `signing_keys` | VA `TestF1AttestationsBoundToTheLedger::test_keys_only_in_public_keys_json_warn_and_fail_under_anchors` |
| B-37 | `run_numbers` | VA `TestF6RunsStartedAndNotReported::test_a_run_started_twice_fails` |
| B-38 | `run_numbers` | LV `TestRunNumbers::test_a_missing_run_is_caught` |
| B-39 | `run_numbers` | VA `TestF6RunsStartedAndNotReported::test_a_run_started_and_never_ended_before_exit_fails`<br>VA `TestF5Truncation::test_cutting_the_ledger_after_a_run_started_fails_under_anchors` |
| B-40 | `run_numbers` | **none** |
| B-41 | `signatures`, `run_numbers` | **none** |
| B-42 | `completeness` | VA `TestF5Truncation::test_dropping_the_regulators_report_signature_fails_under_anchors`<br>VA `TestF5Truncation::test_cutting_the_ledger_after_a_run_started_fails_under_anchors` |
| B-43 | `deletion` | RR `TestFoundWritingTheSpec::test_a_refused_exit_is_not_an_exit` |
| B-44 | `deletion` | LV `TestDeletion::test_exit_without_destruction_fails`<br>LV `TestDeletion::test_a_clean_bundle_records_destruction_after_exit`<br>E2E `test_keys_were_destroyed_after_exit` |
| B-45 | `completeness` | VA `TestF5Truncation::test_dropping_the_regulators_report_signature_fails_under_anchors` |
| B-46 | `timestamps` | LV `TestArtifactPins::test_a_deleted_timestamp_is_caught` |
| B-47 | `timestamps` | **none** |
| B-48 | `timestamps` | **none** |
| B-49 | `timestamps`, `anchor_tsa_root` | TS `test_a_token_is_stamped_checked_and_verified_offline`<br>TS `test_a_token_over_another_digest_is_refused`<br>TS `test_timestamp_info_changed_after_signing_is_refused`<br>VA `TestLows::test_a_timestamp_token_with_two_signers_fails_the_check` |
| B-50 | `timestamps` | VA `TestF2TheAuthoritysTimeCounts::test_a_rebuild_claiming_the_original_times_fails` |
| B-51 | `timestamps` | VA `TestF2TheAuthoritysTimeCounts::test_a_rebuild_stating_its_real_times_fails` |
| B-52 | `timestamps` | VA `TestF2TheAuthoritysTimeCounts::test_tokens_issued_in_reverse_order_fail`<br>VA `TestF2TheAuthoritysTimeCounts::test_the_honest_bundle_states_the_span_it_was_stamped_over` |
| B-53 | `timestamps`, `anchor_tsa_root` | TS `test_a_certificate_not_for_time_stamping_is_refused`<br>VA `TestF9TimestampChain::test_a_signer_not_only_for_time_stamping_is_refused` |
| B-54 | `timestamps`, `anchor_tsa_root` | VA `TestF9TimestampChain::test_an_honest_intermediate_is_accepted`<br>VA `TestF9TimestampChain::test_an_issuer_that_may_not_issue_is_refused`<br>TS `test_a_token_from_an_unpinned_root_is_refused` |
| B-55 | `timestamps` | TS `test_a_ledger_stamped_externally_verifies_from_its_bundle` |
| B-56 | `timestamps` | LV `test_a_clean_bundle_still_warns_about_development_timestamps`<br>VA `test_a_development_token_signed_by_another_bundle_key_is_refused` |
| B-57 | `timestamps` | RR `TestFoundWritingTheSpec::test_a_development_token_over_another_entry_fails` |
| B-58 | `plan_versions` | VA `TestLows::test_plan_json_edited_beside_the_signed_versions_fails` |
| B-59 | `plan_versions`, `anchor_plan_digest` | LV `TestArtifactPins::test_other_terms_under_the_signed_digest_are_caught`<br>CLI `TestEachAnchor::test_a_plan_filed_under_the_signed_digest_but_with_other_terms_fails` |
| B-60 | `plan_versions` | E2E `test_the_plan_was_amended_and_both_versions_travel` |
| B-61 | none | **none** |
| B-62 | `artifact_digests` | LV `TestArtifactPins::test_a_run_citing_a_plan_not_in_the_bundle_is_caught` |
| B-63 | `plan_signatures` | RR `TestFoundWritingTheSpec::test_a_plan_put_in_force_while_its_run_was_under_way_fails` |
| B-64 | `plan_signatures` | VA `TestF4AmendmentsSignedAsTheOriginal::test_an_amendment_without_the_parties_idp_signatures_fails` |
| B-65 | `plan_signatures` | **none** |
| B-66 | `plan_signatures` | **none** |
| B-67 | `plan_signatures` | VA `TestF4AmendmentsSignedAsTheOriginal::test_signatures_that_do_not_verify_fail_a_plan_signed_with_keys` |
| B-68 | `plan_signatures` | CAU `TestSigningThePlan::test_a_plan_signed_with_sandbox_keys_is_reported_as_such`<br>VA `TestF4AmendmentsSignedAsTheOriginal::test_signatures_that_do_not_verify_fail_a_plan_signed_with_keys` |
| B-69 | `artifact_digests` | LV `TestArtifactPins::test_a_swapped_model_is_caught` |
| B-70 | `plan_signatures`, `report_signature` | **none** |
| B-71 | `plan_signatures`, `report_signature` | ID `TestJose::test_unsigned_and_shared_secret_tokens_are_refused`<br>ID `TestJose::test_a_key_published_for_one_algorithm_does_not_verify_another`<br>ID `TestPlanSignature::test_a_substituted_key_does_not_verify`<br>VA `test_a_token_with_a_critical_header_is_refused` |
| B-72 | `plan_signatures`, `report_signature` | ID `TestPlanSignature::test_it_cannot_be_moved_to_other_terms`<br>CA `TestTheReport::test_a_plan_signature_cannot_pass_for_a_report_signature`<br>RR `TestTheReportSignatureCommitsToTheHead::test_a_head_moved_after_signing_breaks_the_nonce` |
| B-73 | `plan_signatures`, `report_signature` | ID `TestPlanSignature::test_it_cannot_be_given_to_someone_else` |
| B-74 | `plan_signatures`, `report_signature` | **none** |
| B-75 | `plan_signatures`, `report_signature` | VA `TestF2TheAuthoritysTimeCounts::test_an_old_login_recorded_as_a_plan_signature_fails` |
| B-76 | `plan_signatures` | VA `TestF3SignaturesBoundToParties::test_the_providers_login_recorded_as_the_regulators_fails` |
| B-77 | `plan_signatures`, `report_signature` | RR `TestEmailOnlyParties::test_an_email_alone_warns_without_anchors` |
| B-78 | `plan_signatures` | **none** |
| B-79 | `report_signature` | VA `TestF3SignaturesBoundToParties::test_the_providers_login_recorded_as_the_regulators_fails`<br>CA `TestTheReport::test_signed_by_the_regulator_through_the_idp` |
| B-80 | `report_signature` | **none** |
| B-81 | `plan_signatures`, `report_signature` | VA `TestF3SignaturesBoundToParties::test_a_login_to_another_application_fails_against_the_audience_you_hold`<br>VA `test_an_audience_is_checked_with_azp_when_there_are_several` |
| B-82 | `plan_signatures`, `report_signature` | SP `test_the_sample_verifies_with_exactly_the_local_warnings` |
| B-83 | `anchor_idp_keys` | CLI `TestIdpKeys::test_a_signature_by_a_key_in_the_set_passes`<br>CLI `TestIdpKeys::test_a_signature_by_a_key_outside_the_set_fails`<br>CLI `TestEachAnchor::test_idp_keys_fail_a_signature_made_with_another_key` |
| B-84 | `signatures` | LV `TestTampering::test_altering_the_attestation_breaks_the_signature` |
| B-85 | none | VA `TestLows::test_malformed_input_is_a_failure_not_a_traceback` |
| B-86 | `signatures` | **none** |
| B-87 | `signatures` | VA `TestF1AttestationsBoundToTheLedger::test_substituted_attestations_fail_with_every_anchor`<br>VA `TestF1AttestationsBoundToTheLedger::test_substituted_attestations_fail_without_anchors` |
| B-88 | `signatures` | **none** |
| B-89 | `harness_statements` | VA `TestF1AttestationsBoundToTheLedger::test_a_harness_statement_the_ledger_never_recorded_fails` |
| B-90 | `signing_keys`, `signatures`, `harness_statements` | VA `TestF1AttestationsBoundToTheLedger::test_a_signing_key_you_hold_must_be_the_one_used`<br>CLI `TestAnchorsFile::test_a_signing_key_is_given_by_the_file_or_a_flag` |
| B-91 | `signing_keys` | **none** |
| B-92 | `signing_keys` | LV `TestTampering::test_substituting_a_public_key_fails` |
| B-93 | `signing_keys` | VA `TestF1AttestationsBoundToTheLedger::test_keys_only_in_public_keys_json_warn_and_fail_under_anchors` |
| B-94 | `signatures` | VA `TestF1AttestationsBoundToTheLedger::test_an_attestation_signed_by_another_listed_key_fails` |
| B-95 | `signatures` | VA `TestRotatedControlPlaneKeys::test_each_attestation_verifies_under_the_version_it_names`<br>VA `TestRotatedControlPlaneKeys::test_a_version_you_do_not_hold_fails_when_you_hold_the_keys`<br>VA `TestRotatedControlPlaneKeys::test_a_key_set_naming_another_signer_is_refused` |
| B-96 | `harness_statements` | LV `TestHarnessStatements::test_a_statement_the_control_plane_signed_is_not_the_harnesss`<br>SOC `TestTheVerifier::test_measurements_signed_with_the_harness_key_are_refused_off_centre` |
| B-97 | `harness_statements` | **none** |
| B-98 | `harness_statements` | **none** |
| B-99 | `harness_statements` | LV `TestHarnessStatements::test_a_number_changed_after_the_harness_signed_fails`<br>SOC `TestTheVerifier::test_the_attestation_s_results_must_be_the_scorer_s` |
| B-100 | `harness_statements` | **none** |
| B-101 | `harness_statements` | LV `TestHarnessStatements::test_log_coverage_is_recomputed_from_the_signed_request_ids` |
| B-102 | `harness_statements` | LV `TestHarnessStatements::test_no_statement_warns_and_fails_under_anchors`<br>VA `TestF10ResultsTheHarnessDidNotSign::test_an_attestation_citing_no_harness_statement_fails_under_anchors` |
| B-103 | `harness_statements` | SOC `TestTheVerifier::test_a_driver_statement_not_signed_in_the_job_is_refused` |
| B-104 | `harness_statements` | SOC `TestTheVerifier::test_results_computed_from_other_responses_are_refused`<br>SOC `TestTheVerifier::test_the_driver_and_the_scorer_agreeing_passes` |
| B-105 | `harness_statements` | SOC `TestTheVerifier::test_a_query_count_the_driver_did_not_see_is_refused`<br>SOC `TestTheVerifier::test_more_items_than_the_driver_saw_answered_is_refused` |
| B-106 | `anchor_plan_digest` | CLI `TestEachAnchor::test_a_wrong_value_fails_its_named_check`<br>CLI `TestEachAnchor::test_a_bare_plan_digest_among_others_you_hold_passes` |
| B-107 | `anchor_policy_digest` | CLI `TestEachAnchor::test_a_wrong_value_fails_its_named_check`<br>CLI `TestEachAnchor::test_the_right_value_passes_and_is_reported_as_external` |
| B-108 | `anchor_harness_digest` | CLI `TestEachAnchor::test_a_wrong_value_fails_its_named_check`<br>CLI `TestEachAnchor::test_the_right_value_passes_and_is_reported_as_external` |
| B-109 | `thresholds` | LV `TestThresholdRecomputation::test_a_lie_about_a_threshold_is_caught` |
| B-110 | `thresholds` | **none** |
| B-111 | `thresholds` | **none** |
| B-112 | `thresholds` | AFS `TestVerifier::test_honest_results_recompute`<br>AFS `TestVerifier::test_a_softened_observed_value_is_caught` |
| B-113 | `sample_sizes` | SP `test_the_sample_verifies_with_exactly_the_local_warnings` |
| B-114 | none | **none** |
| B-115 | `dataset_commitments` | **none** |
| B-116 | `dataset_commitments` | **none** |
| B-117 | `dataset_commitments` | VA `TestF7LateCommitment::test_a_dataset_committed_after_its_run_started_fails` |
| B-118 | none | DC `test_v2_is_pinned_by_its_specification`<br>DC `test_v1_is_the_old_function_and_still_verifies` |
| B-119 | `dataset_commitments` | RR `TestFoundWritingTheSpec::test_a_plan_pinning_another_dataset_commitment_fails` |
| B-120 | `isolation` | LV `TestIsolationReporting::test_a_backend_that_disagrees_with_its_isolation_evidence_fails` |
| B-121 | `isolation` | LV `TestIsolationReporting::test_a_policy_digest_mismatch_fails` |
| B-122 | `isolation` | **none** |
| B-123 | `isolation` | LV `TestIsolationReporting::test_local_process_isolation_warns_loudly` |
| B-124 | `isolation` | HPC `test_a_claim_signed_by_the_wrong_key_fails`<br>HPC `test_an_operator_signature_passed_off_as_the_centres_fails`<br>HPC `test_changing_who_signed_after_the_fact_fails`<br>HPC `test_the_centre_may_still_sign_in_centre_signature`<br>SLURM `test_evidence_changed_after_the_centre_signed_it_fails` |
| B-125 | `isolation` | HPC `test_the_ledgers_key_and_the_bundles_must_agree`<br>HPC `test_without_the_operators_key_nothing_can_be_checked`<br>SLURM `test_without_the_centres_key_nothing_can_be_checked` |
| B-126 | `isolation` | HPC `test_a_conversion_signed_by_someone_else_fails` |
| B-127 | `isolation` | HPC `test_a_run_at_a_centre_without_a_key_release_fails`<br>HPC `test_a_release_to_a_job_running_another_sif_fails`<br>HPC `test_a_probe_that_reached_something_fails`<br>HPC `test_a_namespace_with_more_than_loopback_fails`<br>HPC `test_a_release_to_a_job_other_than_the_one_submitted_fails`<br>HPC `test_a_run_refused_its_keys_that_halted_is_not_a_failure` |
| B-128 | `isolation` | PW `TestVerifier::test_a_run_without_a_weights_release_fails`<br>PW `TestVerifier::test_weights_released_to_another_key_than_the_data_fails`<br>PW `TestVerifier::test_a_receipt_the_provider_did_not_sign_fails`<br>PW `TestVerifier::test_more_runs_than_the_plan_allows_fails` |
| B-129 | `isolation` | SLURM `test_a_run_started_with_no_undertaking_fails`<br>SLURM `test_a_run_authorised_at_one_centre_with_evidence_from_another_fails`<br>SLURM `test_an_undertaking_the_plan_does_not_pin_fails` |
| B-130 | `isolation` | HPC `test_a_sound_centre_signed_claim_warns_and_names_the_centre`<br>HPC `test_a_sound_operator_signed_claim_warns_and_names_the_operator`<br>HPC `test_a_refused_release_is_reported_as_an_incident` |
| B-131 | `isolation` | HPC `test_a_legacy_claim_still_verifies_and_says_what_it_lacks` |
| B-132 | `isolation` | **none** |
| B-133 | `run_logs` | LV `TestRunLogs::test_an_altered_log_fails`<br>LV `TestRunLogs::test_logs_that_match_their_digests_pass`<br>E2E `test_the_run_logs_travel_and_match` |
| B-134 | `run_logs` | LV `TestRunLogs::test_digests_without_logs_warn` |
| B-135 | `personal_data` | PD `TestTheVerifier::test_a_true_description_passes`<br>PD `TestTheVerifier::test_a_manifest_that_does_not_match_the_files_fails`<br>PD `TestTheVerifier::test_a_manifest_without_the_field_fails`<br>VA `TestF8FormatDowngrade::test_understating_personal_data_in_the_current_format_fails` |
| B-136 | none | E2E `test_the_bundle_contains_no_images` |
| B-137 | `personal_data` | PD `TestBundleVersion01::test_a_false_flag_over_staff_identifiers_warns_and_still_verifies`<br>PD `TestBundleVersion01::test_a_false_flag_over_a_bundle_naming_nobody_passes` |
| B-138 | the CLI | CLI `TestAnchorsFile::test_an_unreadable_anchor_exits_2_rather_than_use_the_bundles`<br>CLI `TestAnchorsFile::test_a_misspelt_anchor_is_refused_not_dropped`<br>VA `TestLows::test_an_empty_anchor_is_refused`<br>VA `TestLows::test_an_empty_anchor_flag_exits_2` |
| B-139 | `anchors` | CLI `TestWithoutAnchors::test_every_anchor_is_reported_as_the_bundles_own`<br>CLI `TestEachAnchor::test_all_anchors_given_leave_nothing_to_warn_about`<br>RR `test_the_honest_bundle_verifies_with_every_anchor` |
| B-140 | `anchor_tsa_root` | CLI `TestEachAnchor::test_a_tsa_root_fails_a_bundle_stamped_by_the_operators_own_authority`<br>TS `test_a_tsa_root_given_from_outside_is_the_one_the_timestamps_must_reach` |
| B-141 | `bundle_format` | VA `TestF8FormatDowngrade::test_an_older_format_stamped_after_it_was_superseded_fails_under_a_tsa_root` |
| B-142 | the CLI | LV `test_a_clean_bundle_verifies`<br>CLI `TestWithoutAnchors::test_the_warning_is_a_caveat_and_is_printed` |
| B-143 | the CLI | CLI `TestBundleVersion::test_the_cli_exits_2_on_an_unknown_version`<br>CLI `TestAnchorsFile::test_an_unreadable_anchor_exits_2_rather_than_use_the_bundles` |
| B-144 | `malformed` | VA `TestLows::test_malformed_input_is_a_failure_not_a_traceback`<br>LV `TestTampering::test_a_renamed_ledger_field_fails_rather_than_crashing` |
| B-145 | none | **none** |
| B-146 | `bundle_format` | VA `TestF8FormatDowngrade::test_relabelling_it_as_an_older_format_fails` |
| B-147 | `signing_keys` | VA `TestLegacyBundles::test_its_unanchored_keys_fail_once_you_give_an_anchor` |
| B-148 | `report_signature` | RR `TestTheReportSignatureCommitsToTheHead::test_it_names_the_head_it_signed_over`<br>RR `TestTheReportSignatureCommitsToTheHead::test_a_head_moved_after_signing_breaks_the_nonce` |
| B-149 | `report_signature` | RR `TestTheReportSignatureCommitsToTheHead::test_an_entry_rewritten_before_the_signature_fails` |
| B-150 | `report_signature` | **none** |
| B-151 | `report_signature` | RR `TestTheReportSignatureCommitsToTheHead::test_a_signature_without_a_head_warns` |
| B-152 | `anchor_ledger_head` | RR `TestTheHeadYouHold::test_a_cut_after_the_report_signature_fails`<br>RR `TestTheHeadYouHold::test_an_in_progress_bundle_cut_short_fails`<br>RR `TestTheHeadYouHold::test_a_ledger_rewritten_from_before_the_head_fails`<br>RR `TestTheHeadYouHold::test_a_head_the_ledger_extends_passes`<br>RR `TestTheHeadYouHold::test_the_flag_and_the_anchors_file_take_seq_and_hash` |
| B-153 | `anchor_checkpoints` | RR `TestHeadCheckpoints::test_a_checkpoint_the_control_plane_did_not_sign_fails`<br>RR `TestHeadCheckpoints::test_the_command_writes_one_the_verifier_reads` |
| B-154 | `anchor_checkpoints` | RR `TestHeadCheckpoints::test_a_checkpoint_of_another_participation_fails`<br>RR `TestHeadCheckpoints::test_a_checkpoint_edited_after_stamping_fails` |
| B-155 | `anchor_checkpoints` | RR `TestHeadCheckpoints::test_the_ledger_extends_every_checkpoint`<br>RR `TestHeadCheckpoints::test_a_ledger_cut_after_a_checkpoint_fails`<br>RR `TestHeadCheckpoints::test_a_checkpoint_older_than_the_entry_it_names_fails` |
| B-156 | `anchor_checkpoints` | **none** |
| B-157 | `isolation` | RR `TestCentreKeys::test_the_centres_key_you_hold_passes_under_anchors`<br>RR `TestCentreKeys::test_the_operators_key_recorded_as_the_centres_fails`<br>RR `TestCentreKeys::test_a_key_for_another_centre_fails`<br>RR `TestCentreKeys::test_centre_keys_are_read_as_jwks_object_or_pem` |
| B-158 | `isolation` | RR `TestCentreKeys::test_a_centre_key_only_the_bundle_names_warns_without_anchors`<br>RR `TestCentreKeys::test_and_fails_under_any_anchor`<br>RR `TestCentreKeys::test_an_operator_key_only_in_public_keys_json_fails_under_anchors` |
| B-159 | `isolation` | RR `TestCentreKeys::test_a_key_recorded_after_the_run_fails`<br>RR `TestCentreKeys::test_the_backend_registers_whose_key_signs` |
| B-160 | `tsa_revocation` | RR `TestTsaRevocation::test_tokens_without_revocation_evidence_warn`<br>RR `TestTsaRevocation::test_some_tokens_without_it_warn`<br>RR `TestTsaRevocation::test_the_stamping_code_keeps_it_and_refuses_a_revoked_certificate`<br>RR `TestTsaRevocation::test_it_is_fetched_from_the_responder_the_certificate_names` |
| B-161 | `tsa_revocation` | RR `TestTsaRevocation::test_a_good_status_from_the_issuer_passes`<br>RR `TestTsaRevocation::test_evidence_that_does_not_show_it_good_fails` |
| B-162 | `tsa_revocation` | RR `TestTsaRevocation::test_evidence_that_does_not_show_it_good_fails` |
| B-163 | `plan_signatures`, `report_signature` | RR `TestEmailOnlyParties::test_an_email_alone_fails_under_anchors`<br>RR `TestEmailOnlyParties::test_a_pinned_idp_without_a_verified_email_fails_under_anchors`<br>RR `TestEmailOnlyParties::test_a_pinned_idp_and_a_verified_email_warn` |
| B-164 | `plan_signatures`, `report_signature` | RR `TestFoundWritingTheSpec::test_an_audience_the_plan_names_is_checked_without_the_flag` |
| B-165 | `dataset_commitments` | **none** |
| B-166 | `i18n_catalogues` | VI `test_the_catalogue_recorded_is_the_one_carried`<br>VI `test_an_altered_catalogue_fails`<br>VI `test_a_missing_catalogue_fails`<br>E2E `test_histor_verify_checks_the_catalogues_and_the_renderings` |
| B-167 | `i18n_catalogues` | VI `test_a_translated_rendering_must_record_its_catalogue`<br>VI `test_two_catalogues_for_one_language_fail`<br>VI `test_english_and_the_pseudo_locale_read_none` |
| B-168 | `i18n_catalogues` | VI `test_an_english_report_or_none_passes` |
| B-169 | `i18n_catalogues` | VI `test_a_catalogue_no_rendering_records_fails`<br>VI `test_a_catalogue_beside_an_english_only_report_fails` |
| B-170 | `report_renderings` | VR `TestTheCheck::test_a_missing_language_fails`<br>VR `TestTheCheck::test_a_plan_without_languages_passes_with_nothing_to_check` |
| B-171 | `report_renderings` | **none** |
| B-172 | `report_renderings` | VR `TestTheCheck::test_the_renderings_on_disk_match`<br>VR `TestTheCheck::test_an_altered_translation_fails`<br>VR `TestTheCheck::test_without_the_files_it_checks_the_record_and_says_so`<br>VR `TestTheCheck::test_a_rendering_the_signed_report_does_not_name_fails`<br>VI `test_the_report_directory_defaults_to_the_bundle_s_parent`<br>E2E `test_histor_verify_fails_an_altered_rendering_and_catalogue`<br>E2E `test_without_the_report_files_the_renderings_only_warn` |
| B-173 | `tee_attestation` | TEE `TestTheCheck::test_missing_evidence_under_a_policy_fails`<br>TEE `TestTheCheck::test_a_run_refused_its_keys_and_halted_is_exempt` |
| B-174 | `tee_attestation` | TEE `TestTheCheck::test_malformed_evidence_fails_under_its_own_id`<br>TEE `TestTheCheck::test_mock_reported_as_hardware_fails` |
| B-175 | `tee_attestation` | TEE `TestTheCheck::test_a_substituted_key_fails`<br>TEE `TestTheCheck::test_a_rewritten_binding_fails_on_report_data`<br>E2E `test_the_tee_mock_demo_records_each_report_and_what_it_binds` |
| B-176 | `tee_attestation` | TEE `TestTheCheck::test_another_root_than_the_plan_s_fails`<br>TEE `TestTheCheck::test_the_vendor_roots_you_hold_are_the_ones_used`<br>TEE `TestTheCheck::test_mock_reported_as_hardware_fails`<br>E2E `test_histor_verify_holds_the_chain_to_the_vendor_roots_given` |
| B-177 | `tee_attestation` | TEE `TestTheCheck::test_expired_collateral_fails` |
| B-178 | `tee_attestation` | TEE `TestTheCheck::test_a_wrong_measurement_fails`<br>TEE `TestTheCheck::test_debug_on_fails` |
| B-179 | `tee_attestation` | TEE `TestTheCheck::test_good_mock_evidence_warns_that_it_is_not_hardware`<br>TEE `TestTheCheck::test_synthetic_snp_evidence_warns_as_an_unverified_implementation`<br>E2E `test_the_tee_mock_demo_verifies_and_says_the_mock_is_not_hardware` |
| B-180 | `tee_attestation` | TEE `TestTheCheck::test_the_attestation_must_name_the_report_the_ledger_recorded`<br>TEE `TestTheCheck::test_a_named_report_the_ledger_lacks_fails`<br>TEE `TestTheCheck::test_the_provider_must_have_checked_the_same_report` |
| B-181 | `tee_attestation` | TEE `TestTheCheck::test_evidence_without_a_policy_is_checked_and_says_so`<br>TEE `TestTheCheck::test_without_evidence_or_a_policy_nothing_is_checked` |
| B-182 | none | TR `TestBrokerReleaseToTee::test_a_replayed_nonce_is_refused`<br>TR `TestBrokerReleaseToTee::test_a_substituted_key_is_refused`<br>TR `TestBrokerReleaseToJob::test_a_request_without_evidence_is_refused`<br>TR `TestProviderReleaser::test_it_refuses_a_substituted_key` |
| B-183 | `nb_tests` | NB `TestAnUnauthorisedRun::test_a_run_the_operator_wrote_without_the_gate`<br>NB `TestAnUnauthorisedRun::test_the_attestation_and_the_ledger_disagree`<br>NB `TestAnUnauthorisedRun::test_a_marker_on_the_attestation_alone` |
| B-184 | `nb_tests` | NB `TestAnUnauthorisedRun::test_an_approval_of_another_test`<br>NB `TestAnUnauthorisedRun::test_a_run_after_its_proposal_was_declined` |
| B-185 | `nb_tests` | NB `TestAnAuthorisedRun::test_pre_authorised_by_the_regulator`<br>NB `TestAnAuthorisedRun::test_pre_authorised_by_both`<br>NB `TestAnUnauthorisedRun::test_a_plan_that_does_not_pre_authorise`<br>NB `TestAnUnauthorisedRun::test_an_approval_by_a_party_the_plan_does_not_name`<br>NB `TestAnUnauthorisedRun::test_a_run_the_operator_wrote_without_the_gate` |
| B-186 | `nb_tests` | NB `TestAnUnauthorisedRun::test_an_approval_whose_token_is_over_another_digest`<br>NB `TestAnAuthorisedRun::test_pre_authorised_by_the_regulator` |
| B-187 | `nb_tests` | NB `TestAnAuthorisedRun::test_by_amendment`<br>NB `TestAnUnauthorisedRun::test_an_amendment_that_does_not_adopt_it` |
| B-188 | `nb_tests` | NB `TestAnUnauthorisedRun::test_more_runs_than_the_plan_allows` |
| B-189 | `nb_tests` | NB `TestAnUnauthorisedRun::test_an_unmarked_run_of_the_proposed_test` |
| B-190 | `nb_tests` | NB `TestInTheVerdict::test_histor_verify_runs_the_check_and_fails_an_unauthorised_run`<br>NB `TestInTheVerdict::test_an_authorised_run_does_not_fail_it`<br>NB `TestInTheVerdict::test_not_emitted_for_a_participation_without_notified_body_tests` |

### 19.2 Gaps

**Requirements no verifier check enforces.** Those marked * cannot be checked on a bundle at all (a rule for later versions of this specification, or about what the producer did outside the bundle); the others are candidates for a check or for the producer conformance mode:

B-1, B-2, B-9*, B-10*, B-11*, B-13*, B-15, B-18*, B-31, B-61, B-85, B-114, B-118*, B-136*, B-145*, B-182*.

**Requirements no existing test exercises:**

B-1, B-2, B-9, B-10, B-11, B-15, B-16, B-19, B-27, B-31, B-32, B-33, B-35, B-40, B-41, B-47, B-48, B-61, B-65, B-66, B-70, B-74, B-78, B-80, B-86, B-88, B-91, B-97, B-98, B-100, B-110, B-111, B-114, B-115, B-116, B-122, B-132, B-145, B-150, B-156, B-165, B-171.

Revision 2 closed B-22, B-57 and B-119 (each now enforced and tested) and gave B-14,
B-43 and B-63 tests with their changed rules. Revision 3 adds B-173 to B-190, each
tested; B-182 binds the key broker and the releasers, and its tests are theirs.

### 19.3 Where the code and the documentation differ (informative)

This specification follows the code. Where `docs/verifier.md` or another document
says otherwise, the difference is listed here, to be settled by changing one or the
other.

1. **Personal data.** `personal_data` compares the whole derived object, including
   the English description strings (Appendix B), so a producer must reproduce those
   strings exactly (B-135). Comparing only `present`, the categories' `count` and
   `files`, and `test_subject_data` would say the same without the strings. Kept open
   as a design question.

The first revision listed seven more. Each was settled by changing the code, and the
requirement now states the rule the verifier enforces: the plan a run cites must be in
force before its `run_started` (B-63); a development token's signed digest is compared
with its entry (B-57); an unreadable `plan.json` fails `plan_versions` and the other
checks still run (B-14); only an exit the gate allowed counts for `deletion` (B-43); a
plan member may name the console's client id, checked without `--expect-audience`
(B-164); a 0.3 report entry that records no format fails `bundle_format` (B-22); and
the ledger's dataset commitment is compared with the plan's pin (B-119, B-165). The
i18n catalogues the bundle carries, which the engine's i18n notes said were not yet checked,
are checked by `i18n_catalogues` (section 25).

## 20. The ledger head

The **head** of a ledger at a point is its last entry then, written `{seq, entry_hash}`
in a body and `<seq>:sha256:<hex>` on a command line. Through the hash chain a head
fixes every entry before it.

**B-148.** A `report_signature` entry MAY carry `ledger_head`, an object with an
integer `seq` and a string `entry_hash`: the head when the regulator signed. It MUST
NOT appear in a `plan_signature` entry. When present, the token's nonce MUST be
computed under the v2 report domain of B-72, so the IdP's signature covers the head.
*Check:* `report_signature` (fail).

**B-149.** The ledger MUST hold an entry at the `ledger_head`'s `seq` whose
`entry_hash` is the one recorded.
*Check:* `report_signature` (fail).

**B-150.** The `ledger_head`'s `seq` MUST be lower than the `report_signature` entry's
own `seq`, and not lower than the `seq` of the latest `report_generated` entry before
it for the same `report_sha256`.
*Check:* `report_signature` (fail).

**B-151.** A producer SHOULD record `ledger_head` in every report signature. A verifier
MUST warn on a regulator's report signature that commits to no head.
*Check:* `report_signature` (warn).

**B-152.** When the verifier holds a head (`--expect-head`, `ledger_head:`), the
ledger MUST hold an entry at that `seq` with that `entry_hash`. A ledger that ends
before it fails (entries were cut from its end), as does one whose entry there hashes
otherwise (it was rewritten from that point); a ledger that extends it passes.
*Check:* `anchor_ledger_head` (fail).

## 21. Head checkpoints

A **head checkpoint** is a head published during a participation for someone outside
the operator to keep (the engine's `histor ledger checkpoint`). It is a JSON file
`{checkpoint, envelope, timestamp}`: `envelope` is a DSSE envelope (section 9.1) whose
payload is the statement `{type, sandbox_id, seq, head_hash, time}` with `type`
`https://historlabs.eu/ledger-head-checkpoint/v1`; `checkpoint` is a readable copy of
it, which carries no weight; `timestamp` is a ledger timestamp object (section 6)
whose `digest` is `sha256:` and the hex SHA-256 of the statement's CJ-A form. A
checkpoint is not part of the bundle; the verifier is given it (`--checkpoint FILE`,
repeatable, or `checkpoints:`).

**B-153.** A checkpoint's envelope MUST verify under the control plane's keys, chosen
as for attestations (B-90), and its payload MUST be of the checkpoint type, with an
integer `seq` and a `head_hash` of the form `sha256:<hex>`.
*Check:* `anchor_checkpoints` (fail).

**B-154.** A checkpoint's timestamp MUST be over the statement's digest, MUST verify
(under the verifier's TSA roots when it holds any, otherwise the bundle's keys as in
B-49 and B-56), and its signed time MUST lie within 10 minutes of the statement's
`time`. Its `sandbox_id` MUST be the manifest's.
*Check:* `anchor_checkpoints` (fail).

**B-155.** The ledger MUST hold an entry at each checkpoint's `seq` whose `entry_hash`
is its `head_hash`, and that entry's `recorded_at` MUST be no more than 10 minutes
after the checkpoint's `time`.
*Check:* `anchor_checkpoints` (fail).

**B-156.** A verifier MUST warn on a checkpoint stamped by the development authority:
the operator could have made it at any time.
*Check:* `anchor_checkpoints` (warn).

## 22. HPC centre keys

**B-157.** When the verifier holds centre keys (`--centre-keys`), evidence and image
conversions a centre signed MUST verify under a key given for that centre's name (the
`centre` the evidence or conversion names), or under one given as `hpc-centre`, and no
other; and every key the ledger's `hpc_centre_key` entries or `public-keys.json`
record for that centre MUST be one of those keys. A centre with no key given fails.
*Check:* `isolation` (fail).

**B-158.** Without centre keys, a centre's signature checked under a key only the
bundle names (the ledger's `hpc_centre_key`, or `public-keys.json`), and an operator's
signature checked under `public-keys.json` alone, MUST warn and MUST fail when the
verifier was given any anchor.
*Check:* `isolation` (fail (anchored)).

**B-159.** An HPC key the ledger records (`hpc_centre_key`, `hpc_operator_key`) MUST
be recorded before every image conversion and every run attestation it signs. A
producer at a centre records it when the participation opens there.
*Check:* `isolation` (fail).

## 23. The timestamp authority's revocation status

The **revocation evidence** of an RFC 3161 token is `timestamp.token.revocation`:
`{kind, url, der}`, where `kind` is `ocsp` or `crl`, `url` where it was fetched, and
`der` the base64 of the DER OCSP response or CRL. The stamping code fetches it when it
stamps, from the OCSP responder the signer certificate names, else its CRL
distribution point, and reuses it while it is current. The verifier checks it offline.

**B-160.** A producer stamping with an RFC 3161 authority SHOULD keep revocation
evidence beside every token, and MUST NOT stamp with a certificate the evidence shows
revoked. A verifier MUST warn when any RFC 3161 token carries none, and when the ledger
holds no RFC 3161 token (development timestamps carry none).
*Check:* `tsa_revocation` (warn).

**B-161.** Revocation evidence MUST be about the token's signer certificate and signed
by that certificate's issuer in the token's chain (under the verifier's TSA roots when
it holds any): a CRL issued and signed by the issuer; an OCSP response with status
`successful`, signed by the issuer or by a responder the issuer issued with
`id-kp-OCSPSigning`, holding a single response for the signer's serial number.
*Check:* `tsa_revocation` (fail).

**B-162.** Revocation evidence MUST be current at the token's `genTime`: produced
(`thisUpdate`) no more than 10 minutes after it, not expired (`nextUpdate`) more than
10 minutes before it, and, with no `nextUpdate`, produced no more than 24 hours before
it; and it MUST NOT show the certificate revoked on or before `genTime` (for OCSP, a
status other than `good` or a revocation after `genTime` fails).
*Check:* `tsa_revocation` (fail).

## 24. Parties named by email, and the audience a plan names

**B-163.** A signer the plan names by email only (a string member, or an object member
with no `subject`) MUST fail under any anchor unless the member pins the IdP
(`issuer`) and the token says `email_verified: true`. Without anchors, or when both
hold, the verifier warns (B-77). A signature through the development IdP only warns
that it identifies nobody (B-82).
*Check:* `plan_signatures`, `report_signature` (fail (anchored)).

**B-164.** A `roles` member MAY name `audience`, the client id (a string, or a
non-empty list of strings) the console is registered under at that person's IdP. When
the member that matched a signature names one, the token's `aud` MUST name one of them
and, with several audiences, `azp` MUST, with or without `--expect-audience`.
*Check:* `plan_signatures`, `report_signature` (fail).

## 25. The report's languages

A plan MAY name `report.languages`; the exit report and the written proof are then
rendered in each, from the same evidence, the first language authentic. The
`report_generated` entry records `languages`, `authentic_language` and `renderings`:
one object per rendering with `document` (`exit_report` or `written_proof`),
`language`, `file` (a plain file name), `sha256`, `authentic` (boolean), `reviewed`
and, for a language other than English, `catalogue_sha256`. The renderings are not in
the bundle; the catalogues they were made with are (`i18n/<lang>/report.mo`).

**B-166.** For every language other than `en` and the pseudo-locale `en-XA` in which
the report was rendered, the bundle MUST carry `i18n/<lang>/report.mo`, where `<lang>`
is two or three lowercase letters, and it MUST hash to the `catalogue_sha256` the last
`report_generated` entry records for that language.
*Check:* `i18n_catalogues` (fail).

**B-167.** A rendering in a language other than `en` and `en-XA` MUST record
`catalogue_sha256`; a rendering in `en` or `en-XA` MUST NOT; and all renderings in one
language MUST record the same catalogue.
*Check:* `i18n_catalogues` (fail).

**B-168.** A report rendered in English only (no `renderings`, or only `en` and
`en-XA` ones) carries no catalogue.
*Check:* `i18n_catalogues` (pass with nothing to check; a catalogue present fails by
B-169).

**B-169.** The bundle MUST NOT carry a file under `i18n/` that no rendering record
names as its catalogue.
*Check:* `i18n_catalogues` (fail).

**B-170.** When the plan in force names `report.languages`, the last `report_generated`
entry MUST record `renderings`, its `languages` MUST equal the plan's, and each
language MUST have exactly the two documents, each with a `sha256` of the form
`sha256:<hex>` and a plain `file` name. A report entry with no `renderings` is one
English report, which passes when the plan names no languages.
*Check:* `report_renderings` (fail), run whenever the ledger records a report.

**B-171.** Exactly one exit report and one written proof MUST be `authentic`; the
authentic report's `sha256` MUST be the entry's `report_sha256` and the authentic
written proof's the entry's `written_proof_sha256`.
*Check:* `report_renderings` (fail).

**B-172.** Given the directory the renderings were written to (`--report-dir`, or by
default the bundle's parent directory when it holds every recorded file), each file
MUST hash to its recorded `sha256`, and the authentic report's text MUST contain the
`sha256` of every other rendering, so the regulator's one signature covers them all.
Without the files the verifier MUST warn that they were not checked.
*Check:* `report_renderings` (fail; warn without the files).

## 26. Hardware attestation of the key release

A run's keys MAY be released to a trusted execution environment (TEE) on the strength
of a hardware attestation report (the engine's hardware-attestation roadmap). The plan
pins what the report must show in `artifacts.tee_policy` (`plan.schema.json`):
`platforms`, accepted launch `measurements`, the `init_data_digest` that pins the
harness, an optional `min_tcb` by component, and `vendor_roots`, each a `platform` and
the `sha256:` of a root certificate's DER.

The **TEE evidence** is an object: `platform` (`sev-snp`, `tdx` or `mock`), `report`
(base64 of the raw report), `report_digest`, `measurement`, `init_data_digest`, `tcb`,
`report_data` (lowercase hex of 64 bytes), `debug`, optional `gpu`, `collateral`
(`certificates`, PEM, leaf first and root last; `crls`, PEM; `tcb_info`, the raw JSON
text or null; `ocsp`, base64 DER; `captured_at`) and `collateral_digest`. The
**binding** of a release is `tee_binding`: `release_public_key` (base64 of the raw
32-byte X25519 key the keys were sealed to), `broker_nonce` (hex of 32 bytes),
`plan_digest` and `run_number`. It requires

    report_data = SHA-256(K || N || P || R) || 0x00 * 32

where K is the 32 key bytes, N the 32 nonce bytes, P the 32 bytes the plan
digest's hex encodes, and R the run number as an unsigned 64-bit big-endian integer. The
run's `key_released` entry records the evidence as `tee` and the binding as
`tee_binding`; the provider's receipt, and so `weights_key_released`, MAY record the
report it checked as `tee` (at least `report_digest`).

The *time of the release* is the time the `key_released` entry's timestamp signs
(`genTime` for an RFC 3161 token), or its `recorded_at` when it has none.

Platform `mock` is software made for tests and the demo: a JSON report whose `format`
is `histor-mock-tee-report-v1`, signed with ECDSA P-384 under a generated mock root.
It is never hardware evidence. For `sev-snp` the report is AMD's 0x4A0-byte
`ATTESTATION_REPORT`, signed over bytes 0 to 0x29F with ECDSA P-384 and SHA-384 by the
VCEK, whose chain is ARK, ASK, VCEK; its `measurement` is `MEASUREMENT`, its
`init_data_digest` `HOST_DATA`, its `tcb` the `REPORTED_TCB`, and debug is policy bit
19. For `tdx` the report is Intel's version 4 quote, whose attestation key signs the
header and TD report body with ECDSA P-256, bound by the quoting enclave's report,
which the PCK certificate's key signs; its `measurement` is `MRTD`, its
`init_data_digest` `MRCONFIGID`, its `tcb` `TEE_TCB_SVN` (hex, compared byte by byte),
and debug is `TDATTRIBUTES` bit 0. The reference verifier's `sev-snp` and `tdx`
checks are tested on synthetic structures only (B-179).

**B-173.** When the plan version a run cites pins `artifacts.tee_policy`, the ledger
MUST hold a `key_released` entry for the run carrying `tee` and `tee_binding`. A run
refused its keys that ended `halted` is exempt.
*Check:* `tee_attestation` (fail).

**B-174.** `tee` MUST be a TEE evidence object as above; `report_digest` MUST be the
SHA-256 of the decoded `report`; `collateral_digest` MUST be the SHA-256 of the
collateral's canonical JSON; and `measurement`, `init_data_digest`, `tcb`,
`report_data` and `debug` MUST be what the report itself states, read by its
platform's layout. A report that does not parse as its `platform`'s fails.
*Check:* `tee_attestation` (fail).

**B-175.** `report_data` MUST be the binding of `tee_binding`; `tee_binding`'s
`plan_digest` and `run_number` MUST be the run's; and the SHA-256 of its
`release_public_key` MUST be the entry's `job_public_key_digest`: the report names
the key the keys were sealed to.
*Check:* `tee_attestation` (fail).

**B-176.** Each certificate in `collateral.certificates` MUST be signed by the next,
the last MUST be self-signed, and the SHA-256 of its DER MUST be one the policy's
`vendor_roots` lists for the evidence's `platform`; when the verifier holds
`vendor_roots`, it MUST also be one of those. A root whose common name marks it as
Histor's mock root MUST NOT be accepted for `sev-snp` or `tdx`. The report's signature
MUST verify under the first certificate's key as its platform requires; for `tdx` the
certificates MUST be the chain the quote itself carries.
*Check:* `tee_attestation` (fail).

**B-177.** At the time of the release, every certificate in the chain MUST be within
its validity; the collateral MUST carry a revocation list, signed by and current for
its issuer, from each issuer the platform requires (`mock`: the root; `sev-snp`: the
ARK; `tdx`: the PCK CA and the root); no certificate in the chain MAY be revoked by
then; `tcb_info`, when present, MUST be current (its issue date to its next update);
and `captured_at` MUST NOT be more than 10 minutes after that time.
*Check:* `tee_attestation` (fail).

**B-178.** Under a `tee_policy`, the evidence's `platform` MUST be one of its
`platforms`, the report's measurement one of its `measurements`, its
`init_data_digest` the policy's, and every component of `min_tcb` at least the
policy's. Debug MUST be off, with or without a policy.
*Check:* `tee_attestation` (fail).

**B-179.** A verifier MUST warn, and MUST NOT pass, on evidence of platform `mock`,
even when it is valid: "mock platform: not hardware evidence". A verifier whose
checks of a platform have not been run on reports from real hardware MUST warn on
that platform's evidence and say so.
*Check:* `tee_attestation` (warn).

**B-180.** A run's `isolation_evidence.tee`, when present, MUST equal the summary of
the report its `key_released` records, and a run MUST NOT name a report no
`key_released` records. A `weights_key_released` entry for the run that records `tee`
MUST name the same `report_digest`.
*Check:* `tee_attestation` (fail).

**B-181.** TEE evidence under a plan with no `tee_policy` MUST still meet B-174 to
B-177 (against the verifier's vendor roots, when it holds any), and a verifier MUST
say that it is held to no pinned measurement. With neither a `tee_policy` nor TEE
evidence, nothing in this section applies and `tee_attestation` is not emitted.
*Check:* `tee_attestation` (warn).

**B-182.** A key broker or releaser MUST NOT release a key under a `tee_policy` unless
the evidence meets B-174 to B-178 at the time of release and binds the key the release
is sealed to and a nonce it issued for that run and has not accepted before.
*Check:* none. A verifier re-checks B-174 to B-178 but cannot see whether a nonce was
fresh.

## 27. Tests the notified body initiated

AI Act Annex VII point 4.4: the notified body may carry out further tests. The notified
body proposes a test (an `nb_test_proposed` entry); the plan's optional
`notified_body_tests` says how it is approved: where `allowed` is true, by an
`nb_test_approved` entry from each approver it names, carrying that person's IdP
signature over the proposal's digest (route `pre_authorised`); otherwise by an
amendment, signed by both parties like any plan version, that adopts the proposal
under `notified_body_tests.adopted` (route `amendment`). The run's `run_started` entry
and its attestation carry `initiated_by: notified_body` and the `authorisation` that
names the chain ([`run-attestation.md`](run-attestation.md) section 5a).

The proposal's digest is `"sha256:" + hex(sha256(C))`, where `C` is the canonical JSON
(sorted keys, no whitespace, UTF-8) of `{"type": "sandbox-nb-test-proposal/v1",
"sandbox_id", "plan_digest", "test", "justification", "proposed_by"}`, the last four
from the proposal entry's body.

**B-183.** A run whose `run_started` entry or attestation carries `initiated_by` is a
notified-body run: both MUST carry `initiated_by: notified_body` and the same
`authorisation`, and the `run_started` entry MUST immediately follow a `gate_decision`
that allowed `run_nb_test` for the `notified_body` or the `regulator`.
*Check:* `nb_tests` (fail).

**B-184.** The authorisation's `proposal_seq` MUST name an `nb_test_proposed` entry
before the run, immediately following a `gate_decision` that allowed `propose_test` for
the `notified_body`, with a non-empty `justification`, whose `proposal_digest` and the
authorisation's both equal the digest recomputed from it. The run's `test_ids` MUST be
the proposed test's id alone, its results MUST report no other test, and no
`nb_test_declined` entry for the proposal may precede the run.
*Check:* `nb_tests` (fail).

**B-185.** On route `pre_authorised`, the plan the run cites MUST have
`notified_body_tests.allowed` true and admit the proposed test (its type, dataset, the
plan schema and the plan's cross-checks), and `approvals` MUST name one
`nb_test_approved` entry per approver the plan names, each over the proposal's seq and
digest, between the proposal and the run, immediately following a `gate_decision` that
allowed `approve_test` for that party.
*Check:* `nb_tests` (fail).

**B-186.** Each such approval MUST carry an IdP signature that verifies as a plan
signature does (section 8), with the nonce `"sbx-nbtest." + b64url(sha256(
"sandbox-nb-test-approval/v1\n" + proposal_digest + "\n" + salt))`, by a person the
plan names for that party. An approval through the development IdP, or matched by
email only, is weak.
*Check:* `nb_tests` (fail; warn when weak).

**B-187.** On route `amendment`, the plan the run cites MUST adopt the proposal under
`notified_body_tests.adopted`, naming a test in its `tests` equal to the proposed test;
the authorisation's `plan_digest` MUST be that plan and its `plan_signed_seq` the
`plan_signed` entry that put it in force, between the proposal and the run. That
version's signatures are held to section 8 like any other (`plan_signatures`).
*Check:* `nb_tests` (fail).

**B-188.** Counting notified-body runs in run order, none MAY exceed the
`notified_body_tests.max_runs` of the plan it cites.
*Check:* `nb_tests` (fail).

**B-189.** A run not marked as the notified body's MUST NOT report a test that an
`nb_test_proposed` entry proposes and the plan the run cites does not list.
*Check:* `nb_tests` (fail).

**B-190.** A verifier MUST run `nb_tests` whenever the ledger holds an
`nb_test_proposed`, `nb_test_approved` or `nb_test_declined` entry, or a run or
attestation carries `initiated_by`; it is not emitted otherwise.
*Check:* `nb_tests` (emitted as stated).

## Appendix A. Ledger entry types

The types a ledger writer accepts (`ledger/store.py`, `ENTRY_TYPES`). A verifier reads
the ones marked with the checks that read them.

| Entry type | Records | Read by |
|---|---|---|
| `plan_signature` | One party's IdP signature over a plan digest (section 8) | `plan_signatures`, `anchor_plan_digest`, `anchor_idp_keys`, `personal_data` |
| `plan_signed` | A plan version put in force: `plan_digest`, `signatures`, `method`, `amendment` | `plan_versions`, `plan_signatures`, `anchor_plan_digest` |
| `signing_key_registered` | `key_id`, `public_key`, `signs` | `signing_keys`, `bundle_format` |
| `harness_key_provisioned`, `scorer_key_provisioned` | `public_key` of the harness's or scorer's key | `signing_keys` |
| `timestamp_authority` | `name`, `root_pem` of the RFC 3161 authority | (copied into `public-keys.json`) |
| `model_configured`, `model_preflight` | The provider's model and its bring-up | — |
| `artifact_committed` | An artifact digest committed | — |
| `dataset_committed` | `dataset_id`, `commitment` | `dataset_commitments` (against the run and the plan it cites) |
| `gate_decision` | `action`, `allow`, `role`, `subject`, `reasons`, `plan_digest` | `run_numbers`, `deletion`, `completeness` (`action` `exit`, `allow` true), `nb_tests` (`propose_test`, `approve_test`, `run_nb_test`) |
| `run_started` | `run_number`, and at a centre `centre` and `agreement`; for a notified-body run `initiated_by`, `requested_role` and `authorisation` (section 27) | `run_numbers`, `dataset_commitments`, `isolation`, `nb_tests` |
| `nb_test_proposed`, `nb_test_approved`, `nb_test_declined` | The notified body's proposed test, an approver's IdP-signed approval of it, a refusal with its reason (section 27) | `nb_tests` |
| `run_attestation` | `run_number`, `outcome`, `envelope`, `harness_statement`, `driver_statement` | `signatures`, `run_numbers`, `harness_statements`, `plan_signatures`, `signing_keys`, `isolation` |
| `run_halted` | `run_number`, `by`, `reason` | `run_numbers` |
| `suspended`, `resumed` | Art. 57(11) | — |
| `image_converted`, `hpc_centre_key`, `hpc_operator_key`, `job_submitted`, `key_released`, `key_release_refused`, `weights_key_released`, `weights_key_release_refused` | HPC centre evidence (sections 12 and 22); `key_released` and `weights_key_released` also record TEE evidence, at a centre or not (section 26) | `isolation`; `key_released`, `key_release_refused` and `weights_key_released` also `tee_attestation` |
| `keys_destroyed` | `key_scopes`, `destroyed_at` | `deletion`, `completeness` |
| `report_generated` | `report_sha256`, `bundle_digest`, `bundle_version`, `report_file`, and with languages `languages`, `authentic_language`, `renderings` (section 25) | `completeness`, `report_signature`, `bundle_format`, `i18n_catalogues`, `report_renderings` |
| `report_signature` | The regulator's IdP signature over `report_sha256`, and the `ledger_head` it commits to (section 20) | `report_signature`, `completeness`, `anchor_idp_keys` |
| `bundle_verified`, `findings_recorded`, `serious_incident`, `publication_consent`, `report_delivered`, `ai_office_notified` | The authority's acts and the participant's consent | — |

## Appendix B. Fixed strings of the personal-data manifest

`categories.staff_identifiers.description`:

> email addresses and identity-provider subject ids of the people who act for the parties: in the plan's roles and processors, and in the ledger entries that record who committed, requested, decided or signed what

`categories.idp_id_tokens.description`:

> the raw OpenID Connect ID token behind each plan or report signature made through an identity provider, kept whole because the IdP's signature covers it; its claims name the signer and say when and how they logged in

`test_subject_data_basis`:

> none, by construction of the export: no image, no ground-truth label or age, no group label of an item and no item id of any dataset. Results are aggregates by group; the model's decision log gives its output per request, keyed by a random request id that nothing in the bundle links to an item

Each is one line with no trailing newline; the quote markers are not part of the
string.
