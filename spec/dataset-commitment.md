# Dataset commitment

The value a plan pins in `datasets[].commitment`, the gate records in
`dataset_committed`, the run attestation names as a `dataset:<id>` subject, and the
harness checks when it opens a sealed set. It binds a result to the data it came
from without disclosing the data. The reference implementation is
`histor/crypto/commitment.py`.

## 1. What it covers

A dataset is a directory holding `manifest.jsonl`, one item per line:

```json
{"id": "3f9a…", "path": "images/3f9a….png", "true_age": 16.5, "groups": {"sex": "f", "skin_tone_band": "V-VI"}}
```

and the file each item's `path` names. The commitment covers every item and the
SHA-256 of every file it names. It covers nothing else: a file the manifest does not
list is not committed, is not sealed, and is refused if a sealed set carries one.

An item has exactly the members `id` (a non-empty string), `path`, `true_age` (a
finite JSON number) and `groups` (an object mapping strings to strings). No `id` and
no `path` appears twice.

A `path` is a relative POSIX path: not empty, not starting with `/`, with no empty,
`.` or `..` segment, no backslash and no NUL, and not `manifest.jsonl` itself. The
file it names, with any links resolved, is inside the dataset directory. A manifest
that breaks any of these has no commitment.

## 2. Scheme v2 (current)

```
preimage = "histor-dataset-commitment/v2\n"
         || for each item, in ascending order of id (by code point):
              canonical_json(item + {"image_sha256": hex(SHA-256(file bytes))}) || "\n"
commitment = "sha256:" || hex(SHA-256(preimage))
```

`hex` is lowercase. `canonical_json` is the plan's canonical form (sorted keys, no
insignificant whitespace, UTF-8 without escaping non-ASCII), with numbers in one
canonical form:

- an integral value is written as an integer, with no fraction or exponent:
  `17`, `17.0`, `1.7e1` and `17.00` are all `17`, and `-0.0` is `0`;
- any other value is written as the shortest decimal that parses back to the same
  IEEE 754 double, in positional notation: `16.50` is `16.5`;
- `NaN`, the infinities, booleans and strings are not numbers, and are refused.

So the commitment depends on the values in the manifest, not on how a tool happened
to write them. For the two items `b` (`true_age` `17.0`) and `a` (`16.5`) the
preimage is:

```
histor-dataset-commitment/v2
{"groups":{"sex":"f","skin_tone_band":"V-VI"},"id":"a","image_sha256":"…","path":"images/a.png","true_age":16.5}
{"groups":{"sex":"f","skin_tone_band":"V-VI"},"id":"b","image_sha256":"…","path":"images/b.png","true_age":17}
```

(The engine's test suite, published with the engine, pins v2 to this example.)

## 3. Scheme v1 (before 2026-09-28)

The same items in the same order, each serialised by Python's
`json.dumps(record, sort_keys=True)` (separators `", "` and `": "`, non-ASCII
escaped, numbers as parsed, so `17` and `17.0` differ), concatenated with no
separator and no domain line:

```
commitment = "sha256:" || hex(SHA-256(json_v1(record_1) || json_v1(record_2) || …))
```

v1 is kept so that a plan signed over a v1 value still verifies. Nothing computes a
new v1 value unless asked.

## 4. Which scheme a value is

Both schemes write `sha256:<64 hex>`, the form the plan schema's `sha256_digest` and
an in-toto subject digest take, so the value does not name its scheme. A checker
recomputes the commitment over the content under v2, then v1, and accepts the value
if either matches; the engine's test lab records which one did (`commitment_scheme` in
the sealed file's sidecar and in the lab's record).

This is unambiguous: a v2 preimage begins with the domain line and a v1 preimage
with `{` (or is empty), so no content has the same preimage under both schemes, and
a value can match a given content under two schemes only through a SHA-256
collision. Accepting v1 does not weaken the binding: v1 is not canonical, but for
content it commits to, it is as collision-resistant as v2.

## 5. Sealing

A sealed set (`histor/sandbox/sealed.py`, container `sbx-sealed-v1`) is a gzipped
tar of `manifest.jsonl` and the files it lists, encrypted with AES-256-GCM, with the
dataset id and this commitment bound in as associated data. Every member is a
regular file with uid and gid 0, empty user and group names, mtime 0 and mode
`0644`, and the gzip header carries no time or name, so the same set seals to the
same plaintext. Opening refuses, before writing anything, a member that is not a
regular file, a name that fails the path rules of §1, a name that appears twice, and
a file the manifest does not list; it then writes into an empty directory and checks
the content against the commitment (§4).
