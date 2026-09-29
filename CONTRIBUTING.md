# Contributing

Histor has one maintainer, so this page is short and honest about what fits.

## What is welcome

Open an issue for any of these:

- A bug in the verifier, and above all a bundle it accepts but should reject, or
  rejects but should accept. A bundle that shows it is the best report you can send.
- A question about the formats in `spec/`, or a place where the spec and the code
  disagree.
- An error in the documentation.

A security issue goes to [`SECURITY.md`](SECURITY.md) instead, privately, never to a
public issue.

## Code contributions

Code changes are by arrangement. Open an issue that describes the change before you
write it, so we can agree whether it fits and how. The formats in `spec/` are
contracts that other parties' tooling relies on, so a pull request that arrives
without that conversation may be closed however good it is.

Two rules for any change that is agreed:

- A change to what the verifier accepts comes with a test, and usually with a tampered
  bundle in `examples/tampered/` that shows the case.
- A change to a format in `spec/` changes the schema, the verifier and the samples
  together. The samples are signed, so they are regenerated rather than edited; for
  now only the maintainer can regenerate them.

## Developer Certificate of Origin

Every commit in a pull request carries a sign-off under the
[Developer Certificate of Origin 1.1](https://developercertificate.org/). The
sign-off says that you wrote the change, or otherwise have the right to submit it
under this project's licence (EUPL-1.2). Git adds the line for you:

```sh
git commit -s
```

which appends `Signed-off-by: Your Name <you@mail.example>` to the message.

## Working on the code

```sh
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[test]"
pytest
ruff check . && ruff format --check .
```

CI runs the same commands on Python 3.12 and 3.13.
