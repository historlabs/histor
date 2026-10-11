"""Isolation: the evidence each run carries that the model was kept from
the data and the network, and at an HPC centre, who vouches for it."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from typing import Any

from histor.crypto import release, signing, weights
from histor.verifier.checks._common import FAIL, PASS, WARN, CheckResult, _of_run, _raw_key

# --- 5. isolation -----------------------------------------------------------


# Who may sign an ``hpc_centre`` claim: the key id their envelopes name, the ledger
# entry that records their public key, and how the verifier's output names them.
SIGNERS = {
    "centre": ("hpc-centre", "hpc_centre_key", "the centre"),
    "sandbox_operator": ("sandbox-operator", "hpc_operator_key", "the sandbox operator"),
}


# The plan's OCI pins, and the component each is converted into a SIF for.
PINNED_COMPONENTS = {
    "model_image_digest": "model",
    "relay_image_digest": "relay",
    "harness_image_digest": "harness",
}


def _signer(record: dict[str, Any]) -> str:
    """Who signed a claim or a conversion. Without ``signed_by`` it predates the field,
    from when only a centre signed."""
    return str(record.get("signed_by") or "centre")


def _signature(record: dict[str, Any], signer: str) -> Any:
    """The signature, from ``signature``, or for the centre alone from the older
    ``centre_signature``. An operator's claim cannot borrow the centre's field."""
    if record.get("signature"):
        return record["signature"]
    return record.get("centre_signature") if signer == "centre" else None


def _envelope(value: Any) -> dict[str, Any]:
    """A DSSE envelope as it is carried: the object itself (in a ledger entry's body), or
    base64 of its JSON (in the isolation arm)."""
    if isinstance(value, dict):
        return value
    decoded = json.loads(base64.b64decode(str(value), validate=True))
    if not isinstance(decoded, dict):
        raise ValueError("the signature is not a DSSE envelope")
    return decoded


@dataclass(frozen=True)
class _HpcKey:
    """The keys a signer of HPC evidence is checked under, where they came from
    (``anchor``: your ``--centre-keys``; ``ledger``: its ``hpc_centre_key`` or
    ``hpc_operator_key`` entry; ``bundle``: public-keys.json alone), and the seq of the
    ledger entry that recorded them."""

    pems: tuple[str, ...]
    source: str
    recorded_at: int = 0


def _signer_key(
    signer: str,
    public_keys: dict[str, str],
    entries: list[dict[str, Any]],
    centre: str | None = None,
    centre_keys: tuple[tuple[str, str], ...] = (),
) -> tuple[_HpcKey | None, str]:
    """The public key for a signer, or why there is none.

    For the centre, the keys you gave (``--centre-keys``) under the centre's name or
    ``hpc-centre`` are the only ones used, and the ledger's record must be one of them.
    Otherwise the ledger's entry is the record, chained and timestamped;
    ``public-keys.json`` is where a bundle made before the entry was read carried it.
    When both are present they must be the same key.
    """
    key_id, entry_type, name = SIGNERS[signer]
    recorded = [
        (int(e.get("seq") or 0), str(e["body"]["public_key"]))
        for e in entries
        if e.get("entry_type") == entry_type
        and isinstance(e.get("body"), dict)
        and e["body"].get("public_key")
        and (centre is None or e["body"].get("centre") in (None, centre))
    ]
    bundled = public_keys.get(key_id)
    if signer == "centre" and centre_keys:
        given = tuple(pem for kid, pem in centre_keys if kid in (centre, key_id))
        if not given:
            return None, (
                f"you gave no key for {centre!r} (--centre-keys names "
                f"{sorted({kid for kid, _ in centre_keys})})"
            )
        held = {_raw_key(pem) for pem in given}
        for where, pem in [*((entry_type, p) for _, p in recorded), ("public-keys.json", bundled)]:
            if pem and _raw_key(pem) not in held:
                return None, (
                    f"the bundle's {where} key for {centre!r} is not a key you hold for it: "
                    "the evidence could have been signed by whoever recorded that key"
                )
        return _HpcKey(given, "anchor"), ""
    if recorded and bundled and recorded[-1][1].strip() != bundled.strip():
        return None, (
            f"the ledger's {entry_type} and the bundle's {key_id!r} key are different keys, "
            f"so nothing says which one is {name}'s"
        )
    if recorded:
        return _HpcKey((recorded[-1][1],), "ledger", recorded[-1][0]), ""
    if bundled is None:
        return None, f"the bundle carries no key for {name}, so its signature cannot be checked"
    return _HpcKey((bundled,), "bundle"), ""


def _verify_under(envelope: Any, key_id: str, key: _HpcKey) -> dict[str, Any]:
    """The payload of ``envelope`` signed under ``key_id`` by one of ``key``'s keys."""
    error: Exception = signing.VerificationError("no key")
    for pem in key.pems:
        try:
            return signing.verify_json(_envelope(envelope), {key_id: pem})
        except signing.VerificationError as failed:
            error = failed
    raise error


@dataclass
class _Conversions:
    """The verified OCI-to-SIF pairs, by OCI digest, and who signed them."""

    sif: dict[str, str] = field(default_factory=dict)
    signers: set[str] = field(default_factory=set)
    problems: list[str] = field(default_factory=list)
    sources: set[tuple[str, str]] = field(default_factory=set)  # (signer, key source)


def _conversions(
    public_keys: dict[str, str],
    entries: list[dict[str, Any]],
    centre_keys: tuple[tuple[str, str], ...] = (),
) -> _Conversions:
    """Every ``image_converted`` entry, each verified under the key of whoever it says
    signed it. A later conversion of the same image replaces an earlier one."""
    out = _Conversions()
    for entry in entries:
        if entry.get("entry_type") != "image_converted":
            continue
        body = entry.get("body") or {}
        seq = entry.get("seq")
        signer = _signer(body)
        if signer not in SIGNERS:
            out.problems.append(f"an image conversion (seq {seq}) names an unknown signer")
            continue
        key_id, _, name = SIGNERS[signer]
        centre = str(body["centre"]) if body.get("centre") else None
        key, missing = _signer_key(signer, public_keys, entries, centre, centre_keys)
        if key is None:
            out.problems.append(f"image conversion (seq {seq}): {missing}")
            continue
        if key.source == "ledger" and seq is not None and key.recorded_at > int(seq):
            out.problems.append(
                f"image conversion (seq {seq}) is signed under {name}'s key, which the ledger "
                f"recorded only later (seq {key.recorded_at})"
            )
            continue
        try:
            pair = _verify_under(_signature(body, signer), key_id, key)
            oci, sif = str(pair["oci_digest"]), str(pair["sif_digest"])
        except (signing.VerificationError, ValueError, KeyError, TypeError):
            out.problems.append(f"an image conversion (seq {seq}) is not {name}'s")
            continue
        if body.get("oci_digest", oci) != oci or body.get("sif_digest", sif) != sif:
            out.problems.append(
                f"an image conversion (seq {seq}) records digests other than the ones {name} signed"
            )
            continue
        out.sif[oci] = sif
        out.signers.add(signer)
        out.sources.add((signer, key.source))
    return out


def _release_problems(
    run: int,
    outcome: str,
    plan: dict[str, Any],
    conversions: _Conversions,
    entries: list[dict[str, Any]],
) -> tuple[list[str], str]:
    """Whether a run's keys went to the job that was measured, and a sentence saying
    what the release shows.

    The broker checked this before it sealed anything. It is checked again here from
    the ``key_released`` entry, because the verifier takes nobody's word for it, the
    broker's included.
    """
    released = _of_run(entries, "key_released", run)
    if not released:
        if _of_run(entries, "key_release_refused", run) and outcome == "halted":
            # The broker failed closed and the run stopped: nothing was opened in it.
            return [], f"run {run} was refused its keys and halted, so no data was opened"
        return [
            "no key_released entry for this run: nothing shows its keys went to the job "
            "that was measured"
        ], ""
    problems = []
    if len(released) > 1:
        problems.append(
            f"keys were released {len(released)} times for this run; a release is once per run"
        )
    entry = released[-1]
    body = entry["body"]
    measurements = body.get("measurements")
    measurements = measurements if isinstance(measurements, dict) else {}
    measured = measurements.get("sif")
    measured = measured if isinstance(measured, dict) else {}
    for pin, component in PINNED_COMPONENTS.items():
        oci = plan.get("artifacts", {}).get(pin)
        expected = conversions.sif.get(str(oci)) if oci else None
        if expected is None:
            continue  # said already, as a pin with no signed conversion
        if measured.get(component) != expected:
            problems.append(
                f"the job measured its {component} SIF as {str(measured.get(component))[:19]}… "
                f"but the conversion of the pinned image recorded {expected[:19]}…: the keys "
                "went to a job running something else"
            )
    isolation = release.network_isolation(plan)
    problems.extend(release.isolation_problems(measurements, isolation))
    submitted = _of_run(entries, "job_submitted", run)
    if submitted and str(submitted[-1]["body"].get("slurm_job_id")) != str(
        body.get("slurm_job_id")
    ):
        problems.append(
            f"keys were released to job {body.get('slurm_job_id')}, but job "
            f"{submitted[-1]['body'].get('slurm_job_id')} was the one submitted"
        )
    attested = [int(e.get("seq", 0)) for e in _of_run(entries, "run_attestation", run)]
    if attested and int(entry.get("seq", 0)) > min(attested):
        problems.append("the key release is recorded after the run's attestation")
    return problems, (
        f"run {run}'s keys were released once, to a key (digest "
        f"{str(body.get('job_public_key_digest'))[:19]}…) held by Slurm job "
        f"{body.get('slurm_job_id')}, after that job's measured SIF digests matched the "
        + (
            "conversions and the syscall filter the plan declares refused every connection "
            "the probe tried"
            if isolation == release.SYSCALL_FILTER
            else "conversions, every probe from the model's namespace was blocked and that "
            "namespace held only loopback"
        )
        + f" (ledger seq {entry.get('seq')})"
    )


def _weights_problems(
    run: int, outcome: str, plan: dict[str, Any], entries: list[dict[str, Any]]
) -> tuple[list[str], str]:
    """Whether the provider's own releaser released the weights key for this run to
    the job that got the data keys, and a sentence saying so.

    Checked from the provider's signed receipt, under the releaser key the plan pins,
    so this does not rest on the control plane's word that the provider agreed. A plan
    that pins no encrypted weights is read as before, and the note says the weights
    were in the model's image.
    """
    pin = weights.pin_of(plan)
    if pin is None:
        return [], (
            f"run {run}'s plan pins no encrypted weights, so the model's weights were in its "
            "image and passed through the sandbox with it"
        )
    try:
        weights.check_pin(pin)
    except weights.WeightsError as error:
        return [f"the plan's weights pin does not hold: {error}"], ""
    released = _of_run(entries, "weights_key_released", run)
    if not released:
        refused = _of_run(entries, "weights_key_release_refused", run) or _of_run(
            entries, "key_release_refused", run
        )
        if refused and outcome == "halted":
            return [], f"run {run} was refused the weights key and halted, so the model never ran"
        return [
            "no weights_key_released entry for this run: nothing shows the provider released "
            "its weights to the job"
        ], ""
    problems = []
    if len(released) > 1:
        problems.append(
            f"the weights key was released {len(released)} times for this run; a release is "
            "once per run"
        )
    entry = released[-1]
    body = entry["body"]
    try:
        receipt = signing.verify_json(
            body.get("receipt"), {weights.RELEASER_KEY_ID: str(pin["releaser_public_key"])}
        )
    except (signing.VerificationError, ValueError, TypeError) as error:
        problems.append(
            "the provider's receipt for the weights key does not verify under the releaser "
            f"key the plan pins: {error}"
        )
        return problems, ""
    if receipt.get("format") != weights.RECEIPT_FORMAT:
        problems.append(f"the provider's receipt is not an {weights.RECEIPT_FORMAT}")
    differing = [f for f in weights.RECEIPT_FIELDS if str(receipt.get(f)) != str(body.get(f))]
    if differing:
        problems.append(
            f"the ledger's weights release differs from the provider's receipt in {differing}"
        )
    for name in ("ciphertext_digest", "plaintext_digest"):
        if receipt.get(name) != pin.get(name):
            problems.append(f"the provider released a key for other weights ({name}) than the pin")
    max_runs = (plan.get("limits") or {}).get("max_runs")
    try:
        over = max_runs is not None and int(receipt.get("runs_released", 0)) > int(max_runs)
    except (TypeError, ValueError):
        over = True
    if over:
        problems.append(
            f"the provider's receipt counts {receipt.get('runs_released')} runs, beyond the "
            f"plan's max_runs of {max_runs}"
        )
    data = _of_run(entries, "key_released", run)
    if data:
        data_body = data[-1]["body"]
        for name in ("request_digest", "job_public_key_digest"):
            if data_body.get(name) != receipt.get(name):
                problems.append(
                    f"the data keys and the weights key answer different {name}s: they did not "
                    "go to the same job key"
                )
    attested = [int(e.get("seq", 0)) for e in _of_run(entries, "run_attestation", run)]
    if attested and int(entry.get("seq", 0)) > min(attested):
        problems.append("the weights release is recorded after the run's attestation")
    return problems, (
        f"the provider's own releaser released run {run}'s weights key (its receipt verifies "
        f"under the releaser key the plan pins; run {receipt.get('runs_released')} of "
        f"{receipt.get('max_runs')}) to the same job key as the data keys (digest "
        f"{str(receipt.get('job_public_key_digest'))[:19]}…, ledger seq {entry.get('seq')}), "
        "and only the weights' ciphertext passed through the sandbox"
    )


def _refusals(entries: list[dict[str, Any]]) -> list[str]:
    """Every refused key release, as an incident, in the words the ledger records.

    A refusal is the broker failing closed, which is the control working, so it does
    not fail the bundle. It is still an incident: a second request for one run, or a
    job whose measurements did not match, is what an attempt on the keys looks like.
    So it is never left out of the verdict.
    """
    out = []
    for entry in entries:
        kind = entry.get("entry_type")
        if kind not in {"key_release_refused", "weights_key_release_refused"}:
            continue
        body = entry.get("body") or {}
        reasons = body.get("reasons") or body.get("reason") or "no reason recorded"
        if isinstance(reasons, list):
            reasons = "; ".join(str(r) for r in reasons)
        job = f", job {body['slurm_job_id']}" if body.get("slurm_job_id") else ""
        who = (
            "the weights key was not released"
            if kind == "weights_key_release_refused"
            else "the key broker refused a key release"
        )
        out.append(
            f"INCIDENT: {who} for run {body.get('run_number')}{job} (ledger seq "
            f"{entry.get('seq')}): {reasons}"
        )
    return out


def _centre_problems(
    evidence: dict[str, Any],
    plan: dict[str, Any],
    public_keys: dict[str, str],
    entries: list[dict[str, Any]],
    run: int = 0,
    outcome: str = "",
    centre_keys: tuple[tuple[str, str], ...] = (),
    sources: set[tuple[str, str]] | None = None,
) -> tuple[list[str], list[str]]:
    """What is wrong with an ``hpc_centre`` claim, and what a sound one shows. Where
    each signer's key came from is added to ``sources`` as ``(signer, source)``, for
    :func:`check_isolation` to hold to the anchors you gave.

    Four things: the signature, under the key of whoever ``signed_by`` names; the chain
    from the plan's OCI pins to the SIF images that ran; the key release bound to the
    job; and, where the plan pins encrypted weights, the provider's release of the
    weights key to the same job key. A bundle made before the release existed, with no
    ``signed_by`` in the claim and no ``key_released`` entry anywhere in its ledger, is
    read as it was then, and the verdict says what it lacks.
    """
    signer = _signer(evidence)
    if signer not in SIGNERS:
        return [f"the claim names an unknown signer {signer!r}"], []
    key_id, _, name = SIGNERS[signer]
    signature = _signature(evidence, signer)
    if not signature:
        return [f"it claims isolation at a centre with no signature from {name}"], []
    centre = str(evidence["centre"]) if evidence.get("centre") else None
    key, missing = _signer_key(signer, public_keys, entries, centre, centre_keys)
    if key is None:
        return [missing], []
    try:
        signed = _verify_under(signature, key_id, key)
    except (signing.VerificationError, ValueError, KeyError, TypeError) as error:
        return [f"{name}'s signature does not verify: {error}"], []
    problems = []
    attested = [int(e.get("seq", 0)) for e in _of_run(entries, "run_attestation", run)]
    if key.source == "ledger" and attested and key.recorded_at > min(attested):
        problems.append(
            f"{name}'s key was recorded in the ledger at seq {key.recorded_at}, after the run's "
            "attestation: it was not fixed before the run"
        )
    if sources is not None:
        sources.add((signer, key.source))
    # signed_by is inside what was signed, so who signed cannot be changed afterwards.
    claimed = {k: v for k, v in evidence.items() if k not in {"signature", "centre_signature"}}
    if signed != claimed:
        problems.append(f"{name} signed something other than the evidence the run carries")

    conversions = _conversions(public_keys, entries, centre_keys)
    problems += conversions.problems
    if sources is not None:
        sources |= conversions.sources
    for pin in PINNED_COMPONENTS:
        oci = plan.get("artifacts", {}).get(pin)
        if oci and oci not in conversions.sif:
            problems.append(f"no signed conversion of the pinned {pin} {str(oci)[:19]}…")

    notes = []
    others = conversions.signers - {signer}
    if others:
        notes.append(
            "the image conversions were signed by "
            + " and ".join(SIGNERS[s][2] for s in sorted(others))
        )
    legacy = "signed_by" not in evidence and not any(
        e.get("entry_type") == "key_released" for e in entries
    )
    if legacy:
        notes.append(
            f"run {run} predates keys released to the job: there is no key_released entry, "
            "so nothing shows its keys went only to the job that was measured"
        )
    else:
        found, released = _release_problems(run, outcome, plan, conversions, entries)
        problems += found
        if released:
            notes.append(released)
        found, released = _weights_problems(run, outcome, plan, entries)
        problems += found
        if released:
            notes.append(released)
    return problems, notes


def is_placeholder(agreement: dict[str, Any]) -> bool:
    """Whether what the plan pins says of itself that it is not an executed
    undertaking.

    A run may go to a centre that has signed nothing: then the plan pins a placeholder
    whose ``id`` and ``note`` record that, so the run is authorised under something
    that says plainly what it is. The word ``placeholder`` in either is the marker, and
    the verifier reports such a run as uncovered rather than as covered by a centre's
    word."""
    marked = str(agreement.get("id", "")) + " " + str(agreement.get("note", ""))
    return "placeholder" in marked.lower()


def _undertaking_problems(
    run: int, evidence: dict[str, Any], plan: dict[str, Any], entries: list[dict[str, Any]]
) -> tuple[dict[str, Any] | None, list[str]]:
    """The undertaking that covered a run at a centre, or what is wrong.

    The gate names the agreement in ``run_started`` when it authorises a run at a
    centre. A run whose evidence names another centre, or whose start names no
    agreement, ran where no confidentiality undertaking in the plan reached."""
    centre = str(evidence.get("centre"))
    started = next(
        (
            e["body"]
            for e in entries
            if e.get("entry_type") == "run_started" and e["body"].get("run_number") == run
        ),
        None,
    )
    if started is None or not started.get("agreement"):
        return None, [
            f"the run was not authorised as a run at {centre!r}, so no confidentiality "
            "undertaking covered it there"
        ]
    if started.get("centre") != centre:
        return None, [
            f"the run was authorised at {started.get('centre')!r} but its evidence is from "
            f"{centre!r}"
        ]
    named = started["agreement"]
    pinned = next((a for a in plan.get("agreements") or [] if a.get("id") == named.get("id")), None)
    if pinned is None:
        return None, [f"the run names undertaking {named.get('id')!r}, which its plan lacks"]
    if pinned.get("centre") != centre or pinned.get("document_sha256") != named.get(
        "document_sha256"
    ):
        return None, [
            f"undertaking {named.get('id')!r} in the plan is not the one the run names, "
            f"or is not from {centre!r}"
        ]
    return pinned, []


# Each backend can produce exactly one kind of isolation evidence. A predicate whose
# ``backend`` and ``isolation_evidence.type`` disagree claims more (or other) than
# happened, whichever of the two is true: "kubernetes" beside ``local_process`` names
# an isolated platform the run never touched.
ISOLATION_BY_BACKEND = {
    "kubernetes": "cilium",
    "slurm": "hpc_centre",
    "local": "local_process",
}


def check_isolation(
    plans: dict[str, dict[str, Any]],
    statements: list[dict[str, Any]],
    public_keys: dict[str, str] | None = None,
    entries: list[dict[str, Any]] | None = None,
    centre_keys: tuple[tuple[str, str], ...] = (),
    anchored: bool = False,
) -> CheckResult:
    """``centre_keys`` are the centres' keys you gave (``--centre-keys``); ``anchored``
    that you gave any anchor, under which a centre's word checked under a key only the
    bundle names fails: whoever assembled the bundle could have recorded its own key as
    the centre's."""
    question = "is isolation evidence present and does it match the plan's policy?"

    kinds: set[str] = set()
    # hpc_centre runs, by who signed their evidence: (run, centre).
    vouched: dict[str, list[tuple[Any, str]]] = {}
    # Where each signer's key came from, over every hpc_centre run.
    sources: set[tuple[str, str]] = set()
    centre_notes: list[str] = []
    undertakings: list[str] = []
    # The ids of what the plan pins that says of itself it is not an executed
    # undertaking (is_placeholder): reported as placeholders, not as a centre's word.
    placeholders: list[str] = []
    egress: list[str] = []
    for statement in statements:
        predicate = statement["predicate"]
        run = predicate["run_number"]
        plan = plans.get(predicate.get("plan_digest", ""), {})
        pinned = plan.get("artifacts", {}).get("network_policy_digest")
        evidence = predicate.get("isolation_evidence") or {}
        kind = str(evidence.get("type"))
        kinds.add(kind)

        backend = str(predicate.get("backend"))
        expected = ISOLATION_BY_BACKEND.get(backend)
        if expected is None:
            return CheckResult(
                "isolation", question, FAIL, f"run {run} names unknown backend {backend!r}"
            )
        if kind != expected:
            return CheckResult(
                "isolation",
                question,
                FAIL,
                f"run {run} says it ran on the {backend} backend but carries {kind} "
                f"isolation evidence; the {backend} backend produces {expected}. The "
                "attestation contradicts itself, so neither claim can be relied on",
            )

        if kind == "cilium":
            if evidence.get("network_policy_digest") != pinned:
                return CheckResult(
                    "isolation",
                    question,
                    FAIL,
                    f"run {run} ran under network policy "
                    f"{str(evidence.get('network_policy_digest'))[:19]}… but the plan pins "
                    f"{str(pinned)[:19]}…: the results are from a different experiment",
                )
            if not evidence.get("drop_log_digest"):
                return CheckResult(
                    "isolation", question, FAIL, f"run {run} carries no drop log digest"
                )
        elif kind == "hpc_centre":
            problems, notes = _centre_problems(
                evidence,
                plan,
                public_keys or {},
                entries or [],
                int(run),
                str(predicate.get("outcome", "")),
                centre_keys,
                sources,
            )
            undertaking, uncovered = _undertaking_problems(run, evidence, plan, entries or [])
            problems.extend(uncovered)
            if problems:
                return CheckResult(
                    "isolation", question, FAIL, f"run {run}: " + "; ".join(problems)
                )
            vouched.setdefault(_signer(evidence), []).append((run, str(evidence.get("centre"))))
            centre_notes += notes
            agreement = undertaking or {}
            undertakings.append(str(agreement.get("id")))
            if is_placeholder(agreement):
                placeholders.append(str(agreement.get("id")))
        elif kind == "local_process":
            if evidence.get("model_egress"):
                egress.append(f"run {run} -> {evidence['model_egress']}")
            continue  # reported as a caveat, below; not a failure of the bundle
        else:
            return CheckResult(
                "isolation", question, FAIL, f"run {run} carries unknown isolation type {kind!r}"
            )

    # A hosted model is the one case where the data is known to have left the host,
    # not merely able to. That is said outright, beside the caveat.
    sent = (
        " THE TEST DATA WAS SENT TO A HOSTED MODEL OUTSIDE THE HOST: " + "; ".join(egress) + "."
        if egress
        else ""
    )
    # A refused key release is an incident wherever it happened, and is always said.
    incidents = _refusals(entries or [])
    reported = (" " + " ".join(incidents)) if incidents else ""
    if kinds == {"local_process"}:
        return CheckResult(
            "isolation",
            question,
            WARN,
            "NO ISOLATION WAS ENFORCED. Every run in this bundle was executed as "
            "ordinary processes on one host. The results describe what the model "
            "answered; they establish nothing about whether it could have reached the "
            "data or the network. This bundle is a development artefact and is not "
            "sandbox evidence." + sent + reported,
        )
    if "local_process" in kinds:
        return CheckResult(
            "isolation",
            question,
            WARN,
            "some runs in this bundle were executed with no isolation enforced "
            "(isolation_evidence.type = local_process); those runs are not evidence."
            + sent
            + reported,
        )
    if vouched:
        # The centre's word is worth its key, and a key only the bundle names is
        # whoever assembled the bundle's to name: under any anchor that fails.
        unanchored = sorted(
            f"{SIGNERS[signer][2]}'s (from "
            + ("the ledger's own record" if source == "ledger" else "public-keys.json alone")
            + ")"
            for signer, source in sources
            if source != "anchor" and (signer == "centre" or source == "bundle")
        )
        if unanchored and anchored:
            return CheckResult(
                "isolation",
                question,
                FAIL,
                f"KEYS NOT ANCHORED: the HPC evidence was checked under {', '.join(unanchored)} "
                "key, which only the bundle names: whoever assembled it could have recorded a "
                "key of its own as the centre's. Give the centre's key with --centre-keys, "
                "obtained from the centre",
            )
        caveat = (
            f" The HPC evidence was checked under {', '.join(unanchored)} key, which only the "
            "bundle names; give the centre's key with --centre-keys."
            if unanchored
            else ""
        )
        # A different trust model, and said so rather than given the same tick; and
        # whose word it is, since the operator's is not the centre's. Where the plan
        # pins a placeholder rather than an executed undertaking, nothing covered root
        # on the node, and the line says that instead of naming a contract.
        signed = sorted(set(undertakings) - set(placeholders))
        unsigned = sorted(set(placeholders))
        covered = caveat + " Root on the compute node could read the model while it ran"
        if signed:
            covered += (
                "; what covered that is a contract, the centre's confidentiality undertaking "
                f"({', '.join(signed)}), not cryptography"
            )
        if unsigned:
            covered += (
                f"; nothing covered that under {', '.join(unsigned)}, which the plan pins as a "
                "placeholder recording that the centre signed no confidentiality undertaking"
            )
        covered += "."
        return CheckResult(
            "isolation", question, WARN, _vouched(vouched, centre_notes) + covered + reported
        )
    if incidents:
        return CheckResult(
            "isolation", question, WARN, f"isolation evidence: {sorted(kinds)}." + reported
        )
    return CheckResult("isolation", question, PASS, f"isolation evidence: {sorted(kinds)}")


def _vouched(vouched: dict[str, list[tuple[Any, str]]], notes: list[str]) -> str:
    """What a sound ``hpc_centre`` claim rests on, by who signed it."""
    sentences = []
    for signer, runs in sorted(vouched.items()):
        numbers = ", ".join(str(run) for run, _ in runs)
        centres = ", ".join(sorted({centre for _, centre in runs}))
        if signer == "centre":
            sentences.append(
                f"isolation vouched for by {centres} (run {numbers}): the centre's signature "
                "over its job record and node configuration verifies, and every pinned image "
                "has a signed conversion to the SIF that ran. This rests on the centre's word, "
                "not on a network policy anyone can hash and a drop log anyone can read."
            )
        else:
            sentences.append(
                f"isolation at {centres} (run {numbers}) vouched for by the sandbox operator: "
                "the operator's signature over the job record and node configuration its "
                "courier observed verifies, and every pinned image has a signed conversion to "
                "the SIF that ran. This rests on the sandbox operator's word: the party that "
                "runs the sandbox, vouching for its own run. That is weaker than a centre's "
                "word, and neither is a network policy anyone can hash or a drop log anyone "
                "can read."
            )
    return " ".join(sentences) + "".join(f" {note[0].upper()}{note[1:]}." for note in notes)
