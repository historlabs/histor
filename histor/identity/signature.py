"""A plan signature that is a login at the signer's own identity provider.

Art. 57(5) asks for a plan agreed between the provider and the competent authority.
The demo scripts sign it with keys the sandbox holds, which proves the sandbox signed
it. What the authority and the provider need is proof that *their* person agreed to
*these* terms, established by *their* IdP, and checkable later without trusting the
sandbox.

An OpenID Connect ID token nearly is that. It is signed by the IdP, names the person
(``iss``, ``sub``), says when and how strongly they authenticated (``auth_time``,
``acr``, ``amr``), and echoes back the ``nonce`` the relying party sent. So the nonce
is made from the plan digest:

    nonce = "sbx-plan." + b64url(sha256("sandbox-plan-signature/v1\\n" + digest + "\\n" + salt))

and the login is forced fresh (``prompt=login``, ``max_age=0``) at the level of
assurance the IdP's signing policy asks for. The IdP's signature over the token then
covers the plan digest: the sandbox cannot move a signature to other terms without
the IdP's key. Any OIDC provider can do this; no IdP needs to know what a sandbox
plan is. Sigstore's keyless signing rests on the same idea: a login at the signer's
own IdP stands in for a key the signer would otherwise have to hold.

The record keeps the raw token and the key that verified it, so the verifier can
check it offline. What it cannot establish offline is that the key really was the
IdP's at the time: that rests on the key set the console fetched when the signature
was made, and the verifier says so.

The exit report is signed the same way (Art. 57(7)). The nonce
is made from the report's sha256 under its own domain and prefix,
``"sandbox-report-signature/v1"`` and ``sbx-report.``, so a login that signed a plan
can never be read as having signed a report whose hash happens to be given in its
place, nor the other way round.

A report signature also commits to the ledger's head when the regulator signs: the
sequence number and hash of the last entry then (``ledger_head``), under the domain
``"sandbox-report-signature/v2"``. Through the hash chain that is every entry before
it, the ``report_generated`` entry and its bundle digest included, so the ledger the
regulator signed over cannot be cut or rewritten short of that point without the
IdP's key. What comes after the signature is anchored only outside the bundle (the
verifier's ``--expect-head`` and ``--checkpoint``).

What this is not: a qualified electronic signature under eIDAS. Where an authority
needs one, the same plan digest goes to its QES tool (AutoFirma, a QSCD) and the
detached signature is recorded beside this one; `docs/identity.md` has that route.
"""

from __future__ import annotations

import hashlib
import secrets
from typing import Any

from histor.identity import jose
from histor.identity.trust import Principal

# The development IdP's issuer (histor.identity.devidp.ISSUER, which is set from this). Kept
# here so that reading a signature never imports the development IdP and the dev keys
# behind it: the verifier needs only the name, to say that such a signature
# identifies nobody.
DEV_ISSUER = "https://dev-idp.sandbox.invalid"

METHOD = "oidc_id_token"
DOMAIN = b"sandbox-plan-signature/v1\n"

# What can be signed, and the field of the ledger entry that carries its digest.
DOCUMENTS: dict[str, tuple[bytes, str, str]] = {
    "plan": (DOMAIN, "sbx-plan.", "plan_digest"),
    "report": (b"sandbox-report-signature/v1\n", "sbx-report.", "report_sha256"),
    # An approver's approval of a notified body's proposed test (Annex VII point 4.4),
    # where the plan pre-authorises such tests: over the proposal's digest
    # (histor/plan/nbtests.py proposal_digest), under its own domain.
    "nb_test": (b"sandbox-nb-test-approval/v1\n", "sbx-nbtest.", "proposal_digest"),
}


# A report signature that also commits to the ledger head at signing (``ledger_head``).
REPORT_HEAD_DOMAIN = b"sandbox-report-signature/v2\n"


def head_ref(head: dict[str, Any]) -> str:
    """A ledger head as a nonce binds it and the verifier takes it: ``<seq>:<entry_hash>``."""
    return f"{int(head['seq'])}:{head['entry_hash']}"


def new_salt() -> str:
    return secrets.token_urlsafe(16)


def binding_nonce(
    digest: str, salt: str, document: str = "plan", head: dict[str, Any] | None = None
) -> str:
    """The nonce a signing login is sent with. ``head``, for a report only, is the
    ledger's last entry when the regulator signs (``{"seq", "entry_hash"}``)."""
    domain, prefix, _ = DOCUMENTS[document]
    if head is not None:
        if document != "report":
            raise ValueError("only a report signature commits to the ledger head")
        domain = REPORT_HEAD_DOMAIN + head_ref(head).encode("utf-8") + b"\n"
    material = domain + digest.encode("utf-8") + b"\n" + salt.encode("utf-8")
    return prefix + jose.b64url_encode(hashlib.sha256(material).digest())


def document_of(entry_body: dict[str, Any]) -> str:
    """Which document a recorded signature is over, from the field that names it."""
    if "report_sha256" in entry_body:
        return "report"
    return "nb_test" if "proposal_digest" in entry_body else "plan"


def record(
    principal: Principal,
    salt: str,
    max_age_seconds: int,
    ledger_head: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """What goes into the ``plan_signature`` or ``report_signature`` entry, besides
    party and digest. ``ledger_head`` is the head a report signature's nonce commits to."""
    out: dict[str, Any] = {
        "method": METHOD,
        "idp": principal.idp,
        "issuer": principal.iss,
        "sub": principal.sub,
        "email": principal.email,
        "organisation": principal.organisation,
        "acr": principal.acr,
        "amr": list(principal.amr),
        "auth_time": principal.auth_time,
        "freshness": "auth_time" if principal.auth_time is not None else "iat after prompt=login",
        "max_age_seconds": max_age_seconds,
        "salt": salt,
        "id_token": principal.token,
        "jwk": principal.jwk,
        "jwk_thumbprint": jose.thumbprint(principal.jwk) if principal.jwk else None,
        "development": principal.development,
    }
    if ledger_head is not None:
        out["ledger_head"] = {
            "seq": int(ledger_head["seq"]),
            "entry_hash": str(ledger_head["entry_hash"]),
        }
    return out


def verify(entry_body: dict[str, Any]) -> list[str]:
    """Check a recorded signature offline. Returns the problems; empty means it holds.

    Everything is recomputed from the token, never read from the record's own fields:
    a record that says ``issuer: authority`` over a token from somewhere else is a
    forgery.
    """
    if entry_body.get("method") != METHOD:
        return [f"not an IdP-bound signature (method {entry_body.get('method')!r})"]
    try:
        token = jose.parse(str(entry_body["id_token"]))
        jose.verify(token, dict(entry_body["jwk"]))
    except (KeyError, TypeError, jose.JoseError) as error:
        return [f"the ID token does not verify against the recorded key: {error}"]

    claims = token.claims
    problems = []
    document = document_of(entry_body)
    field = DOCUMENTS[document][2]
    head = entry_body.get("ledger_head")
    if head is not None and (
        document != "report"
        or not isinstance(head, dict)
        or not isinstance(head.get("seq"), int)
        or not isinstance(head.get("entry_hash"), str)
    ):
        return [f"its ledger_head {head!r} is not a report's {{seq, entry_hash}}"]
    expected = binding_nonce(
        str(entry_body.get(field)), str(entry_body.get("salt")), document, head
    )
    if claims.get("nonce") != expected:
        problems.append(f"the token's nonce does not commit to this {document} digest")
    if str(claims.get("iss", "")).rstrip("/") != entry_body.get("issuer"):
        problems.append(f"the token was issued by {claims.get('iss')!r}, not the recorded issuer")
    subject_values = {claims.get("sub"), claims.get("oid")}
    if entry_body.get("sub") not in subject_values:
        problems.append("the token does not name the recorded subject")
    issued = claims.get("iat")
    auth_time = claims.get("auth_time", issued)
    if auth_time is None or issued is None:
        problems.append("the token does not say when the person authenticated")
    elif int(issued) - int(auth_time) > int(entry_body.get("max_age_seconds", 300)) + 60:
        problems.append("the authentication was not fresh when the token was issued")
    return problems


def is_development(entry_body: dict[str, Any]) -> bool:
    return bool(entry_body.get("development")) or entry_body.get("issuer") == DEV_ISSUER


def dev_sign(
    keys_dir: Any,
    email: str,
    role: str,
    digest: str,
    document: str = "plan",
    ledger_head: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """A signature from the development IdP, for the demo scripts.

    The same token, nonce and record the console produces when someone signs through
    the development IdP, and marked ``development`` the same way: the verifier says
    it identifies nobody. The scripts use it so that what `make demo` seals is
    shaped like what a real participation seals.
    """
    from histor.identity import devidp
    from histor.identity.trust import TrustConfig

    dev = devidp.DevIdP(keys_dir)
    trust = TrustConfig([], dev.audience)
    trust.add(dev.config())
    salt = new_salt()
    nonce = binding_nonce(digest, salt, document, ledger_head)
    principal = trust.authenticate(dev.mint(email, [role], nonce=nonce), nonce=nonce)
    return record(principal, salt, trust.idps[principal.idp].signing.max_age_seconds, ledger_head)
