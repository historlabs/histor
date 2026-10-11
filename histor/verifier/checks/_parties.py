"""Who signed: whether a party's signature was made through their own
identity provider, and at the time its entry records. Shared by ``plan_signatures``,
``report_signature`` and the notified body's tests (:mod:`histor.verifier.nb_tests`)."""

from __future__ import annotations

import datetime
from typing import Any

from histor.verifier.anchors import Anchors
from histor.verifier.checks._common import RECORDED_AT_TOLERANCE, _instant, _stamp

# How long before the entry recording it an IdP login may have been made. A console
# records a signature within seconds of the login; an hour is generous, and a login
# older than that is not the act the entry records.
LOGIN_BEFORE_RECORDING = datetime.timedelta(hours=1)


def _login_time_problems(entry: dict[str, Any]) -> list[str]:
    """Whether the IdP login behind a signature is of the time its entry was recorded.

    The token's ``iat`` is signed by the IdP; ``recorded_at`` is held to the
    timestamp authority's time (``timestamps``). A login from long before, or one dated
    after the entry that records it, is not the act the entry records: an old login
    replayed into a rebuilt ledger, for one."""
    from histor.identity import jose

    recorded = _instant(entry.get("recorded_at"))
    try:
        issued = int(jose.parse(str(entry["body"]["id_token"])).claims["iat"])
    except (KeyError, TypeError, ValueError, jose.JoseError):
        return []  # signature.verify says what is wrong with the token
    if recorded is None:
        return []
    login = datetime.datetime.fromtimestamp(issued, datetime.UTC)
    if login > recorded + RECORDED_AT_TOLERANCE:
        return [f"the login is dated {_stamp(login)}, after the entry that records it"]
    if login < recorded - LOGIN_BEFORE_RECORDING:
        return [
            f"the login was at {_stamp(login)}, more than an hour before the entry that "
            f"records it ({entry.get('recorded_at')})"
        ]
    return []


# The parties whose agreement a plan needs (Art. 57(5)), and who signs the report.
SIGNING_PARTIES = ("provider", "regulator")


def _claims(body: dict[str, Any]) -> dict[str, Any]:
    """The claims of a recorded ID token; empty if it does not parse (``signature.verify``
    says so)."""
    from histor.identity import jose

    try:
        return dict(jose.parse(str(body["id_token"])).claims)
    except (KeyError, TypeError, jose.JoseError):
        return {}


def _names(member: Any, claims: dict[str, Any]) -> bool:
    """Does a person the plan's ``roles`` block names match a verified token?

    The forms ``gate.rbac.member_matches`` accepts, matched against the token's own
    claims and never the record's: a bare email against ``email``; an object with an
    ``issuer`` against ``iss`` (the IdP's URL, since the name a console gave an IdP is
    not in the token), then ``subject`` against ``sub`` or Entra's ``oid``, or
    ``email`` against ``email``.
    """
    email = str(claims.get("email") or "").lower()
    if isinstance(member, str):
        return bool(email) and member.lower() == email
    if not isinstance(member, dict):
        return False
    issuer = member.get("issuer")
    if issuer and str(issuer).rstrip("/") != str(claims.get("iss", "")).rstrip("/"):
        return False
    if member.get("subject") is not None:
        return member["subject"] in {claims.get("sub"), claims.get("oid")}
    if member.get("email") is not None:
        return bool(email) and str(member["email"]).lower() == email
    return False


def _describe(member: Any) -> str:
    """A plan member as a person would read it (as ``gate.rbac.describe``)."""
    if isinstance(member, dict):
        who = member.get("email") or member.get("subject") or "?"
        return f"{who} via {member['issuer']}" if member.get("issuer") else str(who)
    return str(member)


def _party_problems(
    body: dict[str, Any], plan: dict[str, Any] | None, anchors: Anchors
) -> tuple[list[str], list[str]]:
    """Whether a signature is the party's it is recorded as: what is wrong, and what
    binds it only weakly.

    ``party`` is a field of the ledger entry, which the operator writes. What says
    who signed is the token: its ``iss`` with its ``sub`` or ``email``, which must
    match someone the signed plan names in ``roles`` for that party. And the token
    must have been issued to the audience you hold (``--expect-audience``), so a login
    to some other application cannot be recorded as a signature.

    A party the plan names by email only binds weakly: that warns, and fails when you
    gave any anchor unless the plan pins the IdP (``{issuer, email}``) and the token
    says the email was verified (``email_verified: true``).
    """
    from histor.identity import jose
    from histor.identity import signature as signature_module

    anchored = bool(anchors.external())
    claims = _claims(body)
    party = body.get("party")
    who = f"{claims.get('email') or claims.get('sub')} at {claims.get('iss')}"
    problems: list[str] = []
    weak: list[str] = []
    if anchors.audience:
        try:
            jose.check_audience(claims, anchors.audience)
        except jose.JoseError as error:
            problems.append(f"the login was not to the application you hold: {error}")
    if party not in SIGNING_PARTIES:
        return [*problems, f"it is recorded as signed by {party!r}, not a party to the plan"], []
    roles = (plan or {}).get("roles")
    members = (roles.get(party) if isinstance(roles, dict) else None) or []
    matched = [m for m in members if _names(m, claims)]
    if plan is None:
        problems.append(
            f"the plan it signs is not in the bundle, so nothing says who the {party} is"
        )
    elif not members:
        problems.append(f"the plan names nobody as the {party}, so nothing binds {who} to it")
    elif not matched:
        problems.append(
            f"{who} signed as the {party}, but the plan names "
            f"{', '.join(_describe(m) for m in members)} as the {party}"
        )
    elif named := [
        str(a)
        for m in matched
        if isinstance(m, dict) and m.get("audience")
        for a in (m["audience"] if isinstance(m["audience"], list) else [m["audience"]])
    ]:
        # The plan, which both parties signed, names the console's client id at this
        # party's IdP: the login must be to it, with or without --expect-audience.
        try:
            jose.check_audience(claims, tuple(named))
        except jose.JoseError as error:
            problems.append(f"the login was not to the application the plan names: {error}")
    if (
        matched
        and not problems
        and not any(isinstance(m, dict) and m.get("subject") is not None for m in matched)
    ):
        # Named by email only. An email is an IdP's assertion about an address, which
        # it may not have checked, and which any IdP whose key is accepted can make
        # unless the plan pins the issuer. The stable binding is iss + sub.
        pinned = any(isinstance(m, dict) and m.get("issuer") for m in matched)
        verified = claims.get("email_verified") is True
        development = str(claims.get("iss", "")).rstrip("/") == signature_module.DEV_ISSUER
        lacking = [
            *([] if pinned else ["the plan does not pin the IdP (issuer)"]),
            *([] if verified else ["the token does not say the email was verified"]),
        ]
        said = (
            f"the plan names the {party} ({claims.get('email')}) by email only, not by "
            "issuer and subject"
        )
        if lacking and anchored and not development:
            # The development IdP's signatures are said to identify nobody already.
            problems.append(f"{said}, and {' and '.join(lacking)}")
        else:
            weak.append(
                f"{said}" + (f" ({'; '.join(lacking)})" if lacking else "") + ": an email can "
                "be reassigned, and only a subject is the IdP's stable name for a person; "
                "name them as {issuer: <iss>, subject: <sub>}"
            )
    return problems, weak


def _principal(body: dict[str, Any]) -> tuple[str, str]:
    claims = _claims(body)
    return str(claims.get("iss", "")).rstrip("/"), str(claims.get("sub", ""))
