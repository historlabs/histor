"""Who may do what: one table, read by the gate and by the console.

Two kinds of permission, kept apart because they are enforced differently:

**Actions** change the participation or touch personal data. They go through the gate,
and every decision, allow or deny, is in the ledger before it takes effect.

**Read scopes** decide what the console hands a renderer. They are not recorded one
by one, because reading a result is not processing personal data, and a ledger entry
per page view would bury the entries that matter. Reading the test data is the
exception: it is personal data, so it is an action (``view_test_data``), decided and
recorded like any other (Art. 59(1)(c): access that is documented).

A role here is a *sandbox* role. Nothing in this module knows about identity
providers: an IdP asserts who someone is and, at most, which sandbox role its own
organisation vouches for; the plan says which people hold each role in this
participation; this table says what the role may do. `histor.identity.trust` is where an
IdP's claims become a role, and it can only ever produce a role listed here.
"""

from __future__ import annotations

from typing import Any

ACTIONS = frozenset(
    {
        "sign_plan",
        # Art. 57(5), draft implementing act Art. 5(4): a new version of the plan in
        # force, already signed by both parties, takes its place.
        "amend_plan",
        "configure_model",
        "commit_model",
        "commit_dataset",
        "view_test_data",
        "request_run",
        "halt_run",
        "suspend",
        "resume",
        "exit",
        "generate_report",
        # Art. 57(7): the regulator signs the exit report, through their own IdP.
        "sign_report",
        "verify_bundle",
        # The authority's own acts, which it records rather than the system measuring
        # them (draft implementing act Art. 6 and 8).
        # Art. 6(3)(a) and (c): the regulatory issues, recommendations and lessons.
        "record_findings",
        # AI Act Art. 3(49) and 73; draft act Art. 5(2)(f) and 6(3)(b).
        "report_incident",
        # Art. 6(5): the participant agrees, or refuses, to publish the exit report.
        "record_consent",
        # Art. 6(4): the exit report reached the participant.
        "record_delivery",
        # Art. 8(2): the AI Office was told of a suspension.
        "notify_ai_office",
        # AI Act Annex VII, point 4.4: the notified body may carry out further tests.
        # It proposes one; the plan says who approves it (histor/plan/nbtests.py); once
        # approved, it or the regulator on its behalf requests the run.
        "propose_test",
        "approve_test",
        "decline_test",
        "run_nb_test",
    }
)

# The notified body's tests, from proposal to run. After exit each needs a new
# participation.
NB_TEST_ACTIONS = frozenset({"propose_test", "approve_test", "decline_test", "run_nb_test"})

# Records rather than changes: none of them adds to what is tested or touches the
# data, so a suspension does not hold them back, and they remain after exit. A
# serious incident is most likely reported during exactly the suspension it caused.
RECORDS = frozenset(
    {
        "record_findings",
        "report_incident",
        "record_consent",
        "record_delivery",
        "notify_ai_office",
    }
)

# What can happen before both parties have signed: the signing itself, and the
# provider saying which model the plan should pin. Nothing that runs anything.
BEFORE_SIGNATURE = frozenset({"sign_plan", "configure_model"})

# Who may do what. The notified body reads, and acts only on its own tests (Annex VII
# point 4.4): it proposes one, and runs it once the plan's approvers have approved it.
# The DPA can suspend: Art. 57(10) associates it with the sandbox, and an
# association that cannot stop processing is a formality.
ROLE_ACTIONS: dict[str, frozenset[str]] = {
    # Art. 57(5): the plan is agreed between the competent authority and the
    # participant, so these two, and only these two, sign it.
    "regulator": frozenset(
        {
            "sign_plan",
            "amend_plan",
            "request_run",
            "halt_run",
            "suspend",
            "resume",
            "exit",
            "generate_report",
            "sign_report",
            "verify_bundle",
            "record_findings",
            "report_incident",
            "record_delivery",
            "notify_ai_office",
            # Approves a notified body's test where the plan pre-authorises them, or
            # declines it; and may request its run on the notified body's behalf.
            "approve_test",
            "decline_test",
            "run_nb_test",
        }
    ),
    "dpa": frozenset({"suspend", "halt_run", "generate_report", "report_incident"}),
    # A serious incident may be reported by any party to the plan's procedure; the
    # entry says who reported it. Only the participant consents to publication.
    "provider": frozenset(
        {
            "sign_plan",
            "amend_plan",
            "configure_model",
            "commit_model",
            "request_run",
            "report_incident",
            "record_consent",
            # Only where the plan names the provider among the approvers, which the
            # gate checks. The provider never requests the notified body's run.
            "approve_test",
            "decline_test",
        }
    ),
    # The test lab holds the held-out set: it commits it and may look at it.
    "test_lab": frozenset({"commit_dataset", "view_test_data", "report_incident"}),
    # Processes the test data on the data holder's behalf (GDPR Art. 28): may look at
    # it, never at what the model made of it.
    "data_processor": frozenset({"view_test_data"}),
    "notified_body": frozenset({"propose_test", "run_nb_test"}),
    "verifier": frozenset(),
}

READ_SCOPES = frozenset(
    {
        "plan",  # the signed plan and its signatures
        "model_card",  # the card as committed, and where the data goes
        "progress",  # the live run: phase, items done, elapsed
        "results:full",  # every metric at group resolution
        "results:aggregate",  # outcome per test and which thresholds broke
        "results:disparities",  # between-group gaps only, no accuracy
        "bundle",  # the evidence bundle panel and what stops it sealing
        "ledger",  # the whole ledger tape
        "ledger:data_events",  # data, key, suspension and gate entries only
        "people",  # who has acted, from the gate's record
    }
)

ROLE_SCOPES: dict[str, frozenset[str]] = {
    "regulator": frozenset(
        {"plan", "model_card", "progress", "results:full", "bundle", "ledger", "people"}
    ),
    "notified_body": frozenset(
        {"plan", "model_card", "progress", "results:full", "bundle", "ledger"}
    ),
    # The DPA sees the document and the denials, and disparities between groups;
    # not aggregate accuracy, which is the provider's and the regulator's business.
    "dpa": frozenset(
        {
            "plan",
            "model_card",
            "progress",
            "results:disparities",
            "bundle",
            "ledger:data_events",
            "people",
        }
    ),
    # Aggregate only. Never per-group figures or item-level outputs from the held-out
    # set: a provider who can see which items failed can fit to them.
    "provider": frozenset({"plan", "model_card", "progress", "results:aggregate", "bundle"}),
    "test_lab": frozenset({"plan", "model_card", "progress", "bundle"}),
    # The data processor sees the data and where it is sent, never the results. A
    # processor who could read which items the model got wrong would be one message
    # away from telling the provider.
    "data_processor": frozenset({"plan", "model_card", "progress"}),
    "verifier": frozenset(),
}

ROLES = tuple(r for r in ROLE_ACTIONS if r != "verifier")

# The parties whose signatures make a plan binding.
SIGNING_PARTIES = ("provider", "regulator")


def may(role: str, action: str) -> bool:
    return action in ROLE_ACTIONS.get(role, frozenset())


def can_read(role: str, scope: str) -> bool:
    return scope in ROLE_SCOPES.get(role, frozenset())


def member_matches(entry: Any, subject: str, principal: dict[str, Any]) -> bool:
    """Does a person named in the plan's ``roles`` block match the caller?

    Two forms. A bare email is the original one, and it matches the caller's email.
    It is only as strong as the IdP that asserted the email, which is why
    `histor.identity.trust` refuses an unverified one and pins each IdP to the roles it may
    vouch for. The object form names the IdP and, better, its stable subject
    identifier: an email can be reassigned, a ``sub`` (or Entra's ``oid``) cannot.

        - regulator@authority.example
        - {issuer: "https://login.microsoftonline.com/<tenant>/v2.0", subject: "<oid>"}
        - {issuer: eu-login, email: "assessor@nb.example"}

    ``issuer`` matches the token's ``iss`` or the name the trust configuration gives
    that IdP.
    """
    email = str(principal.get("email") or subject or "").lower()
    if isinstance(entry, str):
        return bool(email) and entry.lower() == email
    if not isinstance(entry, dict):
        return False
    issuer = entry.get("issuer")
    if issuer and issuer not in {principal.get("iss"), principal.get("idp")}:
        return False
    if entry.get("subject") is not None:
        return bool(principal.get("sub")) and entry["subject"] == principal.get("sub")
    if entry.get("email") is not None:
        return bool(email) and str(entry["email"]).lower() == email
    return False


def is_member(
    plan: dict[str, Any], role: str, subject: str, principal: dict[str, Any] | None = None
) -> bool | None:
    """True or False if the plan names people for ``role``; None if it names none."""
    members = (plan.get("roles") or {}).get(role) or []
    if not members:
        return None
    return any(member_matches(m, subject, principal or {}) for m in members)


def describe(entry: Any) -> str:
    """A plan member as a person would read it."""
    if isinstance(entry, str):
        return entry
    if isinstance(entry, dict):
        who = entry.get("email") or entry.get("subject") or "?"
        return f"{who} via {entry['issuer']}" if entry.get("issuer") else str(who)
    return str(entry)
