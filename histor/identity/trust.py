"""Which identity providers the sandbox trusts, and for what.

A sandbox has several organisations in it and each brings its own identity provider:
the competent authority its government directory, the provider its corporate tenant,
the notified body and the DPA theirs. There is no one IdP to trust, so the console is
an OpenID Connect relying party that trusts a *list* of issuers, each configured
with:

* **what it may vouch for.** ``roles.allowed`` caps the sandbox roles an IdP can
  produce. A provider's Entra tenant can make someone a ``provider`` and nothing
  else, whatever claims its administrators put in a token. This is the property the
  whole arrangement rests on: without it, any participant's IdP admin could mint a
  regulator.
* **where its roles are.** Every IdP puts them somewhere different
  (``realm_access.roles`` in Keycloak, ``roles`` in Entra ID, ``groups`` in Okta,
  nowhere in Google or EU Login). ``preset`` sets the usual place and each field can
  be overridden.
* **which claims must hold.** ``require`` pins claims to values: Entra's ``tid`` to
  one tenant, Google's ``hd`` to one domain. A multi-tenant issuer with no pin
  trusts every tenant in the world.
* **how strong a login must be to sign.** ``signing.acr_values`` is asked for when a
  plan is signed, and ``signing.accept_acr`` / ``accept_amr`` are what the token must
  come back with. eIDAS levels of assurance travel as ``acr`` values, so an
  authority can require ``http://eidas.europa.eu/LoA/high`` for its own signature.

The IdP proposes; the plan disposes. A role from here is only a claim that the
person's organisation holds that role. The gate then checks the person is named in
the plan's ``roles`` block for this participation (`histor.gate.rbac.member_matches`).

IdPs that speak only SAML 2.0, national eID schemes and the eIDAS nodes among them, sit
behind a broker (Keycloak, for example) that speaks OIDC to the
console. The broker is one more issuer here; `docs/identity.md` has the matrix.
"""

from __future__ import annotations

import json
import os
import threading
import time
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from histor.gate.rbac import ROLES
from histor.identity import jose

LEEWAY_SECONDS = 60


class AuthError(Exception):
    """A token that does not establish who someone is, with the reason why."""


# Where each kind of IdP usually keeps things. Everything here can be overridden per
# IdP in the trust file; a preset is a default, never a requirement.
PRESETS: dict[str, dict[str, Any]] = {
    "keycloak": {
        "roles_claim": "realm_access.roles",
        "subject_claim": "sub",
        "email_claims": ["email"],
        "require_email_verified": True,
    },
    "entra": {
        # App roles arrive in ``roles``. ``oid`` is the user's id across every app in
        # the tenant; ``sub`` is pairwise per app and changes if the app is
        # re-registered. Entra sends no email_verified: the tenant pin in ``require``
        # is what makes the address trustworthy.
        "roles_claim": "roles",
        "subject_claim": "oid",
        "email_claims": ["email", "preferred_username", "upn"],
        "require_email_verified": False,
        "organisation_claim": "tid",
    },
    "okta": {
        "roles_claim": "groups",
        "subject_claim": "sub",
        "email_claims": ["email"],
        "require_email_verified": True,
    },
    "google": {
        # No roles. Pin ``hd`` in ``require`` and use ``fixed_roles``.
        "roles_claim": None,
        "subject_claim": "sub",
        "email_claims": ["email"],
        "require_email_verified": True,
        "organisation_claim": "hd",
    },
    "eu-login": {
        # The Commission's EU Login. No roles; fixed_roles plus the plan's list.
        "roles_claim": None,
        "subject_claim": "sub",
        "email_claims": ["email"],
        "require_email_verified": False,
    },
    "generic": {
        "roles_claim": "roles",
        "subject_claim": "sub",
        "email_claims": ["email"],
        "require_email_verified": True,
    },
}


@dataclass(frozen=True)
class SigningPolicy:
    """How fresh and how strong a login must be for a plan signature."""

    acr_values: tuple[str, ...] = ()
    accept_acr: tuple[str, ...] = ()
    accept_amr: tuple[str, ...] = ()
    max_age_seconds: int = 300


@dataclass(frozen=True)
class IdPConfig:
    name: str
    issuer: str
    client_id: str
    display: str = ""
    preset: str = "generic"
    allowed_roles: frozenset[str] = frozenset()
    roles_claim: str | None = "roles"
    role_map: dict[str, str] = field(default_factory=dict)
    fixed_roles: frozenset[str] = frozenset()
    subject_claim: str = "sub"
    email_claims: tuple[str, ...] = ("email",)
    require_email_verified: bool = True
    organisation_claim: str | None = None
    require: dict[str, Any] = field(default_factory=dict)
    signing: SigningPolicy = SigningPolicy()
    scopes: tuple[str, ...] = ("openid", "email", "profile")
    client_secret_env: str | None = None
    jwks: tuple[dict[str, Any], ...] = ()
    jwks_uri: str | None = None
    authorization_endpoint: str | None = None
    token_endpoint: str | None = None
    end_session_endpoint: str | None = None
    development: bool = False

    @property
    def label(self) -> str:
        return self.display or self.name

    def client_secret(self) -> str | None:
        """From the environment, named in the file. A secret in a YAML file is a
        secret in a repository sooner or later."""
        return os.environ.get(self.client_secret_env) if self.client_secret_env else None


@dataclass(frozen=True)
class Principal:
    """Who a verified token says someone is, and what their IdP vouches for."""

    idp: str
    iss: str
    sub: str
    email: str
    name: str
    roles: frozenset[str]
    organisation: str = ""
    acr: str = ""
    amr: tuple[str, ...] = ()
    auth_time: int | None = None
    issued_at: int | None = None
    development: bool = False
    token: str = ""
    jwk: dict[str, Any] = field(default_factory=dict)

    @property
    def display(self) -> str:
        return self.email or self.sub

    def gate_principal(self) -> dict[str, Any]:
        """What the gate records and matches plan members against."""
        return {"idp": self.idp, "iss": self.iss, "sub": self.sub, "email": self.email}


def _claim(claims: dict[str, Any], path: str | None) -> Any:
    """A claim by dotted path: ``realm_access.roles``, ``resource_access.console.roles``."""
    if not path:
        return None
    value: Any = claims
    for part in path.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def _strings(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return value.split()
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


def _idp_from(raw: dict[str, Any], audience: str) -> IdPConfig:
    try:
        name, issuer = str(raw["name"]), str(raw["issuer"]).rstrip("/")
    except KeyError as error:
        raise ValueError(f"an IdP entry is missing {error}") from error
    preset_name = str(raw.get("preset", "generic"))
    if preset_name not in PRESETS:
        raise ValueError(f"{name}: unknown preset {preset_name!r}; one of {sorted(PRESETS)}")
    preset = PRESETS[preset_name]
    roles = raw.get("roles") or {}
    allowed = frozenset(roles.get("allowed") or [])
    unknown = sorted((allowed | set(roles.get("fixed") or [])) - set(ROLES))
    unknown += sorted(set((roles.get("map") or {}).values()) - set(ROLES))
    if unknown:
        raise ValueError(f"{name}: roles not known to the sandbox: {unknown}")
    if not allowed:
        raise ValueError(
            f"{name}: roles.allowed is empty. Say which sandbox roles this IdP may vouch "
            "for; an IdP that may vouch for anything is one that can mint a regulator."
        )
    if "client_secret" in raw:
        raise ValueError(f"{name}: put the client secret in the environment (client_secret_env)")
    if not issuer.startswith("https://") and not raw.get("allow_http"):
        raise ValueError(f"{name}: issuer must be https")
    signing = raw.get("signing") or {}
    jwks_file = raw.get("jwks_file")
    jwks = raw.get("jwks") or (
        json.loads(Path(jwks_file).read_text(encoding="utf-8")) if jwks_file else None
    )
    return IdPConfig(
        name=name,
        issuer=issuer,
        client_id=str(raw.get("client_id") or audience),
        display=str(raw.get("display") or ""),
        preset=preset_name,
        allowed_roles=allowed,
        roles_claim=roles.get("claim", preset["roles_claim"]),
        role_map=dict(roles.get("map") or {}),
        fixed_roles=frozenset(roles.get("fixed") or []),
        subject_claim=str(raw.get("subject_claim") or preset["subject_claim"]),
        email_claims=tuple(raw.get("email_claims") or preset["email_claims"]),
        require_email_verified=bool(
            raw.get("require_email_verified", preset["require_email_verified"])
        ),
        organisation_claim=raw.get("organisation_claim", preset.get("organisation_claim")),
        require=dict(raw.get("require") or {}),
        signing=SigningPolicy(
            acr_values=tuple(signing.get("acr_values") or []),
            accept_acr=tuple(signing.get("accept_acr") or []),
            accept_amr=tuple(signing.get("accept_amr") or []),
            max_age_seconds=int(signing.get("max_age_seconds", 300)),
        ),
        scopes=tuple(raw.get("scopes") or ("openid", "email", "profile")),
        client_secret_env=raw.get("client_secret_env"),
        jwks=tuple((jwks or {}).get("keys", []) if isinstance(jwks, dict) else (jwks or [])),
        jwks_uri=raw.get("jwks_uri"),
        authorization_endpoint=raw.get("authorization_endpoint"),
        token_endpoint=raw.get("token_endpoint"),
        end_session_endpoint=raw.get("end_session_endpoint"),
    )


Fetch = Callable[[str], dict[str, Any]]


def plain_http_allowed(url: str) -> bool:
    """Plain http only to this machine's loopback address, as OAuth allows a native
    client (RFC 8252 §8.3). By the parsed host, never a prefix:
    ``http://127.0.0.1.attacker.example`` starts with the same characters."""
    parts = urllib.parse.urlsplit(url)
    return parts.scheme == "http" and parts.hostname in {"127.0.0.1", "::1"}


def http_fetch(url: str) -> dict[str, Any]:
    """GET a JSON document. Discovery and key sets only; never a user's data."""
    if not url.startswith("https://") and not plain_http_allowed(url):
        raise AuthError(f"refusing to fetch identity metadata over plain http: {url}")
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=10) as response:
        document: dict[str, Any] = json.loads(response.read())
    return document


class TrustConfig:
    """The trusted issuers, their metadata and their keys."""

    KEY_TTL_SECONDS = 600

    def __init__(self, idps: list[IdPConfig], audience: str, fetch: Fetch | None = None) -> None:
        names = [i.name for i in idps]
        duplicates = sorted({n for n in names if names.count(n) > 1})
        if duplicates:
            raise ValueError(f"IdP names must be unique: {duplicates}")
        self.idps = {i.name: i for i in idps}
        self.by_issuer = {i.issuer: i for i in idps}
        self.audience = audience
        self.fetch = fetch or http_fetch
        self._metadata: dict[str, dict[str, Any]] = {}
        self._keys: dict[str, tuple[float, list[dict[str, Any]]]] = {}
        self._lock = threading.Lock()

    @classmethod
    def load(cls, path: Path, fetch: Fetch | None = None) -> TrustConfig:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        audience = str(raw.get("audience") or "sandbox-console")
        return cls([_idp_from(i, audience) for i in raw.get("idps") or []], audience, fetch)

    def add(self, idp: IdPConfig) -> None:
        if idp.name in self.idps:
            raise ValueError(f"an IdP called {idp.name!r} is already configured")
        self.idps[idp.name] = idp
        self.by_issuer[idp.issuer] = idp

    # ---------------------------------------------------------------- metadata

    def metadata(self, idp: IdPConfig) -> dict[str, Any]:
        """Endpoints from the file, or from OIDC discovery when the file names none."""
        configured = {
            "authorization_endpoint": idp.authorization_endpoint,
            "token_endpoint": idp.token_endpoint,
            "jwks_uri": idp.jwks_uri,
            "end_session_endpoint": idp.end_session_endpoint,
        }
        if idp.jwks or all(configured[k] for k in ("authorization_endpoint", "token_endpoint")):
            return configured
        with self._lock:
            if idp.name not in self._metadata:
                document = self.fetch(f"{idp.issuer}/.well-known/openid-configuration")
                if str(document.get("issuer", "")).rstrip("/") != idp.issuer:
                    raise AuthError(
                        f"{idp.name}: discovery says issuer {document.get('issuer')!r}, "
                        f"configured {idp.issuer!r}"
                    )
                self._metadata[idp.name] = document
            discovered = self._metadata[idp.name]
        return {k: v or discovered.get(k) for k, v in configured.items()}

    def keys(self, idp: IdPConfig, refresh: bool = False) -> list[dict[str, Any]]:
        if idp.jwks:
            return list(idp.jwks)
        with self._lock:
            cached = self._keys.get(idp.name)
            if cached and not refresh and time.monotonic() - cached[0] < self.KEY_TTL_SECONDS:
                return cached[1]
        uri = self.metadata(idp).get("jwks_uri")
        if not uri:
            raise AuthError(f"{idp.name}: no jwks_uri configured or discovered")
        keys = list(self.fetch(str(uri)).get("keys", []))
        with self._lock:
            self._keys[idp.name] = (time.monotonic(), keys)
        return keys

    # ------------------------------------------------------------ verification

    def authenticate(
        self,
        raw: str,
        now: float | None = None,
        nonce: str | None = None,
        audience: str | None = None,
    ) -> Principal:
        """Verify a token from any trusted issuer and say who it names.

        Raises :class:`AuthError` with the reason. Never returns a principal with a
        role its IdP is not allowed to vouch for.
        """
        now = time.time() if now is None else now
        try:
            token = jose.parse(raw)
        except jose.JoseError as error:
            raise AuthError(str(error)) from error
        claims = token.claims
        issuer = str(claims.get("iss", "")).rstrip("/")
        idp = self.by_issuer.get(issuer)
        if idp is None:
            raise AuthError(f"issuer {issuer!r} is not trusted by this sandbox")

        jwk = self._verify_signature(idp, token)
        self._check_times(claims, now)
        self._check_audience(claims, audience or idp.client_id)
        if nonce is not None and claims.get("nonce") != nonce:
            raise AuthError("the token's nonce is not the one this login asked for")
        for name, expected in idp.require.items():
            if _claim(claims, name) != expected:
                raise AuthError(f"{idp.name}: claim {name!r} must be {expected!r}")

        subject = str(_claim(claims, idp.subject_claim) or "")
        if not subject:
            raise AuthError(f"{idp.name}: token has no {idp.subject_claim!r} claim")
        email = next((str(v) for c in idp.email_claims if (v := _claim(claims, c))), "").lower()
        if email and idp.require_email_verified and claims.get("email_verified") is not True:
            # An unverified address is one anybody could have typed. Keep the subject,
            # drop the email: the plan can still name this person by ``sub``.
            email = ""

        return Principal(
            idp=idp.name,
            iss=issuer,
            sub=subject,
            email=email,
            name=str(claims.get("name") or email or subject),
            roles=self._roles(idp, claims),
            organisation=str(_claim(claims, idp.organisation_claim) or ""),
            acr=str(claims.get("acr") or ""),
            amr=tuple(_strings(claims.get("amr"))),
            auth_time=int(claims["auth_time"]) if "auth_time" in claims else None,
            issued_at=int(claims["iat"]) if "iat" in claims else None,
            development=idp.development,
            token=token.raw,
            jwk=jwk,
        )

    def _verify_signature(self, idp: IdPConfig, token: jose.Token) -> dict[str, Any]:
        try:
            jwk = jose.select_key(token, self.keys(idp))
        except jose.JoseError:
            # Keys rotate. One refetch, not a loop an attacker can drive.
            try:
                jwk = jose.select_key(token, self.keys(idp, refresh=True))
            except jose.JoseError as error:
                raise AuthError(f"{idp.name}: {error}") from error
        try:
            jose.verify(token, jwk)
        except jose.JoseError as error:
            raise AuthError(f"{idp.name}: {error}") from error
        return jwk

    @staticmethod
    def _check_times(claims: dict[str, Any], now: float) -> None:
        try:
            exp = float(claims["exp"])
        except (KeyError, TypeError, ValueError) as error:
            raise AuthError("token has no usable exp") from error
        if now > exp + LEEWAY_SECONDS:
            raise AuthError("token has expired")
        for name in ("nbf", "iat"):
            if name in claims and float(claims[name]) > now + LEEWAY_SECONDS:
                raise AuthError(f"token {name} is in the future")

    @staticmethod
    def _check_audience(claims: dict[str, Any], audience: str) -> None:
        aud = _strings(claims.get("aud"))
        if audience not in aud:
            raise AuthError(f"token is for {aud}, not for {audience!r}")
        if len(aud) > 1 and claims.get("azp") != audience:
            raise AuthError("token has several audiences and was not issued to this console")

    @staticmethod
    def _roles(idp: IdPConfig, claims: dict[str, Any]) -> frozenset[str]:
        asserted = set(idp.fixed_roles)
        for value in _strings(_claim(claims, idp.roles_claim)):
            role = idp.role_map.get(value) if idp.role_map else value
            if role:
                asserted.add(role)
        return frozenset(asserted & idp.allowed_roles)

    # --------------------------------------------------------------- signing

    def check_signing_login(self, principal: Principal, now: float | None = None) -> list[str]:
        """Is this login fresh and strong enough to sign a plan with?"""
        now = time.time() if now is None else now
        idp = self.idps[principal.idp]
        policy = idp.signing
        problems = []
        # auth_time is what OIDC returns when max_age is sent, but not every IdP does.
        # The signing login is forced with prompt=login, so where it is missing the
        # token's own iat is when the person authenticated; the record says which.
        when = principal.auth_time if principal.auth_time is not None else principal.issued_at
        if when is None:
            problems.append("the IdP did not say when the person authenticated")
        elif now - when > policy.max_age_seconds + LEEWAY_SECONDS:
            problems.append(
                f"the authentication is {int(now - when)} s old; signing "
                f"needs one within {policy.max_age_seconds} s"
            )
        if policy.accept_acr and principal.acr not in policy.accept_acr:
            problems.append(
                f"the authentication was at level {principal.acr or 'unstated'!r}; signing "
                f"needs one of {list(policy.accept_acr)}"
            )
        if policy.accept_amr and not set(policy.accept_amr) & set(principal.amr):
            problems.append(
                f"the authentication used {list(principal.amr) or 'unstated methods'}; "
                f"signing needs one of {list(policy.accept_amr)}"
            )
        return problems
