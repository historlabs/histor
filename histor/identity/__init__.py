"""Who someone is, as their own identity provider says, and what that makes them here.

:mod:`histor.identity.trust` verifies tokens from any configured issuer and maps their claims
to sandbox roles; :mod:`histor.identity.oidc` is the browser login; :mod:`histor.identity.signature`
binds a plan signature to a fresh login; :mod:`histor.identity.devidp` stands in for every
real IdP in development and says so wherever its tokens end up.
"""
