"""Operational observability: the services' own logs, never evidence.

:mod:`histor.obs.logs` is the structured logging every service uses. Evidence (the
ledger, the relay's hash log, the harness's result line, the drop log) has formats of
its own and never goes through here.
"""
