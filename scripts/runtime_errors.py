"""Shared exception identity for runtime probes and their module entrypoint."""


class ProbeError(RuntimeError):
    """A runtime assertion or bounded command failed."""
