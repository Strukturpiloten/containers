"""Publication identity and freshness policy for maintained registry tags."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping

RUN_ID_ANNOTATION = "io.github.strukturpiloten.publish.run-id"
RUN_ATTEMPT_ANNOTATION = "io.github.strukturpiloten.publish.run-attempt"
REVISION_ANNOTATION = "org.opencontainers.image.revision"


@dataclass(frozen=True, order=True)
class PublicationIdentity:
    """GitHub's monotonically allocated run ID and its rerun attempt."""

    run_id: int
    run_attempt: int

    @classmethod
    def from_values(cls, run_id: str, run_attempt: str) -> PublicationIdentity:
        """Parse positive GitHub run identifiers."""
        if not run_id.isdecimal() or not run_attempt.isdecimal() or int(run_id) < 1 or int(run_attempt) < 1:
            msg = "Publication run ID and attempt must be positive decimal integers."
            raise ValueError(msg)
        return cls(int(run_id), int(run_attempt))

    @classmethod
    def from_annotations(cls, annotations: Mapping[str, object]) -> PublicationIdentity:
        """Read the identity stamped on a published multiarch index."""
        run_id = annotations.get(RUN_ID_ANNOTATION)
        run_attempt = annotations.get(RUN_ATTEMPT_ANNOTATION)
        if not isinstance(run_id, str) or not isinstance(run_attempt, str):
            msg = "Registry image has no publication run identity."
            raise ValueError(msg)  # noqa: TRY004
        return cls.from_values(run_id, run_attempt)


def require_fresh_promotion(
    *, candidate: PublicationIdentity, existing: PublicationIdentity, same_digest: bool
) -> None:
    """Reject a different digest from an equal or newer publication."""
    if same_digest:
        return
    if existing >= candidate:
        msg = f"Stale publication {candidate} cannot replace {existing}."
        raise ValueError(msg)
