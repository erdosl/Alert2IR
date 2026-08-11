"""Contract for normalizing source-specific alerts."""

from typing import Protocol, TypeVar

from alert2ir.core.models import CanonicalAlert

PayloadT = TypeVar("PayloadT", contravariant=True)


class SourceAdapter(Protocol[PayloadT]):
    def normalize(self, payload: PayloadT) -> CanonicalAlert:
        """Normalize a source-specific payload into a canonical alert."""
        ...
