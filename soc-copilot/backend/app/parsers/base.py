from abc import ABC, abstractmethod
from typing import Any

from app.models.alert import NormalizedAlert


class AlertParser(ABC):
    """Base class for source-specific alert parsers."""

    @abstractmethod
    def parse(self, payload: dict[str, Any]) -> NormalizedAlert:
        ...
