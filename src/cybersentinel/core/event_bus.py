"""Decoupled event bus for subscribing to assessment lifecycle events."""

from typing import Callable
from cybersentinel.models.events import AssessmentEvent
from cybersentinel.utils.timestamps import utc_now

EventHandler = Callable[[AssessmentEvent], None]


class EventBus:
    """Thread-safe event bus distributing AssessmentEvents to subscribers."""

    def __init__(self):
        self._handlers: list[EventHandler] = []
        self._history: list[AssessmentEvent] = []

    def subscribe(self, handler: EventHandler) -> None:
        """Register a callback for all published events."""
        if handler not in self._handlers:
            self._handlers.append(handler)

    def unsubscribe(self, handler: EventHandler) -> None:
        """Unregister an event callback."""
        if handler in self._handlers:
            self._handlers.remove(handler)

    def emit(
        self,
        event_type: str,
        message: str,
        agent: str | None = None,
        metadata: dict | None = None,
    ) -> AssessmentEvent:
        """Create and publish an event to all subscribers."""
        event = AssessmentEvent(
            timestamp=utc_now(),
            type=event_type,
            agent=agent,
            message=message,
            metadata=metadata or {},
        )
        self._history.append(event)

        for handler in list(self._handlers):
            try:
                handler(event)
            except Exception:
                # Event subscriber exceptions should not crash the core pipeline
                pass

        return event

    @property
    def history(self) -> list[AssessmentEvent]:
        """Return full event history log."""
        return list(self._history)

    def clear(self) -> None:
        """Clear recorded events."""
        self._history.clear()
