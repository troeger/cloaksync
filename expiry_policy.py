"""
Expiry decisions for user namespaces.

This module holds only logic. It reads nothing from Kubernetes or
Keycloak and changes nothing, so it can be tested without a cluster.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum


@dataclass(frozen=True)
class ExpirySettings:
    # Days a namespace is kept after its creation or its last extension.
    extension_days: int
    # Days a namespace stays suspended before it is deleted.
    suspension_days: int
    # Days before the deadline at which each reminder is due.
    reminder_days: tuple[int, ...]

    def __post_init__(self) -> None:
        if self.extension_days <= 0:
            raise ValueError("The extension days must be positive.")
        if self.suspension_days < 0:
            raise ValueError("The suspension days must not be negative.")
        if not self.reminder_days:
            raise ValueError("At least one reminder is necessary.")
        for days in self.reminder_days:
            if days <= 0 or days >= self.extension_days:
                raise ValueError(
                    f"Reminder days {days} must be positive and fewer "
                    f"than the extension days {self.extension_days}."
                )


@dataclass(frozen=True)
class NamespaceFacts:
    name: str
    created_at: datetime
    last_extension_at: datetime | None
    last_reminder_at: datetime | None
    # Set when CloakSync moved the deadline so that all reminders fit.
    moved_deadline: datetime | None
    owner_email_known: bool
    suspended: bool


class Status(Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    EXPIRED = "expired"


class Action(Enum):
    NONE = "none"
    SEND_REMINDER = "send reminder"
    SUSPEND = "suspend"
    RESTORE = "restore"
    DELETE = "delete"
    # An action is due, but nobody can be warned by mail.
    ADMIN_REVIEW = "admin review"


@dataclass(frozen=True)
class Decision:
    deadline: datetime
    status: Status
    action: Action
    # Set for SEND_REMINDER: which reminder of the schedule is due.
    reminder_days: int | None = None
    # The deadline is new and has to be stored as moved_deadline.
    moves_deadline: bool = False
    reason: str = ""


_ACTIONS_THAT_NEED_MAIL = {Action.SEND_REMINDER, Action.SUSPEND, Action.DELETE}


def period_start(facts: NamespaceFacts) -> datetime:
    """The start of the current extension period: the last extension, or the creation."""
    return facts.last_extension_at or facts.created_at


def deadline(facts: NamespaceFacts, settings: ExpirySettings) -> datetime:
    regular_deadline = period_start(facts) + timedelta(days=settings.extension_days)
    if facts.moved_deadline is None:
        return regular_deadline
    return max(regular_deadline, facts.moved_deadline)


def status_at(
    namespace_deadline: datetime, settings: ExpirySettings, now: datetime
) -> Status:
    if now < namespace_deadline:
        return Status.ACTIVE
    if now < namespace_deadline + timedelta(days=settings.suspension_days):
        return Status.SUSPENDED
    return Status.EXPIRED


def due_reminder(
    facts: NamespaceFacts,
    settings: ExpirySettings,
    namespace_deadline: datetime,
    now: datetime,
) -> int | None:
    """The reminder days of the latest due reminder that was not sent yet."""
    # A reminder is due once its time (deadline minus reminder days) has come.
    due_reminder_days = [
        days
        for days in settings.reminder_days
        if namespace_deadline - timedelta(days=days) <= now
    ]
    if not due_reminder_days:
        return None
    # Several reminders can be due at once, for example after CloakSync was
    # down for a while. Only the latest one is sent: the one closest to the
    # deadline, so the smallest number of days. The earlier ones are skipped,
    # so the user gets one mail, not several in a row. A failed send does not
    # count as sent, so the same reminder is due again on the next run.
    latest_due_days = min(due_reminder_days)
    latest_due_time = namespace_deadline - timedelta(days=latest_due_days)
    # A reminder sent at or after the due time already covers this reminder.
    # A reminder sent before it belongs to an earlier one in the schedule,
    # or to an older deadline. After an extension, the deadline and all due
    # times move forward, so the old reminders no longer count.
    if facts.last_reminder_at is not None and facts.last_reminder_at >= latest_due_time:
        return None
    return latest_due_days


def all_reminders_sent(
    facts: NamespaceFacts, settings: ExpirySettings, namespace_deadline: datetime
) -> bool:
    final_reminder_time = namespace_deadline - timedelta(
        days=min(settings.reminder_days)
    )
    return (
        facts.last_reminder_at is not None
        and facts.last_reminder_at >= final_reminder_time
    )


def decide(facts: NamespaceFacts, settings: ExpirySettings, now: datetime) -> Decision:
    if now.tzinfo is None:
        raise ValueError("The current time must have a time zone.")

    decision = _decide_by_deadline(facts, settings, now)
    if decision.action in _ACTIONS_THAT_NEED_MAIL and not facts.owner_email_known:
        return Decision(
            decision.deadline,
            decision.status,
            Action.ADMIN_REVIEW,
            reason=f"{decision.action.value} is due, but the owner has no email address",
        )
    return decision


def _decide_by_deadline(
    facts: NamespaceFacts, settings: ExpirySettings, now: datetime
) -> Decision:
    namespace_deadline = deadline(facts, settings)
    status = status_at(namespace_deadline, settings, now)

    if status is Status.ACTIVE:
        # Before the deadline, but still suspended: the user extended in time.
        if facts.suspended:
            return Decision(
                namespace_deadline,
                status,
                Action.RESTORE,
                reason="extended during the suspension period",
            )
        # Before the deadline, and a reminder is due.
        reminder_days = due_reminder(facts, settings, namespace_deadline, now)
        if reminder_days is not None:
            return Decision(
                namespace_deadline,
                status,
                Action.SEND_REMINDER,
                reminder_days=reminder_days,
            )
        # Before the deadline, nothing is due.
        return Decision(namespace_deadline, status, Action.NONE)

    # After the deadline, but the user did not get the full warning.
    # Never suspend without it. This covers namespaces that existed before
    # namespace expiry started, and reminders lost to a relay outage.
    if not all_reminders_sent(facts, settings, namespace_deadline):
        first_reminder_days = max(settings.reminder_days)
        return Decision(
            now + timedelta(days=first_reminder_days),
            Status.ACTIVE,
            Action.SEND_REMINDER,
            reminder_days=first_reminder_days,
            moves_deadline=True,
            reason="deadline moved so that all reminders fit",
        )
    # After the deadline, fully warned, not suspended yet.
    if not facts.suspended:
        return Decision(namespace_deadline, status, Action.SUSPEND)
    # Suspended, and the suspension period is over.
    if status is Status.EXPIRED:
        return Decision(namespace_deadline, status, Action.DELETE)
    # Suspended, and still within the suspension period.
    return Decision(namespace_deadline, status, Action.NONE)
