"""
Expiry decisions for user namespaces.

This module holds only logic. It reads nothing from Kubernetes or
Keycloak and changes nothing, so it can be tested without a cluster.
"""

from datetime import datetime, timedelta
from enum import Enum


class ExpirySettings:
    def __init__(
        self, extension_days: int, suspension_days: int, reminder_days: tuple[int, ...]
    ) -> None:
        if extension_days <= 0:
            raise ValueError("The extension days must be positive.")
        if suspension_days < 0:
            raise ValueError("The suspension days must not be negative.")
        if not reminder_days:
            raise ValueError("At least one reminder is necessary.")
        for days in reminder_days:
            if days <= 0 or days >= extension_days:
                raise ValueError(
                    f"Reminder days {days} must be positive and fewer "
                    f"than the extension days {extension_days}."
                )

        # Days a namespace is kept after its creation or its last extension.
        self.extension_days = extension_days
        # Days a namespace stays suspended before it is deleted.
        self.suspension_days = suspension_days
        # Days before the deadline at which each reminder is due.
        self.reminder_days = reminder_days


class NamespaceFacts:
    def __init__(
        self,
        name: str,
        created_at: datetime,
        last_extension_at: datetime | None,
        last_reminder_at: datetime | None,
        moved_deadline: datetime | None,
        owner_email_known: bool,
        suspended: bool,
    ) -> None:
        self.name = name
        self.created_at = created_at
        self.last_extension_at = last_extension_at
        self.last_reminder_at = last_reminder_at
        # Set when CloakSync moved the deadline so that all reminders fit.
        self.moved_deadline = moved_deadline
        self.owner_email_known = owner_email_known
        self.suspended = suspended


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


class Decision:
    def __init__(
        self,
        deadline: datetime,
        status: Status,
        action: Action,
        reminder_days: int | None = None,
        moves_deadline: bool = False,
        reason: str = "",
    ) -> None:
        self.deadline = deadline
        self.status = status
        self.action = action
        # Set for SEND_REMINDER: which reminder of the schedule is due.
        self.reminder_days = reminder_days
        # The deadline is new and has to be stored as moved_deadline.
        self.moves_deadline = moves_deadline
        self.reason = reason


_ACTIONS_THAT_NEED_MAIL = {Action.SEND_REMINDER, Action.SUSPEND, Action.DELETE}

# A reminder sent this long after its due time still counts as on time. It has
# to be shorter than the smallest reminder days, so it covers the time between
# two runs, not a missed reminder.
_ON_TIME_TOLERANCE = timedelta(hours=1)


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


def next_due_reminder(
    facts: NamespaceFacts,
    settings: ExpirySettings,
    namespace_deadline: datetime,
    now: datetime,
) -> int | None:
    """The reminder days of the next reminder in the schedule, if it is due."""
    # Reminders go out in order, from the most days to the fewest. A reminder
    # counts as sent if the last reminder went out at or after its due time
    # (deadline minus reminder days). After an extension, the deadline and all
    # due times move forward, so reminders for the old deadline no longer count.
    # A failed send is not stored as sent, so it is due again on the next run.
    unsent_reminder_days = [
        days
        for days in settings.reminder_days
        if facts.last_reminder_at is None
        or facts.last_reminder_at < namespace_deadline - timedelta(days=days)
    ]
    if not unsent_reminder_days:
        return None
    next_days = max(unsent_reminder_days)
    if namespace_deadline - timedelta(days=next_days) > now:
        return None
    return next_days


def decide(facts: NamespaceFacts, settings: ExpirySettings, now: datetime) -> Decision:
    """What namespace expiry does next for the namespace."""
    if now.tzinfo is None:
        raise ValueError("The current time must have a time zone.")

    namespace_deadline = deadline(facts, settings)
    status = status_at(namespace_deadline, settings, now)
    reminder_days = next_due_reminder(facts, settings, namespace_deadline, now)

    if status is Status.ACTIVE and facts.suspended:
        # The user extended during the suspension period: the new deadline is in
        # the future, but the namespace is still suspended.
        decision = Decision(
            namespace_deadline,
            status,
            Action.RESTORE,
            reason="extended during the suspension period",
        )
    elif reminder_days is not None:
        # A reminder is due. This can also be after the deadline: a namespace
        # is never suspended before every reminder went out.
        due_time = namespace_deadline - timedelta(days=reminder_days)
        if now - due_time <= _ON_TIME_TOLERANCE:
            # The reminder is on time.
            decision = Decision(
                namespace_deadline,
                status,
                Action.SEND_REMINDER,
                reminder_days=reminder_days,
            )
        else:
            # The reminder is late, for example because CloakSync or the relay
            # was down, or because the namespace existed before namespace
            # expiry started. The deadline moves, so the user still gets the
            # full notice of this reminder.
            decision = Decision(
                now + timedelta(days=reminder_days),
                Status.ACTIVE,
                Action.SEND_REMINDER,
                reminder_days=reminder_days,
                moves_deadline=True,
                reason="reminder is late, deadline moved",
            )
    elif status is Status.ACTIVE:
        # Before the deadline, and no reminder is due.
        decision = Decision(namespace_deadline, status, Action.NONE)
    elif not facts.suspended:
        # After the deadline, all reminders sent, and not suspended yet.
        decision = Decision(namespace_deadline, status, Action.SUSPEND)
    elif status is Status.EXPIRED:
        # Suspended, and the suspension period is over.
        decision = Decision(namespace_deadline, status, Action.DELETE)
    else:
        # Suspended, and still within the suspension period.
        decision = Decision(namespace_deadline, status, Action.NONE)

    if decision.action in _ACTIONS_THAT_NEED_MAIL and not facts.owner_email_known:
        # The due action needs a mail, but the owner has no email address.
        return Decision(
            decision.deadline,
            decision.status,
            Action.ADMIN_REVIEW,
            reason=f"{decision.action.value} is due, but the owner has no email address",
        )
    return decision
