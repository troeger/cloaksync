import unittest
from datetime import UTC, datetime, timedelta

from namespace_expiry import (
    Action,
    ExpirySettings,
    NamespaceFacts,
    decide,
)

DAY = timedelta(days=1)

SETTINGS = ExpirySettings(
    extension_days=90,
    suspension_days=14,
    reminder_days=(30, 7, 1),
)

CREATED = datetime(2026, 2, 1, tzinfo=UTC)
DEADLINE = CREATED + 90 * DAY



def make_facts(
    last_extension_at: datetime | None = None,
    last_reminder_at: datetime | None = None,
    moved_deadline: datetime | None = None,
    owner_email_known: bool = True,
) -> NamespaceFacts:
    return NamespaceFacts(
        name="alice",
        created_at=CREATED,
        last_extension_at=last_extension_at,
        last_reminder_at=last_reminder_at,
        moved_deadline=moved_deadline,
        owner_email_known=owner_email_known,
        suspended=False,
    )


ALL_REMINDERS_SENT = DEADLINE - 1 * DAY


class NamespaceExpiryTest(unittest.TestCase):
    def test_old_namespace_gets_full_warning(self) -> None:
        # Deadline long past, but no reminder ever went out.
        now = DEADLINE + 300 * DAY
        decision = decide(make_facts(), SETTINGS, now)
        self.assertEqual(decision.action, Action.SEND_REMINDER)
        self.assertEqual(decision.reminder_days, 30)
        self.assertEqual(decision.deadline, now + 30 * DAY)
        self.assertTrue(decision.moves_deadline)

    def test_missed_reminder_resumes_with_its_full_notice(self) -> None:
        # The 30-day reminder went out on time, the 7-day one is 2 days late.
        first_sent = DEADLINE - 30 * DAY
        now = DEADLINE - 5 * DAY
        reminded = make_facts(last_reminder_at=first_sent)
        decision = decide(reminded, SETTINGS, now)
        self.assertEqual(decision.action, Action.SEND_REMINDER)
        self.assertEqual(decision.reminder_days, 7)
        self.assertEqual(decision.deadline, now + 7 * DAY)
        self.assertTrue(decision.moves_deadline)

        # On the next day, the moved deadline holds and nothing is due.
        moved = make_facts(last_reminder_at=now, moved_deadline=decision.deadline)
        decision = decide(moved, SETTINGS, now + 1 * DAY)
        self.assertEqual(decision.action, Action.NONE)
        self.assertEqual(decision.deadline, now + 7 * DAY)

    def test_extension_moves_deadline_and_resets_reminders(self) -> None:
        # Reminded for the old deadline, then extended.
        now = DEADLINE - 1 * DAY
        extended = make_facts(last_reminder_at=now, last_extension_at=now)
        decision = decide(extended, SETTINGS, now)
        self.assertEqual(decision.action, Action.NONE)
        self.assertEqual(decision.deadline, now + 90 * DAY)

    def test_expired_namespace_is_suspended_before_deletion(self) -> None:
        reminded = make_facts(last_reminder_at=ALL_REMINDERS_SENT)
        decision = decide(reminded, SETTINGS, DEADLINE + 30 * DAY)
        self.assertEqual(decision.action, Action.SUSPEND)

    def test_due_action_without_email_needs_admin(self) -> None:
        no_email = make_facts(owner_email_known=False)
        decision = decide(no_email, SETTINGS, DEADLINE - 30 * DAY)
        self.assertEqual(decision.action, Action.ADMIN_REVIEW)


if __name__ == "__main__":
    unittest.main()
