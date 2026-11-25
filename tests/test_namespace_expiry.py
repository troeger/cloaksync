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

# The 1-day reminder is the last in the schedule. A reminder at this time
# means all reminders went out.
LAST_REMINDER_AT = DEADLINE - 1 * DAY


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


class NamespaceExpiryTest(unittest.TestCase):
    def test_never_reminded_after_deadline_sends_first_reminder_and_moves_deadline(
        self,
    ) -> None:
        """
        Given: a namespace whose deadline passed 300 days ago, and no reminder
               ever went out.
        When: expiry runs.
        Then: the 30-day reminder is sent, and the deadline moves to now + 30 days,
              so the owner gets the full notice before anything happens.
        """
        facts = make_facts()
        now = DEADLINE + 300 * DAY

        decision = decide(facts, SETTINGS, now)

        self.assertEqual(decision.action, Action.SEND_REMINDER)
        self.assertEqual(decision.reminder_days, 30)
        self.assertEqual(decision.deadline, now + 30 * DAY)
        self.assertTrue(decision.moves_deadline)

    def test_late_reminder_is_sent_and_deadline_moves_by_its_full_notice(
        self,
    ) -> None:
        """
        Given: the 30-day reminder went out on time, and the 7-day reminder is
               2 days late.
        When: expiry runs 5 days before the regular deadline.
        Then: the 7-day reminder is sent, and the deadline moves to now + 7 days,
              so the owner still gets 7 full days of notice.
        """
        facts = make_facts(last_reminder_at=DEADLINE - 30 * DAY)
        now = DEADLINE - 5 * DAY

        decision = decide(facts, SETTINGS, now)

        self.assertEqual(decision.action, Action.SEND_REMINDER)
        self.assertEqual(decision.reminder_days, 7)
        self.assertEqual(decision.deadline, now + 7 * DAY)
        self.assertTrue(decision.moves_deadline)

    def test_moved_deadline_holds_on_the_day_after_a_late_reminder(self) -> None:
        """
        Given: a late 7-day reminder went out 5 days before the regular deadline,
               and moved the deadline to 7 days after that send.
        When: expiry runs one day later.
        Then: nothing is due, and the moved deadline stays.
        """
        reminder_sent_at = DEADLINE - 5 * DAY
        moved_deadline = reminder_sent_at + 7 * DAY
        facts = make_facts(
            last_reminder_at=reminder_sent_at, moved_deadline=moved_deadline
        )
        now = reminder_sent_at + 1 * DAY

        decision = decide(facts, SETTINGS, now)

        self.assertEqual(decision.action, Action.NONE)
        self.assertEqual(decision.deadline, moved_deadline)

    def test_extension_moves_deadline_and_resets_reminders(self) -> None:
        """
        Given: all reminders for the old deadline went out, and the owner
               extended the namespace at the same time.
        When: expiry runs on that day.
        Then: nothing is due, and the deadline is now + 90 days. The reminders
              for the old deadline do not count for the new one.
        """
        now = DEADLINE - 1 * DAY
        facts = make_facts(last_reminder_at=now, last_extension_at=now)

        decision = decide(facts, SETTINGS, now)

        self.assertEqual(decision.action, Action.NONE)
        self.assertEqual(decision.deadline, now + 90 * DAY)

    def test_expired_namespace_is_suspended_before_deletion(self) -> None:
        """
        Given: all reminders went out, and the namespace is not suspended.
        When: expiry runs 30 days after the deadline, which is also after the
              suspension period.
        Then: the namespace is suspended, not deleted. It must be suspended
              before it can be deleted.
        """
        facts = make_facts(last_reminder_at=LAST_REMINDER_AT)
        now = DEADLINE + 30 * DAY

        decision = decide(facts, SETTINGS, now)

        self.assertEqual(decision.action, Action.SUSPEND)

    def test_due_reminder_without_owner_email_needs_admin_review(self) -> None:
        """
        Given: the owner has no known email address.
        When: expiry runs when the 30-day reminder is due.
        Then: an admin review is requested, because nobody can be warned by mail.
        """
        facts = make_facts(owner_email_known=False)
        now = DEADLINE - 30 * DAY

        decision = decide(facts, SETTINGS, now)

        self.assertEqual(decision.action, Action.ADMIN_REVIEW)


if __name__ == "__main__":
    unittest.main()
