# ADR-0005: Store auto-suppressed addresses in a dedicated table

Status: Accepted

## Context

The `restrict` bounce action needs runtime-writable storage for "skip this address at send time". The existing `restricted-members:`/`RestrictionList` mechanism is purely config-derived and rebuilt every cycle by all five `ListProvider` implementations; list membership itself may live in LDAP, a database, a CSV file or inline config, most of which cannot be written at runtime.

## Decision

`bounce_suppressed_members` (`migrations/006`), read and written only through `BounceSuppressionList`, independent of any provider or member backend. `MailProcessor::resolveRecipients()` checks `isSuppressed()` next to `isReceiverRestricted()`. `ListController::manage()` shows a card listing suppressed addresses (only when non-empty) so owners can see why someone stopped receiving mail.

## Alternatives considered

Making `restricted-members:` dynamically writable (would touch all five providers); writing into the list's own `MemberResolver` (impossible for inline/null stores).

## Consequences

No automatic expiry and no UI action to remove an entry (only an operator deleting the row); making `RestrictionList` writable remains a possible follow-up.
