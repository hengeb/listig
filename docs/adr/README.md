# Architecture decision records

Each ADR records a decision that had real alternatives or a deliberate trade-off: the context, the decision, what was rejected and why, and the consequences. Confirmed bug stories that merely led to a rule stay as one sentence next to that rule.

To add one: use the next free number, copy the structure of an existing ADR (Status, Context, Decision, Alternatives considered, Consequences), and link it from the place where the rule lives.

| ADR | Title |
|---|---|
| [0001](0001-verp-bounce-address.md) | Identify a bounced recipient by a signed per-recipient envelope address (VERP) |
| [0002](0002-bounce-origin-authentication.md) | Authenticate a bounce by its origin, scaled to the blast radius of the action |
| [0003](0003-forwarded-mailbox-spam-bounces.md) | Do not automate spam bounces for forwarded mailboxes |
| [0004](0004-queue-retention-for-late-bounces.md) | Keep completed queue entries for 30 days |
| [0005](0005-bounce-suppression-table.md) | Store auto-suppressed addresses in a dedicated table |
| [0006](0006-spam-filter-before-bounce-detection.md) | Run the spam filter before bounce detection |
| [0007](0007-null-sender-envelope-via-reflection.md) | Build the null-sender envelope with Reflection |
| [0008](0008-apcu-snapshot-cache-for-archive.md) | Cache archived mail as an APCu snapshot |
| [0009](0009-imap-search-all-for-message-id-lookup.md) | Find archived mail with SEARCH ALL + FETCH OVERVIEW, not SEARCH HEADER |
| [0010](0010-one-directional-archive-sync.md) | Reconcile the archive index in one direction only |
| [0011](0011-imap-connection-reuse-with-liveness-check.md) | Reuse IMAP connections across worker cycles, guarded by a liveness check |
| [0012](0012-nginx-map-access-logging.md) | Log requests through nginx's `map` + `access_log ... if=` |
| [0013](0013-additive-scoped-config-levels.md) | Make the six scoped config keys purely additive across levels |
| [0014](0014-block-credentials-at-resolution-time.md) | Block credential keys at resolution time, not by filtering the context |
| [0015](0015-fully-dynamic-member-attributes.md) | Keep `Member` fully dynamic, with one LDAP exception |
| [0016](0016-compact-signed-tokens.md) | Compact signed tokens |
| [0017](0017-masked-reply-addresses.md) | Masked reply addresses via a single signed Reply-To token |
| [0018](0018-sender-notices-only-to-authenticated-senders.md) | Send sender notices only to authenticated senders |
| [0019](0019-optional-trusted-authserv-id.md) | Optional `trusted-authserv-id` to pin the trusted Authentication-Results |
| [0020](0020-reply-thread-tag.md) | Reply from the archive via a signed `+re-` address tag |
| [0021](0021-join-policy-and-visibility.md) | Remove unauthenticated subscribe; `join-policy` and `visibility` |
| [0022](0022-unsubscribe-links-act-on-post.md) | Unsubscribe links change nothing on GET |
| [0023](0023-shared-mail-bodies-in-the-queue.md) | Store a queued mail's body once, its headers per recipient |
