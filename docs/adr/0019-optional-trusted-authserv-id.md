# ADR-0019: Optional `trusted-authserv-id` to pin the trusted Authentication-Results

Status: Accepted. Supersedes the "`trusted-authserv-id` allow-list … dropped" alternative of [ADR-0018](0018-sender-notices-only-to-authenticated-senders.md).

## Context

ADR-0018 believes only the topmost `Authentication-Results` header, assuming the receiving MTA prepends its own to every mail, and dropped an authserv-id allow-list because a mandatory key would silently make every installation without it "unauthenticated". The assumption does not hold everywhere: a Listig mailbox may live at any IMAP provider whose MTA the operator does not control. If that MTA adds no header, or not to every mail, a sender-supplied header becomes the topmost one and is believed — by the sender authentication behind notices (`SenderAuthenticator`), the SPF/DKIM reject and `BounceHandler::isDkimAuthenticated()`.

## Decision

An **optional** per-list key `trusted-authserv-id` (a string, comma/space separated, or a YAML list; normal override chain global → provider → list, not additive; `""` = unset):

- **Unset (default):** unchanged — the topmost header counts. No installation is worse off than before.
- **Set:** only headers whose RFC 8601 authserv-id equals one of the values (exact, case-insensitive, version after the id ignored) count; all others are treated as absent, whatever their position. No matching header → the mail is unauthenticated.
- Several matching headers (opendkim and an SPF filter writing separate headers under the same id) are **merged**, topmost first. Per method the first result wins (so a `fail` in the topmost matching header decides the SPF/DKIM reject), while authentication needs just one aligned `pass` anywhere in them (a broken extra DKIM signature must not veto, as in DMARC).
- The selection lives in `HeaderFilter::parseAuthResults()`; all three consumers pass `$list->trustedAuthservIds` and get it for free.
- Log hints: once per worker start and list at `info` when unset (`Logger::info()`), and — together with the existing hourly warning for a missing header — the authserv-ids actually found when the key is set but nothing matches.

## Alternatives considered

- **Make the key mandatory.** Rejected for the reason in ADR-0018.
- **Only the topmost matching header.** Rejected: loses results when SPF and DKIM are written separately.
- **Wildcards / subdomain matching.** Not needed; the id is the exact name the operator reads from a received mail.
- **Config-free plausibility check** (position relative to `Received`, or the id equal to the topmost `Received … by` host). Rejected: providers differ (Gmail inserts the header *below* some of its own `Received` headers; the `by` host is often an internal name unlike the id), so legitimate setups would silently become unauthenticated.

## Consequences

Operators with a mailbox at a third-party provider, or any doubt that the MTA always adds a header, should set the key. It is only as strong as the MTA's duty to remove incoming headers carrying its own id (RFC 8601 §5); without that a sender can still copy the id. A wrong value makes all senders unauthenticated — the log hint with the found ids is there for that.
