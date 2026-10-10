# ADR-0018: Send sender notices only to authenticated senders

Status: Accepted. The authserv-id allow-list rejected below was later added as an optional key — see [ADR-0019](0019-optional-trusted-authserv-id.md).

## Context

Listig reads mail over IMAP that the upstream MTA has already accepted, so a rejection caused by list rules (access, size, rate limit, moderation, spam, SPF/DKIM) can only be reported afterwards, as a new mail. Sent to a forged `From`, that notice — null envelope, original attached as `message/rfc822` — is backscatter: it hits uninvolved third parties, redistributes spam, and endangers the server's reputation (backscatter blocklists). The worst cases were the SPF/DKIM-fail reject and `filters:` rejects, where the From address is forged with high probability.

The notice goes to the `From` address, not the envelope sender / `Return-Path`: the envelope often points to a forwarding service or the VERP address of another list, so `From` is the only address that identifies who wrote the mail. That stays.

Separately, `HeaderFilter::readAuthResults()` used to read the first `Authentication-Results` header it found, whoever wrote it. A header supplied by the sender could therefore claim `dkim=pass`.

## Decision

All decisions about notifying a sender are made in `SenderNoticePolicy::decide()` (used by `RejectionNotifier` and `ModerationMailer`'s pending notice); no caller decides on its own:

- **Authenticated** means DMARC-aligned (`SenderAuthenticator`): `dmarc=pass`, or `dkim=pass` with `header.d` aligned to the From domain, or `spf=pass` with `smtp.mailfrom` aligned to it. Alignment is relaxed (same organizational domain, `OrganizationalDomain`). Also `auth=pass` (SMTP AUTH at the receiving server — the only thing it writes for a mail submitted through it, e.g. from a local Mailu mailbox, where it evaluates no SPF/DKIM/DMARC) with an `smtp.mailfrom` aligned to the From domain.
- `sender-notices: authenticated` (default) notifies only authenticated senders, `always` everyone (original attached only if authenticated), `never` nobody. `reject.auth_failed` and `reject.spam` are **never** notified, in any mode.
- At most one notice per address and `sender-notice-interval` (default 1 hour, max 1 day), across all lists, via `rate_limit` (`__notice__`). Suppressed notices do not use up the quota.
- Without the original, the notice names only subject and date. `reject.size_exceeded` never attaches the original.
- Only the topmost `Authentication-Results` header is read — the own MTA prepends its header to every mail it accepts, so it is the own server's verdict and a sender-supplied header can only sit below it. A mail without the header counts as unauthenticated. This also applies to the SPF/DKIM reject and `BounceHandler::isDkimAuthenticated()`.
- Every suppression is logged (`error_log`, reason, list, sender *domain*, Message-ID). Owners get no UI for it.
- Notices to owners (moderation requests, bounce forwards, failures) are unchanged — owners are known.

## Alternatives considered

- **Address the notice to the envelope sender.** Rejected: unreliable (forwarders, VERP), and forgeable just the same.
- **Never notify.** Safe but takes away the feedback real senders rely on; moderation looks like a vanished mail.
- **Exempt known members.** Rejected: a member's address is as forgeable as any other, and member addresses are visible to other members.
- **Evaluate SPF/DKIM in Listig.** Rejected: needs the connecting IP and a DNS resolver, and duplicates the MTA's work. Listig talks to the MTA only via IMAP/SMTP; no MTA setup (policy daemon, milter) is required — only that the MTA writes `Authentication-Results`, which Dovecot/Postfix setups with opendkim, rspamd or similar already do.
- **Reject during the SMTP session (Postfix `check_policy_service`).** The only fully backscatter-free way, but contradicts "no MTA setup"; possible later as an optional add-on.
- **Public Suffix List for the organizational domain.** Correct but a new dependency plus list updates; replaced by a built-in table of common multi-label suffixes. The residual risk is an unlisted suffix making alignment too generous for domains below it; it is bounded because a passing verdict from the own MTA is still required.
- **A `trusted-authserv-id` allow-list.** Implemented first, then dropped: with an MTA that always adds its header, the topmost header is already the trusted one, and the extra key only added configuration (and made every installation without it silently unauthenticated).

## Consequences

Members whose domain has neither aligned DKIM nor SPF no longer receive notices (`sender-notices: always` restores them, without the original). The MTA must add `Authentication-Results` to every mail it accepts; if it ever does not, a sender-supplied header becomes the topmost one and is believed. A configurable authserv-id allow-list was considered and dropped as unnecessary under that guarantee. `rate_limit` rows are now kept one day.
