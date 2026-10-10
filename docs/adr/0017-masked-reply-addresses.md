# ADR-0017: Masked reply addresses via a single signed Reply-To token

Status: Accepted

## Context

Two needs: (1) a group sharing one official address (`kontakt@`) must be able to answer from that address, with the reply going to the external sender and being visible to the other members; (2) members' addresses should be protectable from each other. `reply-to: sender`/`both` expose the sender's address, and `both` has a duplicate-delivery problem for members.

## Decision

Two new `ReplyToBehavior` values, `masked-sender` and `masked-both`. `Reply-To` is a single `{localPart}+r-{TOKEN}@{domain}` address; token = `TokenService::sign('p', ListFingerprint::of($list), $replyTargetId)` (no expiry) referencing a `reply_targets` row `(list_cn, kind, target_key)`. A member is stored by `username` (else address) and resolved live, so an address change is followed; an external by address. A reply to a token is filtered like list mail (`checkMaskedReply()`: only member/owner/`senders:`; `post-access-members` only for `masked-both`), then relayed From the list address; `masked-both` additionally distributes to the group server-side. An external target gets a plain copy. `masked-sender` replies are private: deleted from IMAP, never archived. A `mailto:` link issued by a web form (`ComposeController`) covers the first mail to an external address. `sender-address-header` is an opt-in way to show the real sender.

## Alternatives considered

- A separate `shared-inbox` list mode: the three things it would change (Reply-To content, token handling by address, plain external copy) are already `reply-to` behaviour or handler behaviour, so one enum value suffices.
- Two `Reply-To` addresses or headers for `both`: not all mail clients handle them; the group copy is made server-side instead.
- An address-bearing token (`kontakt+e-extern=domain@…`): exceeds the 64-byte limit and cannot follow a member's address change.
- Storing a member's address instead of `username`: goes stale.
- A list of previous contacts in the compose form: would reveal external addresses to members who never dealt with them.
- A `Reply-To` exemption for member senders (as in `both`): unnecessary, because the replier is excluded from the group copy on the server.

## Consequences

- A token leaking beyond its recipient is harmless: using it requires being a member, and the lookup is list-bound.
- Tokens carry no expiry (the DB row decides; unused `external` rows are purged after 180 days), so they stay valid while the member is on the list; the relay works in every `reply-to` mode, and a private relay (anything but `masked-both`) never reaches the group, so a mode change cannot leak a private reply.
- The real sender is invisible to members unless `sender-address-header` or the footer variable `{sender-mail}` is used; document that either exposes the address to every member.
- `ReplyTargetStore` uses a MySQL-specific upsert and is verified live, not in the unit suite.
- `from-address: masked` ([Masked From address](../architecture/masked-replies.md#masked-from-address)) reuses the same token as the sender's From, which is why the token no longer expires.
