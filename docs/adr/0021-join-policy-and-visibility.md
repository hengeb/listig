# ADR-0021: Remove unauthenticated subscribe; `join-policy` and `visibility`

Status: Accepted

## Context

`public-subscribe: on` let anyone `POST /{listname}/subscribe` without credentials; Listig then mailed a confirmation link to the given address. Its rate limit is per (list, address), so it does not limit the number of *different* addresses: the endpoint is a mail relay for strangers' addresses (mail bombing, spam complaints against the list's domain). Its only legitimate use — a signup form on another website — can call the endpoint from its own server with the list's Bearer token and its own captcha. A logged-in user, meanwhile, had no way to join a list from the web UI, and which lists a user sees was hard-wired: only their own, plus a world-readable info page for any list name.

## Decision

- **`public-subscribe` and the unauthenticated path are removed.** `POST /{listname}/subscribe` (double opt-in mail) needs the Bearer token, via `ApiTokenMiddleware`. No migration message for old configs: an unknown key is simply ignored.
- **`join-policy: open | invite | request`** (default `invite`). Only `open` is implemented: an authenticated user who can see the list gets a "Join" button; the click adds them immediately (`JoinController`, CSRF-protected). The address is confirmed by the login, so no confirmation mail. `invite` and `request` are displayed in the list info only. Guests never get a join option.
- **`visibility: public | members | hidden`** (default `members`) decides who sees the list in the dashboard and on `/{listname}` (404 otherwise): every authenticated user / members and owners / owners only. Owners always see their lists.
- `MemberResolver::supportsAddition()` (like `supportsRemoval()`) lets the UI offer "Join" only where the store can take members.

## Alternatives considered

- **Keep `public-subscribe`, tighten the limit.** A global limit would just make it a DoS lever on legitimate signups; any per-address limit leaves relaying to many addresses open.
- **Captcha in Listig.** A new dependency and third-party calls for something the integrating website can do itself.
- **Join by confirmation mail.** Needless for a logged-in user (address already verified), and costs a mail per click.
- **Default `visibility: public`.** Would list every list to every logged-in user on existing installations until someone sets the key.
- **Also gating the archive by `visibility`.** The archive has its own, finer `archive` setting; coupling them would make one key silently override the other.

## Consequences

Members of a `hidden` list lose the dashboard card and the `{list-url}` page (a footer link that says "unsubscribe here" leads to a 404; the `List-Unsubscribe` header still works). A `join-policy: open` list that is not `visibility: public` can only be joined by someone who can already see it — by design, the two keys are independent. LDAP-backed lists can only take users that already have a directory entry.
