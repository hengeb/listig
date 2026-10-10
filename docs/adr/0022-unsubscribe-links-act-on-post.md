# ADR-0022: Unsubscribe links change nothing on GET

Status: Accepted

## Context

The unsubscribe link of every mail (`/{listname}/unsubscribe?token=…`, in the footer and in the `List-Unsubscribe` header) removed the member as soon as it was fetched with GET. Link scanners, mail-client previews and security gateways fetch every URL in a mail with GET, so they could unsubscribe members who never clicked. The mails also announced `List-Unsubscribe-Post: List-Unsubscribe=One-Click` (RFC 8058) although the route only knew GET: one-click clients (Gmail, Apple Mail) POST to the URL and got an error.

## Decision

- `GET /{listname}/unsubscribe?token=…` only shows a confirmation page ("Unsubscribe from <list>?" with a button). `POST` to the same URL does the work. The POST is what the confirmation form sends **and** what an RFC 8058 one-click client sends, so the advertised header now works. The token stays the only credential (no session, no CSRF token needed: it cannot be forged).
- The logged-in "Unsubscribe" button of the web UI no longer uses the token link at all: it is a session POST (`POST /_/api/leave/{listname}`, CSRF-protected, like "Join"), with a `confirm()` dialog except where the member could join again with one click (open + public list).
- Both ways go through `ListLeaver`, so `allow-leave`, the "store cannot remove" answer and the owners' notice behave identically.

## Alternatives considered

- **Keep GET acting and detect scanners** (User-Agent, double-click delay): unreliable, and a false negative silently removes a member.
- **One-click only via POST, GET still acting for browsers:** is exactly the hole.
- **Confirmation page also for the UI button:** an extra page for a logged-in user who already confirmed in the browser dialog.

## Consequences

Clicking the footer link needs one more click. A mail client that offers its own "Unsubscribe" button now works. Old links in mails already sent keep working (same URL, the page just asks first).
