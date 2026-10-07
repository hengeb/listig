# ADR-0013: Make the six scoped config keys purely additive across levels

Status: Accepted

## Context

`members:`, `owners:`, `member-resolver:`, `owner-resolver:`, `senders:` and `restricted-members:` can be set globally, per provider and per list. Originally a list's inline `members:`/`owners:` *replaced* what `member-resolver:` produced for it.

Background (moved from the former CLAUDE.md, wording preserved):

> This is a **deliberate behavior change from an earlier version of this codebase**: a list's own inline `members:`/`owners:` used to *replace* what `member-resolver:` produced for that list (`InlineMemberResolver`'s old fallback-chain design). That exclusivity is gone — **every level, including list level, is now purely additive**. A list that previously used its own inline `members:` specifically to override its `member-resolver:` now gets the *union* of both instead; if that's not wanted, remove the `member-resolver:`/`owner-resolver:` (or the relevant global/provider-level entries) rather than relying on the list-level entry to exclude them.

Background (moved from the former CLAUDE.md, wording preserved):

> This was a real gap, not just a hypothetical: before this existed, `owners:` (or any of the other five keys) written inside a `use:`-referenced block — including one loaded via `!include`, e.g. to keep a locally-overridden owner list in a separate, gitignored file — was silently inert. The block's own key content was still parsed and stored (`ConfigResolver::$namedBlocks`), but nothing ever looked inside it for these six keys specifically, since the global/provider "level" was originally read as a single literal value straight off `$config`/`$providerConfig`, never through the `use:`-expansion path ordinary keys go through. Confirmed live: `owners: !include config.local.yml` referenced only via a `use:`-listed block produced zero owners for every affected list until this fix, with no error — the exact kind of silent misconfiguration this codebase otherwise goes out of its way to avoid (compare the `filters:` `{}`-resolution bug under [Variable resolution in filter patterns](../architecture/mail-processing.md#variable-resolution-in-filter-patterns), or the `Auth-Submitted` bounce-detection bug — both similarly silent before being fixed).

## Decision

Every level always adds to the others; there is no replacement semantics. `AbstractListProvider::scopedLevels()` returns all contributing values (global sources, provider sources, list value) as a flat list of independent sources, and each level may itself contribute several sources via `use:` blocks (`ConfigResolver::getGlobalScopedSources()`/`getProviderScopedSources()`).

## Alternatives considered

Keeping list-level override semantics (the previous behaviour).

## Consequences

A list that relied on its own inline `members:` to override its `member-resolver:` now gets the union; remove the unwanted source instead. Behaviour change documented in [Global / provider / list levels](../architecture/config.md#global--provider--list-levels-members-owners-member-resolver-owner-resolver-senders-restricted-members). `filters:` is deliberately not part of this mechanism.
