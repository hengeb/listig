# ADR-0015: Keep `Member` fully dynamic, with one LDAP exception

Status: Accepted

## Context

Member data comes from LDAP, databases, CSV files and inline config with different schemas. Hard-coding `firstname`/`lastname`/`pronoun` would force schema changes and code changes together.

Background (moved from the former CLAUDE.md, wording preserved):

> **Why LDAP and not the other three:** this isn't arbitrary — `cn` is a schema-guaranteed field (a required attribute on the person object classes Listig expects), so copying it is reliable. Database/CSV/inline schemas are entirely operator-defined; there is no equivalent field to auto-derive a `username` from the way `cn` provides one for LDAP, so requiring one would mean rejecting any member row that doesn't happen to have a `username` column/key populated — a new, stricter requirement those three never had, for no clear benefit. An operator who wants the same privacy protection for a database/CSV/inline-backed list simply populates a `username` column/key themselves.

## Decision

`Member` has exactly one fixed field, `$email`; everything else is `Member::$attributes`, named by the backing store (`SELECT *` columns, CSV headers, inline keys, LDAP attributes). A list defines its own mapping as ordinary config keys (`pronoun: "{businessCategory}"`). Exception: `LdapMemberResolver` copies `cn` into `username` and `givenName`/`sn` into `firstname`/`lastname` (if not already set).

## Alternatives considered

Requiring a `username` column/key in every backend (a new, stricter requirement for no clear benefit).

## Consequences

Database attribute names are validated as SQL identifiers and backtick-quoted (injection protection). `personalize:` becomes a genuine trust boundary: only whitelist attributes safe for members to see about themselves. Member-derived values are `Literal`-wrapped so they are never re-parsed as templates.
