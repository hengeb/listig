# Listig documentation

[CLAUDE.md](../CLAUDE.md) is the entry point (overview, hard rules, "read this before working on X"). The documents below are read on demand.

## Architecture (`architecture/`)

- [Configuration semantics](architecture/config.md) · [Variables and template resolution](architecture/variables.md) · [List providers and members](architecture/providers-and-members.md)
- [Worker, IMAP and outgoing queue](architecture/worker-and-queue.md) · [Mail processing](architecture/mail-processing.md) · [Bounces](architecture/bounces.md) · [Masked reply addresses](architecture/masked-replies.md) · [Moderation](architecture/moderation.md) · [Archive](architecture/archive.md)
- [Web UI](architecture/web-ui.md) · [List Management API](architecture/api.md) · [Security, keys and tokens](architecture/security-and-tokens.md) · [Internationalization](architecture/i18n.md) · [Logging](architecture/logging.md)
- [Deployment and Docker](architecture/deployment.md) · [Testing](architecture/testing.md)

## Reference (`reference/`)

[config.yml](reference/config-yml.md) · [per-list keys](reference/list-config-keys.md) · [LDAP](reference/ldap.md) · [member/config stores](reference/member-stores.md) · [database schema](reference/database-schema.md) · [routes](reference/routes.md) · [environment variables](reference/environment.md) · [project structure](reference/project-structure.md)

## Other

[Architecture decision records](adr/README.md) · [Library notes](library-notes.md)

## Code comments

Comments in the source code refer to these documents by path and section title, e.g. `see docs/architecture/config.md "Root-level lists:"`. When you rename or move a section, `grep -rn "Section title" src bin config public templates` finds the comments to update.
