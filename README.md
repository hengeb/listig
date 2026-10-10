# Listig

[![CI](https://github.com/hengeb/listig/actions/workflows/ci.yml/badge.svg)](https://github.com/hengeb/listig/actions/workflows/ci.yml)

Listig is a self-hosted mailing list and newsletter manager written in PHP 8.5. It reads each list's mail from an ordinary IMAP mailbox and sends through that mailbox's SMTP account, so it needs no hook into your mail server (no aliases, no LMTP pipe). Posting, moderating and unsubscribing work by e-mail; a small web UI gives members and list owners an overview.

It is meant for Docker setups and has been tested with Mailu (mail server), Traefik (reverse proxy), Authelia (OpenID Connect), MariaDB and OpenLDAP.

## Why Listig

- **Mail first.** A held mail is accepted or rejected by replying to the moderation notice, or from the web UI. The UI shows subscriptions, the moderation and delivery queues, bounces and the archive. Lists are configured in `config.yml`, LDAP or a database, not in the UI.
- **Discussion lists and newsletters in one tool.** Posting rights are set per sender class (`allow`, `deny`, `moderate`); owners can always post, and `senders:` adds posters who are not members. `reply-to: nobody` and `personalize` (placeholders such as `{firstname}` taken from member attributes) cover the newsletter case. Every recipient gets an individual mail with a one-click `List-Unsubscribe`. There is no campaign editor, template system or tracking, and subscribing from outside goes through the [List Management API](docs/architecture/api.md), not a ready-made form.
- **No MTA setup.** One mailbox per list is enough (see [Requirements](#requirements)). Unlike list servers that are wired into the MTA, Listig only talks IMAP and SMTP.
- **Members from where you already have them:** LDAP, database, CSV or YAML, combinable. Login by magic link or OpenID Connect.
- **Archive** with a threaded view and access levels from `owners` to `public`. HTML mail is sanitized and shown in a sandboxed frame; attachments are available, external images only on request.
- **Bounces.** Every recipient gets a signed VERP envelope address, so a bounce is matched to exactly one recipient. Automatic actions (`bounce-action`: `mark-invalid`, `restrict`, `remove`) are off by default and only act on bounces from an authenticated origin.
- **No backscatter.** Reject and "awaiting approval" notices go only to senders whose mail the receiving server reports as DMARC-aligned authenticated (`Authentication-Results`), by default at most one per address and hour, and never for spam or SPF/DKIM failures.
- **Forged senders.** `post-access-unauthenticated: moderate` (or `deny`) holds back posts whose From address the receiving server could not verify, so a forged member address on a domain without DMARC enforcement is not distributed to everybody.
- **Your layout.** A `custom.latte` can add markup or replace the header on every page. The interface is available in German and English.
- **Also:** masked reply addresses (`reply-to: masked-*`) that relay replies without exposing the address, a global spam filter (`filters:`) and per-sender rate limiting.

## Requirements

- Docker and Docker Compose; MariaDB runs as a separate container (included in the example compose file).
- One mailbox per list with IMAP and SMTP access. The mailbox must also accept `+tag` addresses (`list+accept-…@`, `list+bounce+…@`, `list+r-…@`), which Listig uses for moderation, bounces and masked replies, and deliver them to the same inbox.
- For sender notices: the receiving mail server must add an `Authentication-Results` header to every mail. Without it, no sender counts as authenticated and no notice is sent. If the mailbox is at a third-party provider, also set `trusted-authserv-id` ([per-list keys](docs/reference/list-config-keys.md)).

## Quick start

Requires only Docker and Docker Compose — no repo checkout, no separate migration step. Grab the three example files, fill them in, and start:

```bash
mkdir listig && cd listig
curl -O https://raw.githubusercontent.com/hengeb/listig/main/deploy/compose.yml.example
curl -O https://raw.githubusercontent.com/hengeb/listig/main/deploy/.env.example
curl -O https://raw.githubusercontent.com/hengeb/listig/main/deploy/config.yml.example

cp compose.yml.example compose.yml
cp .env.example .env
cp config.yml.example config.yml
# edit compose.yml/.env/config.yml to match your setup (mail server, database, list provider, ...)

docker compose up -d
```

The web UI listens on port 80 of the host; in production, put it behind your reverse proxy. Database tables are created and kept up to date automatically on container start (see [Database migrations](docs/reference/database-schema.md#database-migrations)).

### Running as a single container

For a standalone container without docker-compose (only MariaDB stays external):

```bash
docker run -d -p 8080:80 --env-file .env -v $(pwd)/config.yml:/app/config/config.yml:ro ghcr.io/hengeb/listig:latest
```

## Configuration

All configuration lives in `config.yml` (start from [`deploy/config.yml.example`](deploy/config.yml.example)) plus a small set of secrets in `.env` (start from [`deploy/.env.example`](deploy/.env.example)): database credentials, mail server credentials, and `APP_SECRET`, the root key from which the per-purpose keys (password encryption, token signing) are derived. Set `hostname` explicitly; every generated link depends on it.

- [`config.yml` reference](docs/reference/config-yml.md) and [per-list keys](docs/reference/list-config-keys.md)
- [List providers and members](docs/architecture/providers-and-members.md): LDAP ([structure](docs/reference/ldap.md)), database and CSV ([layouts](docs/reference/member-stores.md)), inline YAML, subaddress lists
- [Configuration semantics](docs/architecture/config.md): merging, `use:` blocks, `!include`, `$VAR`

## Documentation

Everything else lives under [`docs/`](docs/README.md):

- **Architecture:** [mail processing](docs/architecture/mail-processing.md), [worker and queue](docs/architecture/worker-and-queue.md), [bounces](docs/architecture/bounces.md), [moderation](docs/architecture/moderation.md), [archive](docs/architecture/archive.md), [masked replies](docs/architecture/masked-replies.md), [web UI](docs/architecture/web-ui.md), [List Management API](docs/architecture/api.md), [security, keys and tokens](docs/architecture/security-and-tokens.md), [deployment](docs/architecture/deployment.md)
- **Reference:** [routes](docs/reference/routes.md), [database schema](docs/reference/database-schema.md), [environment variables](docs/reference/environment.md), [project structure](docs/reference/project-structure.md)
- **Decisions:** [architecture decision records](docs/adr/README.md)

## Development

Working from a repo checkout instead of the published image:

```bash
cp deploy/.env.example .env
cp deploy/config.yml.example config/config.yml
docker compose -f docker/compose.yaml up -d --build
```

The web UI is then on `http://localhost:8080`. `make help` lists the available targets (start/stop, logs, shell, rebuild, ...).

```bash
composer install     # add --ignore-platform-req=ext-imap --ignore-platform-req=ext-ldap if those extensions are not installed locally
composer test        # PHPUnit
composer stan        # PHPStan
```

The PHPUnit suite covers the pure-logic layer only (config, variables, filters, tokens, bounce classification, ...); anything that needs a real IMAP, LDAP, SMTP or database connection is verified on a running container. CI runs both checks and publishes the image only if they pass. Details: [Testing](docs/architecture/testing.md).

## License

MIT — see [`LICENSE`](LICENSE).
