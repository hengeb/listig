# Listig

Listig is a self-hosted, Docker-based mailing list manager written in PHP 8.5.

- Polls IMAP mailboxes for incoming mail and distributes it to list members
- Members and list configuration can come from LDAP, a database, CSV, or YAML files
- Moderation, bounce handling, and per-sender/global rate limiting
- A web UI for members (view subscriptions, unsubscribe) and list owners (manage, moderate, view the delivery queue)
- Optional per-list mail archive with `members` / `owners` / `public` / `hidden` / `off` access levels, safely rendered (sanitized HTML, sandboxed, no auto-loaded external images)

## Quick start

Requires Docker and Docker Compose.

```bash
cp .env.example .env
cp config/config.yml.example config/config.yml
# edit both to match your setup (mail server, database, list provider, ...)

docker compose -f docker/compose.yaml up -d
```

The web UI is then reachable at `http://localhost:8080`. See [`Makefile`](Makefile) (`make help`) for common operations, and [`CLAUDE.md`](CLAUDE.md) for the full configuration reference — every `config.yml` key, all list-provider types (LDAP, database, CSV, inline, subaddress), moderation, the archive access levels, and the security model.

### Running as a single container

For a standalone container without docker-compose (only MariaDB stays external):

```bash
docker build -f docker/Dockerfile -t listig .
docker run -d -p 8080:80 --env-file .env -v $(pwd)/config/config.yml:/app/config/config.yml:ro listig
```

## Configuration

All configuration lives in `config/config.yml` (start from `config/config.yml.example`) plus a small set of secrets in `.env` (start from `.env.example`) — database credentials, mail server credentials, and `APP_SECRET`, the root key that per-purpose subkeys (password encryption, token signing) are derived from.

## Development

- `make help` — list available Make targets (start/stop containers, logs, shell, rebuild, ...)
- `docker/compose.yaml` — app (php-fpm + nginx + the worker loop, one image) + MariaDB
- No automated test suite yet — tracked as follow-up work

## License

MIT — see [`LICENSE`](LICENSE).
