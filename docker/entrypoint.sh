#!/bin/sh
set -e

# Applies any pending migrations/*.sql (tracked in schema_migrations) before nginx,
# php-fpm, or the worker start — see bin/migrate.php and CLAUDE.md "Database migrations".
# A failure here aborts the container instead of starting against a stale schema.
php /app/bin/migrate.php

exec "$@"
