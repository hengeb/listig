FROM php:8.5-fpm-bookworm

# Pinned to Debian bookworm (not the "8.5-fpm" default tag, which tracks trixie): trixie
# dropped the c-client library entirely, with no replacement package under any name, and
# it is required to build the imap extension for php-imap/php-imap. Bookworm still carries
# it as libc-client2007e-dev (the correct package name — libc-client-dev never existed
# under that name).
#
# ext-imap itself was removed from PHP core in 8.4 (https://wiki.php.net/rfc/deprecate-and-remove-imap-extension),
# so docker-php-ext-install can no longer build it — it must come from the community-maintained
# pecl/imap package instead. "printf '\n\n'" accepts that installer's two interactive prompts
# (Kerberos support, SSL support) at their default of "yes", matching the old
# --with-kerberos --with-imap-ssl configure flags.
RUN apt-get update && apt-get install -y \
    libldap2-dev \
    libonig-dev \
    libc-client2007e-dev \
    libkrb5-dev \
    curl \
    unzip \
    nginx \
    supervisor \
    && printf '\n\n' | pecl install imap \
    && docker-php-ext-enable imap \
    && docker-php-ext-install \
        pdo \
        pdo_mysql \
        ldap \
        mbstring \
    && rm -f /etc/nginx/sites-enabled/default \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Composer
COPY --from=composer:latest /usr/bin/composer /usr/bin/composer

WORKDIR /app

COPY composer.json composer.lock* ./
RUN composer install --no-dev --optimize-autoloader --no-interaction

COPY . .

# Create latte cache directory
RUN mkdir -p /tmp/latte && chmod 777 /tmp/latte

COPY docker/nginx.conf /etc/nginx/conf.d/default.conf
COPY docker/supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY docker/php.ini /usr/local/etc/php/conf.d/99-listig.ini
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 80

# Baked into the image (rather than duplicated in every compose.yaml) so it applies
# regardless of how the container is started — docker run, docker compose, ... —
# see src/Http/Controller and "Health check" in CLAUDE.md for the /_/health route.
HEALTHCHECK --interval=30s --timeout=10s --retries=3 --start-period=10s \
    CMD curl -f http://localhost/_/health || exit 1

# entrypoint.sh runs bin/migrate.php (applies any pending migrations/*.sql, see
# src/Database/MigrationRunner.php) before handing off to CMD — so nginx, php-fpm,
# and the worker never start against a stale schema. supervisord then runs all
# three as managed processes in this one container — see docker/supervisord.conf.
# Only MariaDB stays external.
ENTRYPOINT ["/entrypoint.sh"]
CMD ["supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
