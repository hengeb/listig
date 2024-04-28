FROM alpine:3.19
LABEL Maintainer="Henrik Gebauer <code@henrik-gebauer.de>" \
      Description="mail forwarder"

COPY --from=composer /usr/bin/composer /usr/bin/composer

WORKDIR /usr/src/app
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]

COPY config/supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY config/php.ini /etc/php83/conf.d/custom.ini

RUN set -ex \
  && apk add --no-cache \
    curl \
    php83 \
    php83-ldap `# needed by symfony/ldap` \
    php83-phar `# needed by composer` \
    php83-mbstring `# needed by composer` \
    php83-openssl `# needed by phpimap/phpimap` \
    php83-imap `# needed by phpimap/phpimap` \
    php83-iconv `# needed by phpimap/phpimap` \
    php83-fileinfo `# needed by phpimap/phpimap` \
    supervisor \
  && true

RUN set -ex \
  && chown -R nobody:nobody . /run \
  && ln -s /usr/bin/php83 /usr/bin/php \
  && true

COPY --chown=nobody ./src .

RUN set -ex \
  && chmod u+x loop.sh \
  && composer install --optimize-autoloader --no-dev --no-interaction --no-progress --no-cache \
  && true

USER nobody
