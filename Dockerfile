FROM alpine:3.18
LABEL Maintainer="Henrik Gebauer <code@henrik-gebauer.de>" \
      Description="mail forwarder"

COPY --from=composer /usr/bin/composer /usr/bin/composer

WORKDIR /usr/src/app
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]

COPY config/supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY config/php.ini /etc/php82/conf.d/custom.ini

RUN set -ex \
  && apk add --no-cache \
    curl \
    php82 \
    php82-ldap `# needed by symfony/ldap` \
    php82-phar `# needed by composer` \
    php82-mbstring `# needed by composer` \
    php82-openssl `# needed by phpimap/phpimap` \
    php82-imap `# needed by phpimap/phpimap` \
    php82-iconv `# needed by phpimap/phpimap` \
    php82-fileinfo `# needed by phpimap/phpimap` \
    supervisor \
  && true

RUN set -ex \
  && chown -R nobody:nobody . /run \
  && ln -s /usr/bin/php82 /usr/bin/php \
  && true

COPY --chown=nobody ./app .

RUN set -ex \
  && chmod u+x loop.sh \
  && composer install --optimize-autoloader --no-dev --no-interaction --no-progress --no-cache \
  && true

USER nobody
