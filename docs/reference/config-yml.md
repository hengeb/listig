# config.yml reference

Annotated example of `config.yml` and the OIDC keys. Semantics are in [Configuration semantics](../architecture/config.md).

## config.yml Structure

```yaml
# The root of config.yml is the default configuration, applied to every list. A root
# key is either:
# - 'use:' (see below), 'list-providers:', or 'filters:' — handled specially, always
#   applied, exactly as documented for each elsewhere in this file.
# - a scalar value (string/number/bool) — a direct default key-value, applied to
#   every list unconditionally.
# - a map value — a *named block*, inert unless referenced via 'use:' (here, or in a
#   list-provider's own 'use:'). Named blocks themselves may NOT contain 'use:'
#   (prevents cycles).
# $VAR syntax substitutes environment variables at parse time (before lazy resolution).
# Missing environment variables cause a hard error at startup.
# Direct root key-values take priority over values pulled in via 'use:'.
# Within 'use:', later entries override earlier ones.
# 'use:' also accepts a bare string instead of a YAML list — a single block name
# (use: mail-config), or several separated by commas/whitespace
# (use: mail-config, list-defaults) — normalized into a list the same way
# personalize:/reserved-subaddresses: are (see ConfigResolver::normalizeUse()).
# This applies at both places 'use:' is read: the config.yml root (below) and a
# list-provider's own 'use:' (see "list-providers" (docs/architecture/config.md) below) — not inside a named
# block, which may not contain its own 'use:' at all (prevents cycles).
language: de                        # 'de' | 'en' — global default, code-default is 'en' (see Internationalization)
use:
  - mail-config
  - list-defaults
  - database

# Named block — referenced via 'use:' above
mail-config:
  # mail-host sets both imap-host and smtp-host unless overridden individually —
  # shown here as two separate hosts instead, since IMAP/SMTP are often split
  # across different servers; use mail-host if yours is the same for both.
  imap-host: $IMAP_HOST
  imap-port: 993                      # default: 993
  imap-secure: ssl                    # ssl | tls | none (default: 'ssl' if imap-port is 993, else 'tls')
  smtp-host: $SMTP_HOST
  smtp-port: 587                      # default: 587
  smtp-secure: tls                    # ssl | tls | none (default: 'ssl' if smtp-port is 465, else 'tls')
  # mail-user sets both imap-user and smtp-user unless overridden individually
  # mail-password sets both imap-password and smtp-password unless overridden
  mail-user: "{list-mail}"             # lazily resolved to list mail address per list
  mail-password: $MAIL_PASSWORD       # from environment variable

# Named block — referenced via 'use:' above
list-defaults:
  reply-to: sender
  allow-leave: direct
  list-label: "[{display-name}]"
  footer: "<p>Diese Mail wurde über die Liste {display-name} verschickt. <a href=\"{list-url}\">Zur Liste</a></p>"

# Named block — referenced via 'use:' above. Database connection, used by
# DatabaseConnectionFactory for all DB-backed providers. Keys are db-host, db-port,
# db-name, db-user, db-password (note: db-password, not db-pass).
database:
  db-host: $DB_HOST
  db-port: $DB_PORT
  db-name: $DB_NAME
  db-user: $DB_USER
  db-password: $DB_PASS

list-providers:
  # A map keyed by provider name (not an array) — the name identifies the provider
  # in logs/error messages, and doubles as its 'type' if the provider sets none of
  # its own; see "list-providers — provider name as implicit type" (docs/architecture/config.md) below.
  staff:
    # type: ldap — reads lists from LDAP mailGroup objects; uses LdapMemberResolver internally
    type: ldap
    ldap-host: ldap://ldap.example.org
    ldap-base-dn: dc=example,dc=org
    ldap-bind-dn: cn=admin,dc=example,dc=org
    ldap-bind-password: $LDAP_BIND_PASSWORD
    ldap-list-dn: ou=lists,dc=example,dc=org
    ldap-filter: "(objectClass=mailGroup)"    # default: (objectClass=mailGroup)
    # Optional: DN of a placeholder entry (a user without a mail address) kept in `member` while a list
    # would otherwise have none — for schemas that demand at least one member. See docs/reference/ldap.md.
    # ldap-empty-group-member: uid=nobody,ou=users,dc=example,dc=org
    use:
      - my-mail-config
    reply-to: list

  # type: inline — lists defined directly in config.yml
  # members/owners can each independently be inline (overrides member-resolver
  # for that field only) or come from member-resolver; if neither is defined,
  # list has no members (no error)
  # `lists:` is a map keyed by list name (not an array with a `name:` field).
  # `list-mail` is the list's own mail address — see "list-mail" (docs/architecture/config.md) below.
  manual:
    type: inline
    list-mail: "{list-name}@example.org"   # provider-level default; per-list override wins
    member-resolver:
      type: database
      members-table: list_members   # SELECT * FROM {members-table} WHERE name = :name — any non-reserved column becomes an attribute
    lists:
      mylist:
        # list-mail resolves to mylist@example.org via the provider-level default above
        # members AND owners from member-resolver (database)
      otherlist:
        list-mail: other@example.org   # explicit per-list override
        members:                    # inline members override member-resolver for this list.
                                     # each entry is either a plain "mail@example.org" string,
                                     # or a map with mail/firstname/lastname/username.
          - alice@example.org
          - firstname: Bob
            lastname: Miller
            mail: bob@example.org
        owners:
          - mail: carol@example.org
      thirdlist:
        owners:                     # inline owners, but members still come from member-resolver
                                     # (database) since "members" is not set here at all
          - mail: dave@example.org

  # type: database — reads list names and config from MariaDB
  # config-table structure: (name VARCHAR, key VARCHAR, value TEXT)
  # lists-query: SELECT DISTINCT name FROM {config-table}
  # config-query: SELECT key, value FROM {config-table} WHERE name = :name
  db:
    type: database
    config-table: list_config
    member-resolver:
      type: ldap
      ldap-host: ldap://ldap.example.org
      ldap-base-dn: dc=example,dc=org
      ldap-bind-dn: cn=admin,dc=example,dc=org
      ldap-bind-password: $LDAP_BIND_PASSWORD
      ldap-list-dn: ou=lists,dc=example,dc=org

  # type: subaddress — subaddress-based forwarding, see "type: subaddress — subaddress forwarding" (docs/architecture/providers-and-members.md)
  fwd:
    type: subaddress
    lists:
      fwd:
        list-mail: fwd@example.org
        members:
          - mail: "{subaddress}@intranet.com"   # template, resolved per incoming mail
        owners:
          - mail: admin@example.org
        post-access-members: deny               # owners-only: no key of their own needed, they always post
        post-access-public: deny
        reserved-subaddresses: admin,root       # optional, in addition to built-in bounce/accept-/reject-
```

## OIDC login (`oidc-*`)

Root-level `config.yml` keys, like `hostname`/`language`/`db-*` — not per-list, since the login flow itself has no list in scope until after a member is found (see `AggregateMemberResolver::findListAndMemberByEmail()`, [Authentication (OIDC)](../architecture/web-ui.md#authentication-oidc)). Entirely optional: OIDC login is only enabled — `GET /_/login/oidc` registered at all, the "Log in with Single Sign-On" button shown on the login form — when `oidc-provider-url`, `oidc-client-id`, and `oidc-client-secret` are **all** set (`'oidc.enabled'` in `config/container.php`); otherwise the route doesn't exist (`404`), same 404-if-unconfigured philosophy as the List Management API's `api-token` gate.

```yaml
oidc-provider-url: https://sso.example.org   # discovery-capable issuer — /.well-known/openid-configuration is fetched from here
oidc-client-id: listig
oidc-client-secret: $OIDC_CLIENT_SECRET

# Only needed if oidc-provider-url isn't the IdP's own public address — e.g. an
# internal Docker Compose service name/URL — and the IdP (like Authelia) derives
# and validates its issuer strictly from the request's Host header. See
# OpenIdConnectService's docblock for the full mechanism.
oidc-public-provider-url: https://sso.example.org

# Optional: only needed if the IdP has no standard, spec-compliant
# end_session_endpoint in its discovery document (RP-initiated logout is
# discovered automatically otherwise — no config needed). Used verbatim, as the
# full redirect target — Listig appends no query parameters of its own, since a
# non-standard logout endpoint (e.g. Authelia's own) may expect entirely
# different ones than the OIDC-spec id_token_hint/post_logout_redirect_uri.
oidc-logout-url: "https://sso.example.org/logout?rd=https%3A%2F%2Flists.example.org%2F_%2Flogin"
```

- Discovery-only: no separate authorization/token/userinfo endpoint keys — `jumbojett/openid-connect-php` fetches them all from `oidc-provider-url`'s `/.well-known/openid-configuration`.
- Authorization Code flow with PKCE (`S256`), scopes `openid profile email`.
- All five keys are in `VariableResolver::BLOCKED_KEYS` (see [Blocked variables](../architecture/variables.md#blocked-variables)) — same treatment as `ldap-host`/`ldap-bind-dn`/`ldap-bind-password`, resolved under `ResolutionPurpose::Trusted` only at the one point they're actually consumed (`OpenIdConnectService::class` in `config/container.php`).
- `oidc-public-provider-url` is used two ways in `OpenIdConnectService`: its host is spoofed into the `Host`/`X-Forwarded-Proto` headers of every backend→IdP request (so the IdP's discovery document — and the ID token's `iss` claim — reflect the public identity, not the internal address this backend actually connects to), and the token/jwks/userinfo endpoints discovery returns (now necessarily public-host-based too) are rewritten back onto `oidc-provider-url`, since only `authorization_endpoint` is ever browser-facing.
- `oidc-logout-url` — see [Authentication (OIDC)](../architecture/web-ui.md#authentication-oidc) for the full logout flow (`OpenIdConnectService::getLogoutUrl()`, `AuthController::logout()`).
