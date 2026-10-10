# List providers and members

List providers, member resolvers, `ListConfig`, sender rules and member attributes.

## Configuration Architecture

**Only LDAP-specific classes may interact with LDAP. Only database-specific classes may run SQL.**
All other classes work with `ListConfig` and `Member` objects.

## ListProvider interface

```php
interface ListProvider {
    /** @return ListConfig[] */
    public function getLists(): array;
    public function getList(string $name): ?ListConfig;
    public function setListConfigValue(string $listName, string $key, string $value): void;
    public function reset(): void;
}
```

| Implementation | type | Description |
|---|---|---|
| `LdapListProvider` | `ldap` | Reads `mailGroup` objects from LDAP; uses `LdapMemberResolver` internally; `setListConfigValue()` replaces the matching `description[]` entry |
| `InlineListProvider` | `inline` | Reads lists from config.yml; inline members or configured `MemberResolver`; takes optional `DatabaseConnectionFactory`; `setListConfigValue()` throws (static config) |
| `DatabaseListProvider` | `database` | Reads list names + EAV config from MariaDB via `DatabaseConnectionFactory` using context `db-*` keys; `setListConfigValue()` upserts into `config-table` |
| `YamlListProvider` | `yaml` | Reads lists from a separate YAML file; inline members or configured `MemberResolver`; takes optional `DatabaseConnectionFactory`; `setListConfigValue()` throws (file not rewritten at runtime) |
| `SubaddressListProvider` | `subaddress` | Subaddress forwarding — see [type: subaddress — subaddress forwarding](#type-subaddress--subaddress-forwarding); `members:` are unresolved `{subaddress}` templates, not a `MemberResolver`; `owners:` uses the normal inline mechanism; `setListConfigValue()` throws (static config) |

Every implementation's constructor takes the provider's own name (its key in `list-providers:`, see [list-providers — provider name as implicit type](config.md#list-providers--provider-name-as-implicit-type)) as its first argument, ahead of `ConfigResolver`/`providerConfig`/etc. — used in log/error messages so a failure (LDAP unreachable, a list missing `list-mail`, a YAML file not found, ...) identifies which provider it came from.

`setListConfigValue()` is used by `ListApiController::encryptPassword()` — see [List Management API](api.md#list-management-api). The composite provider in `container.php` delegates to whichever underlying provider actually owns the list; its own `reset()` simply calls `reset()` on every wrapped provider.

**`Provider\AbstractListProvider`** — all five implementations extend this rather than implementing `ListProvider` directly. Before it existed, `getLists()`/`getList()`/`reset()` and the `$lists`/`resolvedProviderConfig()` caching around them were identical, or near-identical, copy-pasted code in every provider; the only thing that ever genuinely differed between them was *how* `$lists` gets populated. `AbstractListProvider` centralizes the shared part and declares that one differing part as `abstract protected function loadLists(): ?array` for each subclass to implement:

- `getLists()`/`getList()`/`reset()` are implemented once, in terms of `loadLists()` and the inherited `protected ?array $lists` cache — `getList()` is `getLists()` then an array lookup, `reset()` sets `$lists = null`. `DatabaseListProvider` is the one subclass that overrides `getList()` — a single targeted row query is cheaper than always loading every list first just to answer one lookup, so the inherited default doesn't fit there.
- `loadLists(): ?array` returns `null`, rather than throwing, for a failure that should be retried on the very next call within the same cycle instead of being cached as "zero lists" — `LdapListProvider` is the one subclass that needs this (an LDAP outage must not look identical to "the directory genuinely has zero lists" for the rest of the worker cycle; see its own `loadLists()`). Every other subclass either succeeds or throws on a hard config/data error (missing YAML file, empty `list-mail`, ...), unchanged from before this class existed.
- `resolvedProviderConfig()` (provider-level `use:`/direct config, no per-list overrides) is also centralized here — cached for the whole process lifetime, *not* reset per cycle like `$lists`, since it's derived purely from `config.yml`'s own structure (only ever changes via a full process restart, see [Worker loop — config reload](worker-and-queue.md#worker-loop--config-reload)).

## ConfigResolver

`ConfigResolver` merges config.yml blocks, resolves `use:`, substitutes `$VAR` from environment, and produces a flat merged key-value map for each list. Variable `{}` resolution does **not** happen here — it is deferred to `VariableResolver` at point of use.

- `resolveListConfig(array $providerConfig, array $listOverrides = []): array` — full per-list merge (levels 1–5)
- `getResolvedDefault(): array` — resolves only levels 1+2 (the config.yml root's direct key-values with its `use:` blocks expanded); used to read global settings like `db-*` credentials for the PDO connection

## DatabaseConnectionFactory

Caches PDO instances per database configuration fingerprint (hash of `db-host`, `db-port`, `db-name`, `db-user`, `db-password`). All DB-backed providers and resolvers call `getConnection(array $config)` with their resolved config — if the fingerprint matches an existing connection, it is reused; otherwise a new PDO is opened and cached.

This means all providers that inherit `db-*` from the same `default` block share one connection. A provider or list that explicitly overrides `db-host` etc. gets its own separate (cached) connection.

`DatabaseListProvider`, `InlineListProvider`, and `YamlListProvider` pass `$configResolver->resolveListConfig($providerConfig)` (provider-level resolved config, no per-list overrides) as the config for their connection. `DatabaseMemberResolver` receives this same config from its parent provider.

```php
interface MemberResolver {
    /** @return Member[] */
    public function getMembers(string $name): array;
    /** @return Member[] */
    public function getOwners(string $name): array;
    public function findByEmail(string $email): ?Member;
    public function removeMember(string $listName, string $email): void;
    public function supportsRemoval(): bool;
    public function addMember(string $listName, Member $member): void;
    public function supportsAddition(): bool;
    public function supportsInvalidation(): bool;
    public function invalidateEmail(string $listName, string $email, string $reason): void;
}
```

`invalidateEmail()`/`supportsInvalidation()` back the `mark-invalid` automatic bounce action (see [Automatic bounce actions](bounces.md#automatic-bounce-actions)) — mirrors `removeMember()`/`supportsRemoval()` exactly. Replaces the member's own address in place with `Member\InvalidatedEmail::build($email, $reason)` rather than deleting the record outright.

| Implementation | type | Description |
|---|---|---|
| `LdapMemberResolver` | `ldap` | Resolves member/owner DNs via LDAP; every directory attribute except `mail` becomes a `Member::$attributes` entry under its own name (plus a `username` = `cn` convenience copy — see [Member attributes — fully dynamic](#member-attributes--fully-dynamic)); `removeMember` removes the DN from the `member` attribute; `supportsRemoval` always `true`; `addMember` adds it — but only if a directory entry matching the email already exists, else throws |
| `DatabaseMemberResolver` | `database` | `SELECT *`s `members-table` via `DatabaseConnectionFactory` + context config, exposing every non-reserved column as an attribute; `removeMember` sets `is_member = 0`, then deletes row if `is_member = 0 AND is_owner = 0`; `supportsRemoval` always `true`; `addMember` upserts dynamically from `Member::$attributes` (validated as SQL identifiers), preserving existing `is_owner` |
| `CsvMemberResolver` | `csv` | Reads/writes a flat CSV file (`name,mail,is_member,is_owner` reserved, any other header column exposed as an attribute), shared across lists like `members-table`; re-reads on every call, writes take an exclusive `flock`; `supportsRemoval` always `true`; `addMember` extends the header for new attribute keys — see [CSV member file format](../reference/member-stores.md#csv-member-file-format) |
| `InlineMemberResolver` | — | A fixed, statically-configured set of members/owners — the "bare inline entry" building block for one level (global/provider/list) of `members:`/`owners:`, or one entry of `member-resolver:`/`owner-resolver:` that isn't a resolver config (see [Global / provider / list levels](config.md#global--provider--list-levels-members-owners-member-resolver-owner-resolver-senders-restricted-members)). Each entry is a plain email string or a map with a required `mail` key plus any other keys, all becoming attributes verbatim. `removeMember` always throws (a request-scoped in-memory removal can never persist — config.yml is never rewritten, and a fresh instance is built from it on every request anyway) and `supportsRemoval` is always `false` — no fallback/override concept anymore; combining an `InlineMemberResolver` with any other source (from any level) is `CompositeMemberResolver`'s job |
| `NullMemberResolver` | — | Returns empty arrays; `removeMember` is a no-op; `supportsRemoval` `false` (no backing store at all); `addMember` throws |
| `AggregateMemberResolver` | — | Searches across all providers; used by `AuthController` to find any list a user belongs to; `supportsRemoval` `false`; `addMember`/mutating calls throw (lookup only) |

`addMember()` is used by `ListApiController` (see [List Management API](api.md#list-management-api)) for both immediate (`PUT`) and double-opt-in-confirmed subscriptions. Callers must treat the `\RuntimeException` as a real error (e.g. HTTP `409`), not swallow it — an LDAP-backed list silently "succeeding" without actually adding a non-existent-directory-entry member would be worse than an explicit failure.

`supportsInvalidation()`/`invalidateEmail()`: `true`/implemented for `LdapMemberResolver` (instance-wide — a directory entry's `mail` isn't scoped per list, see [Automatic bounce actions](bounces.md#automatic-bounce-actions)), `DatabaseMemberResolver`/`CsvMemberResolver` (naturally per-list, since `mail` is its own row per list there); `false`/throws for `InlineMemberResolver`/`NullMemberResolver`/`AggregateMemberResolver`, exactly mirroring their own `supportsRemoval()`/`removeMember()`.

`ListConfig::getMembers()`/`getOwners()` ask the resolver once per `ListConfig` instance and remember the answer (a store such as LDAP re-queries the directory, one lookup per member, on every call, and the permission helpers `isMember()`, `canPost()`, `isVisibleTo()`, ... each ask again); an instance lives for one request or one worker cycle (`ListProvider::reset()` builds new ones), and `addMember()`/`removeMember()`/`invalidateEmail()` drop the memo.

`supportsAddition()` mirrors it for `addMember()` (`ListConfig::$supportsJoin`, gating the "Join" button): `true` for LDAP, database and CSV (LDAP may still throw if the address has no directory entry), `false` for inline, null and aggregate; the composite resolver is `true` if any source is.

`supportsRemoval()` — checked via `ListConfig::$supportsUnsubscribe` (a property hook, like every other derived `ListConfig` value — see [ListConfig with property hooks](#listconfig-with-property-hooks) — not a method, since `MemberResolver::supportsRemoval()` itself is; the interface it belongs to is method-based throughout) — lets a caller find out *before* calling `removeMember()` whether it would actually persist anything, rather than either silently no-op'ing (previously the case for `NullMemberResolver` and static-inline `InlineMemberResolver`, both of which "succeeded" without ever removing anyone) or throwing. `DashboardController` only shows the "Unsubscribe" link when `allowLeave === Direct` *and* `$supportsUnsubscribe`; `UnsubscribeController`'s direct-unsubscribe branch and `ListApiController::unsubscribe()` (`DELETE /{listname}/{mail}`) both check it (or catch the `\RuntimeException`) before claiming success — see [Unsubscribe endpoint](web-ui.md#unsubscribe-endpoint).

`member-resolver`/`owner-resolver` can be configured as a sub-object on `type: inline` and `type: database` providers, with `type: database`, `type: ldap`, or `type: csv` (`{type: csv, file: /path/to/members.csv}`) — and, since `MemberResolverFactory::buildSources()`, as a *list* of such sub-objects (or bare inline entries) too. `type: ldap` (the list provider) always includes `LdapMemberResolver` for every list it produces (`$extraBase` in `MemberResolverFactory::buildComposedResolver()`), independent of any `member-resolver`/`owner-resolver` configured at any level for it — every configured level only ever adds to it, never replaces it.

For `type: inline` and `type: yaml`: `members`/`owners`/`member-resolver`/`owner-resolver` are all independently additive across all three levels (global/provider/list) — see [Global / provider / list levels](config.md#global--provider--list-levels-members-owners-member-resolver-owner-resolver-senders-restricted-members) for the full mechanism and the deliberate behavior change from the old exclusive-override design. A list with none of the six keys set at any level (global, provider, or list) simply gets an empty `CompositeMemberResolver` for that role — no members, no error.

## Member value object

```php
class Member {
    public string $email;               // the only fixed field
    /** @var array<string, string> everything else a resolver knows — see "Member attributes — fully dynamic" (docs/architecture/providers-and-members.md) */
    public array $attributes;
}
```

A key not present in `$attributes` (and not resolvable via any list-level alias
either) resolves to an empty string rather than a literal `{key}` — see
[Variable substitution](variables.md#variable-substitution).

## String-backed Enums

```php
enum ReplyToBehavior: string { case List = 'list'; case Sender = 'sender'; case Both = 'both'; case Nobody = 'nobody'; case MaskedSender = 'masked-sender'; case MaskedBoth = 'masked-both'; }
enum SenderAddressHeader: string { case Never = 'never'; case External = 'external'; case Always = 'always'; }
enum PostAccess: string { case Allow = 'allow'; case Deny = 'deny'; case Moderate = 'moderate'; }
enum AllowLeave: string { case Direct = 'direct'; case Moderated = 'moderated'; }
enum ArchiveMode: string { case Members = 'members'; case Owners = 'owners'; case Public = 'public'; case Hidden = 'hidden'; case Off = 'off'; }
```

## ListConfig with property hooks

```php
class ListConfig {
    public string $name;  // provider-agnostic identifier (LDAP: cn); constructor throws if this is "_" (reserved for /_/... system routes) or contains anything outside [A-Za-z0-9_-] — see "Routes" (docs/reference/routes.md)
    public string $mail;
    private array $raw;              // fully merged key-value map; null = not present, '' = explicitly empty
    private MemberResolver $members; // injected by ListProvider

    public function getMembers(): array { return $this->members->getMembers($this->name); }
    public function getOwners(): array  { return $this->members->getOwners($this->name); }

    /** Returns the context array for this list, ready to pass to VariableResolver::resolve(). */
    public function createContext(): array { /* list-* vars + all raw config keys + imap/smtp defaults */ }

    public string $displayName {
        get => $this->raw['display-name'] ?? $this->name;
    }
    public ReplyToBehavior $replyTo {
        get => ReplyToBehavior::from($this->raw['reply-to'] ?? 'list');
    }
    public ?string $footer {
        get => $this->raw['footer'] ?? null;  // null = not configured, '' = explicitly disabled
    }
    public int $maxSize {
        get => self::parseSize($this->raw['max-size'] ?? '5M');
    }

    /** Returns personalization whitelist. {list-url} always available. */
    public array $personalizeKeys {
        get {
            $raw = $this->raw['personalize'] ?? '';
            if ($raw === 'off' || $raw === '') {
                return ['list-url'];
            }
            return array_merge(['list-url'], array_map('trim', explode(',', $raw)));
        }
    }

    private static function parseSize(string $value): int {
        // M/MB -> *1_000_000, MiB -> *1_048_576, K/KB -> *1_000, KiB -> *1_024,
        // G/GB -> *1_000_000_000, GiB -> *1_073_741_824, plain int -> bytes
    }
}
```

## Member attributes — fully dynamic

`Member` has exactly one fixed field: `$email`. Everything else a resolver happens to know about a member — `firstname`, `lastname`, `username`, `pronoun`, an LDAP `employeeNumber`, a custom `title` column/key, anything — lives in `Member::$attributes` (`array<string, string>`), keyed by whatever name the backing store itself uses. **Nothing beyond `email` is hardcoded in `Member` or any resolver** (`is_member`/`is_owner`/`name` are reserved too, but structurally — they scope/filter rows, they never become attributes):

- **`type: database`**: `DatabaseMemberResolver` does `SELECT *` and exposes every column except `name`/`mail`/`is_member`/`is_owner` as an attribute. Add, rename, or remove columns in `list_members` freely — no code change needed. `addMember()` builds its `INSERT`/`ON DUPLICATE KEY UPDATE` column list dynamically from `Member::$attributes`; attribute names are validated as plain SQL identifiers (`^[A-Za-z_][A-Za-z0-9_]*$`) and backtick-quoted before being interpolated — this is what prevents SQL injection via a malicious attribute name, since PDO placeholders only cover values, not column names. An attribute naming a column that doesn't actually exist in the table still fails, just at the database (unknown column).
- **`type: csv`**: `CsvMemberResolver` exposes every CSV column except `name`/`mail`/`is_member`/`is_owner` as an attribute — whatever the file's header row currently has. `addMember()` extends the header with any new attribute key it's asked to write, backfilling `''` for every other row (see [CSV member file format](../reference/member-stores.md#csv-member-file-format)).
- **`type: inline`**: every key in a `members:`/`owners:` entry except `mail` becomes an attribute verbatim (`InlineMemberResolver::toMember()`).
- **`type: ldap`**: `LdapMemberResolver` exposes *every* attribute of the directory entry (`Entry::getAttributes()`, first value of each) except `mail`, under its own LDAP name — `{cn}`, `{givenName}`, `{sn}`, `{employeeNumber}`, `{businessCategory}`, whatever the schema has. There is no translation to `pronoun`/`title`/etc. — a list defines its own mapping as a normal config key, e.g.:
  ```yaml
  pronoun: "{businessCategory}"
  ```
  Since these are just config keys, they go through the standard 5-level priority merge (see [Configuration priority](config.md#configuration-priority-low--high)) and are resolved lazily like any other `{}` template — settable once at the config.yml root, at list-provider level, or per list, exactly like `list-mail`'s provider-level default. `firstname`/`lastname` are the one pair that *doesn't* need a list-level alias for LDAP: `LdapMemberResolver::entryToMember()` fills `attributes['firstname']`/`['lastname']` from `givenName`/`sn` — the standard `inetOrgPerson` attributes every LDAP schema this app expects already has — as a fallback (`isset()`-guarded, so a directory that happens to carry its own real `firstname`/`lastname` attributes is never overwritten). This exists so `{firstname}`/`{lastname}` — used throughout the codebase for a person's name (mail personalization, `{sender-name}`, `ListConfig::resolveMemberDisplayName()` in the manage-page owner list, ...) — work for any LDAP-backed list without every operator having to redefine `firstname: "{givenName}"` / `lastname: "{sn}"` themselves; a list-level alias is still supported and, since a member's own attributes are consulted first (see below), simply becomes redundant once this fallback already filled the same value in. `LdapMemberResolver` additionally copies `cn` into `attributes['username']` unconditionally (not `isset()`-guarded, unlike `firstname`/`lastname`) — see [Privacy-preserving `username`](#privacy-preserving-username) below.

**Resolution** (`MailProcessor::buildRecipientContext()`/`buildMailContext()`): `$recipient->attributes` (or, for the sender, `$senderMember->attributes` prefixed `sender-`) is exposed directly under each key's own name, with the canonical `mail`/`sender-mail` always set last so it can never be shadowed by a same-named attribute. A key a specific member simply doesn't have is absent from that member's context — the merge then falls through to whatever the list config defines for that key (e.g. a `pronoun: "{businessCategory}"` alias), and if nothing resolves it at all, `VariableResolver::resolve()` substitutes an empty string rather than leaking raw `{key}` syntax into a sent mail (see [Variable substitution](variables.md#variable-substitution)).

A member with its own explicit attribute value therefore always takes precedence over a list-level alias for that same key — the alias is purely a fallback for providers (chiefly LDAP) that have no dedicated field of their own under that name.

### Example: pronoun-based salutation

Turn a short code like `he`/`she` into a language-appropriate greeting via the `match` filter, chained with `default` for anyone with no pronoun set (see [Filters](variables.md#filters)): `personalize: pronoun,firstname` plus body text `{pronoun|match:he=>Lieber,she=>Liebe|default:Hallo} {firstname}`. For `type: database`/`csv`/`inline`, populate a `pronoun` column/key directly. For `type: ldap`, map it from whatever attribute the directory actually has, e.g. `pronoun: "{businessCategory}"`.

### Privacy-preserving `username`

Two call sites need a non-email identifier for privacy — `MailProcessor` embeds it (instead of the raw address) in unsubscribe tokens and the `X-Original-Sender` header, and `AuthController` in login tokens — via `$member->attributes['username'] ?? $member->email`. For `type: database`/`csv`/`inline`, this is just another attribute like any other (populate a `username` column/key if wanted) — optional, with the same email fallback as any provider that doesn't set it, unchanged from before `Member` was genericized. For `type: ldap`, `LdapMemberResolver` is the **one deliberate exception** to full genericity: it duplicates `cn` into `attributes['username']` in addition to exposing it as `{cn}` under its real name. This exists specifically because `AuthController`'s initial email lookup has no *bounded* list in scope — `AggregateMemberResolver::findListAndMemberByEmail()` searches across every list a user might belong to before any one list is known, so the `username` convention can't rely on a per-list alias the way `pronoun` does — without this one hardcoded convention every LDAP-backed login/unsubscribe/reply would silently embed the plain email address instead. (Once a match is found, `AuthController` does have that one list in scope — it uses it to send the login mail through the list's own SMTP config, see [Authentication (Magic Link)](web-ui.md#authentication-magic-link) — the lookup phase itself is what's genuinely list-agnostic.)

`LdapMemberResolver` is the one deliberate exception to full genericity (`cn` is copied to `username`) because `cn` is schema-guaranteed and the login lookup has no per-list alias to rely on — see [ADR-0015](../adr/0015-fully-dynamic-member-attributes.md).

### Additional addresses per member (`mail-aliases`)

A member/owner may have more than one legitimate address — LDAP's `mail` attribute is multi-valued by schema, and other backends can express the same idea via an extra column/key. Every resolver still only ever exposes **one** address as `Member::$email` (the first `mail` value for LDAP, whatever the `mail` column/key holds for the others) — deliberate, not a limitation worth lifting: `$email` is what's used as the actual delivery address (the recipient envelope in `MailProcessor::resolveRecipients()`, `{mail}` personalization, ...), and a single, stable target address is exactly what that needs. Every *additional* address instead becomes a `mail-aliases` attribute — always the same comma-separated string shape in the end (`Member::$attributes` is `array<string, string>`, see [Member attributes — fully dynamic](#member-attributes--fully-dynamic)), same dual string/array convention `senders:`/`personalize:` already use (see `ListConfig::splitCommaList()`):

- **`type: ldap`** — `LdapMemberResolver::entryToMember()` takes `mail`'s first value as `$email` and joins every value beyond it into `attributes['mail-aliases']`, e.g. `'bob.smith@example.org,b@example.org'` for an entry whose `mail` is `[bob@example.org, bob.smith@example.org, b@example.org]`. Absent entirely (not an empty string) when the entry has only one `mail` value — the common case.
- **`type: inline`/`type: yaml`** — `InlineMemberResolver::toMember()` accepts `mail-aliases` as a YAML list (`mail-aliases: [a@x.org, b@x.org]`), natural for these already-structured formats, and joins it into the same comma-separated string; a `mail-aliases` already written as a plain string passes through unchanged (dual-shape, like everywhere else this pattern is used).
- **`type: csv`/`type: database`** — no code changes needed at all: both resolvers already expose *every* non-reserved column verbatim as a string attribute (see [Member attributes — fully dynamic](#member-attributes--fully-dynamic)), so a plain `mail-aliases` column holding a comma-separated value (`"bob.smith@example.org,b@example.org"`) is picked up automatically by the exact same generic mechanism that already handles `firstname`/`pronoun`/etc.

**`ListConfig::matchEmail()`** (the shared private helper behind `findMemberInList()`/`findOwnerInList()` — and therefore `isMember()`/`isOwnedBy()`, which `IncomingMailFilter::checkPostAccess()`/`requiresModeration()` consult as the actual post-access gate) checks a candidate address against both a member's primary `$email` **and** their `mail-aliases`, so a sender writing from any of their addresses on file — not just the one Listig treats as primary — is still recognized as the same member/owner for posting-access purposes, regardless of which resolver produced them. Members are still recognized as such through the FIRST address only, in the sense that mail is still ever *delivered* to just that one address (unchanged) — this only widens *sender recognition*, never recipient expansion. A member with no `mail-aliases` attribute at all (the common case for every backend) makes `matchEmail()` degrade to the exact same single-address comparison it always did.

This was a real, confirmed gap before this existed, first found for LDAP specifically: `LdapMemberResolver::findByEmail()` (used for login and `{sender-*}` personalization lookups) already worked correctly for any alias address, since its LDAP search filter (`(mail={email})`) matches an entry if *any* of its multi-valued `mail` values equals the target — standard LDAP equality-filter semantics. But `matchEmail()` never touches LDAP (or any other backend) at all; it does a plain string comparison against the already-resolved `getMembers()`/`getOwners()` array, each `Member` carrying only its primary address — so a member sending from a non-primary alias was silently treated as a non-member/non-owner for post-access purposes specifically, even though every other lookup path already recognized them correctly. `mail-aliases` on the other three resolver types is a genuinely new capability (there was never an equivalent "the same person, more than one address" concept for them before), added for parity once the LDAP case was fixed.

## type: subaddress — subaddress forwarding

A `type: subaddress` list forwards mail sent to `{local-part}+{subaddress}@{domain}` (relative to the list's own `mail` address) to a computed target address, without an enumerable member directory. It is an ordinary list in every other respect — same IMAP mailbox, headers, subject-label, footer, moderation eligibility, personalization — only recipient resolution differs.

- No new `recipient`/`target` config key: the destination is expressed by reusing the normal inline `members:` shape (`mail`, and optionally `firstname`/`lastname`/`username`), except each value is a **template** resolved per incoming mail via `VariableResolver`, not static data resolved once at startup. Implemented by `Hengeb\Listig\Provider\SubaddressListProvider` (`ListConfig::$subaddressMemberTemplates`, non-null only for this list type) and `MailProcessor::resolveTemplateMembers()`.
- `owners:` uses the exact same inline mechanism as `type: inline`, so owner posting rights work identically (owners always post, no config key needed). `type: subaddress` lists have no static `members:`, so `getMembers()` is always empty and `post-access-members` is not meaningful for them — every non-owner sender is evaluated as public (`post-access-public`) instead.
- `{subaddress}` is a new mail-context variable — the matched extension for the current incoming mail (e.g. `alice` for `fwd+alice@example.org`), computed by `Hengeb\Listig\Mail\SubaddressExtractor` from the mail's `To`/`Cc` addresses relative to `list->mail`'s local part **and** domain (so `fwd+alice@other-domain.com` does not match). Resolves to an empty string when absent, like `{sender-firstname}` etc.
- If no `members[].mail` template references `{subaddress}` at all, the list degrades gracefully into a fixed-target alias — every mail (subaddressed or not) resolves to the same target(s), with no missing-subaddress rejection.
- Reserved subaddresses are rejected (`FilterResult::reject('reject.reserved_subaddress')`), not forwarded: `bounce` (exact — collides with the `{list->localPart}+bounce@{domain}` Sender header, `ListConfig::$localPart`) and the `accept-`/`reject-` prefixes (collide with moderation mailto addresses) are always reserved; a list may reserve more via the comma-separated `reserved-subaddresses` key. A mail with no subaddress at all is rejected with `reject.missing_subaddress`, but only if at least one member template actually requires one (see above).

## Additional senders (`senders:`)

A third category alongside members/owners/public: addresses allowed to post **without** becoming a member or owner — e.g. a board that should be able to write to the list but must not receive owner-only bounce mail (`NotificationMailer::sendToOwners()`/`BounceHandler` only ever address actual owners, untouched by this feature). Same inline entry shape as `members:`/`owners:` (a plain string, or a map with a required `mail` plus any other attribute keys), settable at any of the three levels — global (every list), provider (every list of that provider), or list (via a provider's own `lists:` node, or the root-level `lists:` mechanism) — see [Global / provider / list levels](config.md#global--provider--list-levels-members-owners-member-resolver-owner-resolver-senders-restricted-members), always additive across all three:

```yaml
list-providers:
  main:
    lists:
      vereinsliste:
        senders:
          - mail: chair@example.org
```

`ListConfig::$authorizedSenders` (`Member[]`) reads `$raw['senders']`, already gathered from all three levels by the provider (see [Global / provider / list levels](config.md#global--provider--list-levels-members-owners-member-resolver-owner-resolver-senders-restricted-members)) — each level normalized through the same dual string-or-array shape `personalizeKeys`/`reservedSubaddresses` already handle: a plain YAML array is used as-is; a single comma-separated **string** — the shape an LDAP `description:senders:a@x.org, b@x.org` entry or a `config-table` row produces, since neither has nested structure — is split via `ListConfig::splitCommaList()` first. Either way each entry is converted via the `public` `InlineMemberResolver::toMember()`.

`ListConfig::isAuthorizedSender()`/`findAuthorizedSender()` are consulted in two places:
- `IncomingMailFilter::checkPostAccess()`/`requiresModeration()` — the same early-return that already exempts owners (`if ($list->isOwnedBy($senderEmail) || $list->isAuthorizedSender($senderEmail)) { return null; }` / `return false;`) — bypasses `post-access-public: deny`/`post-access-members: moderate` without granting any other owner privilege.
- `MailProcessor::process()`'s sender lookup (`$list->findMemberByEmail($senderEmail) ?? $list->findAuthorizedSender($senderEmail) ?? new Member($senderEmail)`) — so `{sender-*}` personalization (e.g. a custom From display name) still resolves correctly for a `senders:`-only poster, not just members/owners.

## Sender restrictions (`restricted-members:`)

A mechanism (like `filters:`/`banned`-style global rules) for both a temporary, single-list write-only mute and a permanent, instance-wide send-**and**-receive ban — deliberately **one** schema rather than two separate ones, since both are the same underlying statement ("this address, this restriction, this scope") differing only in field values. Like the other five keys under [Global / provider / list levels](config.md#global--provider--list-levels-members-owners-member-resolver-owner-resolver-senders-restricted-members), settable at any of the three levels, always additive:

```yaml
# Global — every list, unless narrowed by lists:/except: below
restricted-members:
  - mail: abuser@example.org
    lists: [mylist]              # scoped to these list(s); omitted entirely = every list
    until: "2026-08-20"          # optional; omitted = indefinite, until the entry is manually removed
  - mail: excluded@example.org
    receive: false                # also blocks receiving, on top of the always-implied write block (default true = write-only)
    # no "lists:" -> every list
  - mail: partial@example.org
    except: [board-internal]      # blocked everywhere except this one list

list-providers:
  main:
    lists:
      board-internal:
        # List level — lists:/except: are never needed here: an entry declared on
        # one specific list is only ever gathered into that one list's own
        # RestrictionList instance in the first place (see below), so it's
        # implicitly scoped to just this list already.
        restricted-members:
          - mail: troll@example.org
```

**Per-list construction, not one global instance** — each list provider builds its **own** `RestrictionList` for each list it produces, from that one list's own three gathered levels (global + this provider + this list, concatenated), and passes it as `ListConfig`'s `$restrictions` constructor argument. `ListConfig::isSenderRestricted(string $email)`/`isReceiverRestricted(string $email)` delegate to it with the list's own name already bound — no list name parameter needed from the caller, and no global container-wide `RestrictionList` service exists anymore.

**`lists:`/`except:` on a provider- or list-level entry need no special handling** — `RestrictionList::matches()` is completely unchanged: it checks `lists:`/`except:` against the list name it's given, regardless of which level an entry came from. This is automatically correct precisely *because* each list's `RestrictionList` instance only ever contains that one list's own already-gathered entries — a provider-level entry with no `lists:`/`except:` of its own reaches only the `RestrictionList` instances of that provider's own lists in the first place, so "applies to every list" already means "every list of this provider" without any extra filtering. A list-level entry that happened to carry a `lists:`/`except:` naming a *different* list would simply be inert — harmless, not worth guarding against.

**`src/Config/RestrictionList.php`** (unchanged internals) — `isSendRestricted(string $listName, string $email)`/`isReceiveRestricted(...)` walk the entry list: an entry matches if the email matches (case-insensitive), it hasn't expired (`until` unset or still in the future), `lists:` is unset or contains `$listName`, and `except:` is unset or does **not** contain `$listName`. `isReceiveRestricted()` additionally requires `receive: false` on the entry. `except:` is deliberately **not** validated against `lists:` being absent — both filters just run independently in sequence, `except` wins on the (rare) case of a list appearing in both.

- **Sending**: `IncomingMailFilter::checkPostAccess()` checks `$list->isSenderRestricted($senderEmail)` **first**, before even the owner/`senders:` early-return — an instance-wide ban is meant to be absolute, overriding owner status too. Rejects with `reject.sender_restricted`, going through the normal `RejectionNotifier` pipeline like any other `reject.*` reason (no silent discard).
- **Receiving**: `MailProcessor::resolveRecipients()` filters `$list->isReceiverRestricted($member->email)` out of the expanded recipient list, alongside the pre-existing original-To/Cc exclusion — this is what lets a receive-restriction override even a still-active LDAP group membership (see [Member attributes — fully dynamic](#member-attributes--fully-dynamic): `getMembers()` reflects the directory live; this filter runs *after* that, independent of what the directory itself reports).
