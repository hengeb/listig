# Configuration semantics

How `config.yml` is merged and interpreted. The full annotated example is in [config.yml reference](../reference/config-yml.md).

## Root keys

The root of `config.yml` is the default configuration, applied to every list. A root key is either:

- `use:`, `list-providers:`, `filters:` (and the other keys documented in this file as special: `lists:`, `members:`/`owners:`/`member-resolver:`/`owner-resolver:`/`senders:`/`restricted-members:`, `reliable-spam-reporters:`) — handled specially, always applied;
- a scalar value (string/number/bool) — a direct default key-value, applied to every list unconditionally;
- a map value — a *named block*, inert unless referenced via `use:` (at the root, or in a list-provider's own `use:`). Named blocks themselves may **not** contain `use:` (prevents cycles).

`$VAR` substitutes environment variables at parse time; a missing variable is a hard error at startup. Direct root key-values take priority over values pulled in via `use:`; within `use:`, later entries override earlier ones. `use:` also accepts a bare string — one block name, or several separated by commas/whitespace — normalized by `ConfigResolver::normalizeUse()`. The annotated example is in the [config.yml reference](../reference/config-yml.md).

## list-providers — provider name as implicit type

Every provider is required to resolve to one of the known types (`ldap`, `inline`, `database`, `yaml`, `subaddress`) — but `type:` itself doesn't have to be spelled out on every entry. `type` goes through the normal priority chain (`ConfigResolver::resolveListConfig($providerConfig)` — root `use:`/direct, then the provider's own `use:`/direct, exactly like any other config key), and if that resolves to nothing, the provider's own map key (its name) is used as the type instead. An unresolvable type (name doesn't match a known type, and no `type:` was set anywhere) is a hard error at startup — same fail-fast philosophy as a missing `$VAR` or invalid `filters:` regex.

```yaml
type: ldap   # root-level default type

list-providers:
  provider1:
    ldap-host: ldap://ldap.example.org   # no own 'type' — inherits root default: ldap
    ...
  provider2:
    type: inline                          # explicit — overrides the root default
    ...
```

```yaml
# no root-level default type this time
list-providers:
  ldap:                # no 'type' anywhere → falls back to its own name: type ldap
    ...
  inline:               # same → type inline
    ...
  foo:
    type: database       # explicit → type database
    ...
  bar:                  # no 'type' anywhere, and "bar" isn't a known provider type
    ...                  # → hard error at startup: Unknown list provider type "bar" for provider "bar"
```

## `lists:` format

For `type: inline`, `type: yaml`, and `type: subaddress`, `lists:` is a **map keyed by list name** (not an array of objects with a `name:` field). `type: database` and `type: ldap` have no `lists:` key at all — list names come from the config-table/LDAP directory instead.

## Root-level `lists:`

A **separate**, top-level `lists:` key (sibling of `list-providers:`/`filters:` — not the per-provider `lists:` map documented above, though it shares the same map-keyed-by-list-name shape) supplements or defines individual lists **regardless of which provider produces them**:

```yaml
lists:
  newsletter:                       # one of 10 lists a type: ldap provider produces
    member-resolver:
      - type: database               # additive — LDAP membership is never replaced, only supplemented
        members-table: newsletter_externals
  vereinsliste:
    owners:                          # additive too — see "Global / provider / list levels" (docs/architecture/config.md) below
      - admin1@example.org
      - admin2@example.org
  standalone:                        # not produced by ANY configured provider at all
    list-mail: standalone@example.org
    senders:
      - mail: chair@example.org

list-providers:
  staff:
    type: ldap
    ...   # produces "newsletter" and "vereinsliste" from the directory
```

Two things happen, matched purely by list name:

1. **A name also produced by a configured provider** (any type — LDAP, database, inline, yaml, subaddress) gets the root `lists:` entry merged in as an *additional* per-list source, on top of whatever that provider already resolved for it.
2. **A name produced by no provider at all** is defined from scratch via an **implicit `type: inline` provider** — `list-providers:` can be omitted entirely; using only `lists:` behaves exactly like `list-providers: { inline: { lists: <the same content> } }`. Implemented in the composite `ListProvider` built in `config/container.php`: after collecting every configured provider's `getLists()`, any root `lists:` name not among them is built via a synthetic `InlineListProvider('_root', $configResolver, ['lists' => <only the missing names>], $dbFactory)`. Built **lazily**, only once actually needed (not at container-build time) and cached for the rest of the cycle — eagerly resolving it would mean calling `getLists()` on every provider (including LDAP/database ones) just to find out which names are missing, forcing a premature connection even for a request that never touches those lists (see [Worker loop — config reload](worker-and-queue.md#worker-loop--config-reload)).

**`ConfigResolver::getListOverride(string $name): array`** (`$this->lists[$name] ?? []`) and **`getListOverrideNames(): array`** — `lists:` is parsed once in `processConfig()`, the same root-special-case treatment as `list-providers`/`filters` (excluded from the "is_array → named block" branch). A list's own provider-native `lists:` entry (LDAP `description[]`, a `config-table` row, or a provider's own `lists:` node for `type: inline`/`yaml`/`subaddress`) and this root-level override are merged into a single per-list source *before* being handed to the three-level mechanism below — see [Global / provider / list levels](#global--provider--list-levels-members-owners-member-resolver-owner-resolver-senders-restricted-members) — so the "list level" there always means the union of both.

**`lists:` itself is combined from every source, same as the six scoped keys** — the root's own direct `lists:` map plus each root-level `use:`-referenced named block's own `lists:` map (in `use:` order, root-direct merged in last), *not* just the config.yml root's own literal `lists:` key. This was a real, confirmed gap: `lists:` written inside a `use:`-referenced block (including one loaded via `!include`, e.g. to keep local overrides in a gitignored `config.local.yml`) was silently invisible before this fix — `processConfig()` only ever read `$config['lists']` directly, never looked inside `$this->namedBlocks`, so a whole `lists: testliste: { senders: [...] }` block could sit there, fully parsed and stored, and simply never reach `getListOverride()` at all. Unlike the six scoped keys (an *additive list* of independent sources), this is a *key merge per list name* (`array_merge()`, later source wins on a plain-key conflict) — `lists:` is a map, not a list of entries, so two sources defining the same list name combine that list's own keys rather than each contributing a separate item to concatenate. A key that is itself one of the six scoped keys (e.g. `lists: testliste: senders:`) still goes through the normal additive three-level mechanism afterwards, unaffected by this merge — this only decides *which single per-list override map* reaches that mechanism's list-level slot in the first place.

## Global / provider / list levels (`members:`, `owners:`, `member-resolver:`, `owner-resolver:`, `senders:`, `restricted-members:`)

Six config keys — five documented individually below (`senders:`, `restricted-members:`) plus the `members:`/`owners:`/`member-resolver:`/`owner-resolver:` keys already introduced under [`lists:` format](#lists-format) — share one mechanism: each can be set at **any or all** of three levels, and every level that sets it **always adds to** the others, never replaces:

```yaml
# Global — applies to every list in the whole instance
owners:
  - superadmin@example.org

list-providers:
  staff:
    type: ldap
    ...
    # Provider — applies to every list this provider produces
    senders:
      - mail: it-support@example.org
    lists:
      newsletter:
        # List — applies only to this one list
        member-resolver:
          - type: database
            members-table: newsletter_externals
        restricted-members:          # no lists:/except: needed — see "Sender restrictions" (docs/architecture/providers-and-members.md) below
          - mail: abuser@example.org
            until: "2026-08-20"
```

`newsletter` above ends up with: LDAP directory membership (its provider's own native mechanism) **plus** the database source **plus** `superadmin@example.org` as an owner **plus** `it-support@example.org` as an authorized sender **plus** the one restriction entry — every level's contribution is a strict addition, never a replacement of another level's.

Every level, including list level, is purely additive: a list's own inline `members:`/`owners:` no longer *replaces* what `member-resolver:` produced. To exclude something, remove it from the relevant level instead of relying on an override — see [ADR-0013](../adr/0013-additive-scoped-config-levels.md).

**`AbstractListProvider::scopedLevels(string $key, array $listConfig): array`** — the shared primitive every list provider calls once per key, per list, returning *every* raw value contributing to that key across global, provider, and list (order: all global sources, then all provider sources, then the single list value) — identically for all six keys, no per-key special-casing. Each caller (`buildComposedResolver()`, the `senders:`/`restricted-members:` fold below) treats the return value as a flat list of independent sources to combine, never as a fixed 3-tuple — so a level contributing more than one source (see below) needs no special handling on the consumer side.

**A single "level" can itself have more than one source** — this is what actually makes `use:` work for these six keys, not just for ordinary scalar config values. `ConfigResolver::getGlobalScopedSources(string $key): array` returns the root's own direct value for `$key` (if set) *plus* the value of `$key` inside every named block the root's own `use:` references, in `use:` order — a `members:`/`owners:`/etc. entry set inside a block only reachable via `use:` (including one pulled in via `!include`, since that's spliced into the tree before any of this runs) is picked up exactly the same as a literal root-level entry, and both are additive, not one overriding the other. `ConfigResolver::getProviderScopedSources(string $key, array $providerConfig): array` is the symmetric provider-level equivalent, over that one provider's own `use:` list instead of the root's. Named blocks may not contain their own `use:` (see [Configuration priority](#configuration-priority-low--high)), so there is no further recursion to handle — one level of `use:`-expansion at each of the two levels is all there is.

```yaml
owners:
  - superadmin@example.org    # root-direct — a global source

use:
  - shared-owners              # root-level use: — every members:/owners:/etc. key
                                # inside this block is ALSO a global source

shared-owners:
  owners:
    - ops-team@example.org     # combines additively with superadmin@example.org above,
                                # not instead of it
```

**`MemberResolverFactory::buildSources(array|null $config, array $resolvedProviderConfig): array`** (`MemberResolver[]`) — unchanged from before this generalization: normalizes a single level's raw `member-resolver:`/`owner-resolver:`/`members:`/`owners:` value into independent sources. `null`/`[]` → none; a single resolver-config map (has `type:` ∈ `database`/`ldap`/`csv`) → one element via the pre-existing `create()`; a sequential list → each entry classified the same way, a resolver-config becomes a real resolver, anything else (a bare string, or a map without a recognized `type:` — the exact shape `members:`/`owners:` entries already use) becomes a single-entry `InlineMemberResolver` (populated as *both* members and owners of itself — harmless, since a source built here only ever lands in one of `CompositeMemberResolver`'s two source lists, so only the matching side is ever queried). `InlineMemberResolver::toMember()` is `public static` so this — and `ListConfig::$authorizedSenders`, see [Additional senders](providers-and-members.md#additional-senders-senders) below — can reuse the exact same string/map-to-`Member` conversion `members:`/`owners:` already used.

**`MemberResolverFactory::buildComposedResolver(array $memberResolverLevels, array $membersLevels, array $ownerResolverLevels, array $ownersLevels, array $resolvedProviderConfig, ?MemberResolver $extraBase = null): MemberResolver`** — builds the final resolver for one list from all three levels of both `member-resolver:`+`members:` (member role) and `owner-resolver:`+`owners:` (owner role), calling `buildSources()` once per level and concatenating every level's sources (`array_merge`, order: `$extraBase`, then member-resolver global/provider/list, then members global/provider/list — same pattern for owners) into a single `CompositeMemberResolver`. `$extraBase`, when given, is unconditionally included in both roles — `LdapListProvider`'s own hardcoded `LdapMemberResolver`, which (unlike every other provider type) is never itself expressed via `member-resolver:` (see [type: ldap](../reference/ldap.md)). No "return unchanged if nothing configured" special case is needed — `CompositeMemberResolver` with empty source arrays already behaves like an empty resolver on its own.

**`src/Member/CompositeMemberResolver.php`** (`implements MemberResolver`) — combines independent `$memberSources`/`$ownerSources` arrays. `getMembers()`/`getOwners()` query only their own role's sources and merge-dedupe by lowercased email (first source in configuration order wins on an attribute conflict). `findByEmail()` searches both. `addMember()` tries each member source in order, the first that doesn't throw wins (most resolvers can't signal "not applicable" any other way — `DatabaseMemberResolver` upserts unconditionally, so it always "succeeds"; only `LdapMemberResolver` throws when no matching directory entry exists — so listing LDAP before a database fallback means "prefer LDAP if the person has an entry there"). `removeMember()` calls every source with `supportsRemoval()`, not just the first — the same address can plausibly be a member via more than one source at once, and each source's own `removeMember()` is already a silent no-op when the address isn't actually present there.

**`InlineMemberResolver`** — no fallback/override concept anymore: `__construct(array $members, array $owners)` takes two required, non-nullable arrays and nothing else. `supportsRemoval()` is unconditionally `false` (previously depended on whether a fallback was given) — correct, since `CompositeMemberResolver::supportsRemoval()` is already `true` as soon as *any* one of its sources supports it, independent of what any single inline source reports.

**Each provider gathers all six keys the same mechanical way**, at its own list-construction site (`InlineListProvider`/`YamlListProvider`/`SubaddressListProvider`'s `loadLists()`, `LdapListProvider`/`DatabaseListProvider`'s per-list load method): all six (`member-resolver`, `owner-resolver`, `members`, `owners`, `senders`, `restricted-members`) are excluded from the plain `$raw` config merge (`ConfigResolver::mergeBlock()` replaces rather than combines, so these six are never meaningful as plain `$raw[...]` values) and instead gathered explicitly via `scopedLevels()`:
- `member-resolver`/`members`/`owner-resolver`/`owners` → `MemberResolverFactory::buildComposedResolver()`.
- `senders` → each level normalized (a string is split via `ListConfig::splitCommaList()`, an array/null used as-is) and concatenated into `$raw['senders']` — consumed by `ListConfig::$authorizedSenders` exactly as before, just now sourced from three levels instead of one.
- `restricted-members` → each level normalized the same way (a string becomes one `['mail' => ...]` entry per address, an array/null used as-is) and concatenated into a single `RestrictionList` instance, passed as `ListConfig`'s new `$restrictions` constructor argument — see [Sender restrictions](providers-and-members.md#sender-restrictions-restricted-members).

`SubaddressListProvider` is the one exception: `members:` at any level is *never* fed into the member-resolver composition for it, since for `type: subaddress` that key means the `{subaddress}`-template mechanism instead (`getMembers()` is always empty by design — see [type: subaddress](providers-and-members.md#type-subaddress--subaddress-forwarding)); only `owner-resolver:`/`owners:` go through the normal three-level composition there.

`filters:` deliberately does **not** get this three-level treatment — `SpamFilter`'s rule-based, `action:`-driven mechanism is structurally different enough (no resolver/addition concept to generalize) that unifying it wouldn't simplify anything; it stays a single, global, root-only key exactly as before.

## `list-mail`

The list's own mail address — one name, used both as the YAML config key you write and as the `{list-mail}` variable exposed everywhere else (no separate "input key" vs. "output variable" naming). It is a normal config key, merged through the same 5-level priority chain as any other (see [Configuration priority](#configuration-priority-low--high)) and lazily resolved via the existing `VariableResolver::resolve()` — no dedicated resolver class; the provider just calls it directly with `{list-name}` (and the rest of the already-merged raw config) as context, since a `ListConfig` doesn't exist yet at this point. This lets `list-mail` be set once at provider level (or in a `use:` block) as a template, e.g. `list-mail: "{list-name}@example.org"`, and every list in that provider gets its own valid address without redefining the key per list; a per-list `list-mail:` still overrides it individually. Only `{list-name}` and other already-merged raw config keys are available while resolving it — not `{list-domain}`/`{list-url}`/`{display-name}`, which are computed *from* the resolved `list-mail` and don't exist yet.

The unresolved raw `list-mail` template is deliberately left in `$raw` as-is, not stripped — `ListConfig::createContext()` already merges its own computed `'list-mail' => $this->mail` last (see its code), so the correctly resolved value always wins over the stale raw entry with no special-casing needed.

The startup error fires only if the **fully resolved** value is empty — not merely if a list omits `list-mail` itself, since it may be inherited from a provider/default-level template. A list with no `list-mail` anywhere in its merge chain throws `\RuntimeException` (fail-fast, same philosophy as missing `$VAR`s or an invalid `filters:` regex).

`type: ldap` reads the list's address from the LDAP `mail` attribute directly (schema-mandated by the `mailGroup` objectClass, not a YAML config key) and `type: database` reads a literal per-list `mail` row from `config-table` — neither goes through this lazy-resolution path, so the templating described here is currently `type: inline`/`type: yaml`/`type: subaddress`-only.

## `description` → `list-description`

Unlike `list-mail`, this one *does* have a different name depending on which side you're looking at — deliberately. You write the short, natural key `description` everywhere a list is configured — LDAP `description[]` (`description:Some text`), the database `list_config` table (a row with `key = 'description'`), and inline/yaml `lists:` entries (`description: "Some text"`). `ConfigResolver::resolveListConfig()` renames it to `list-description` once, for every provider, right before returning the merged config (a plain key rename, not `{}` resolution, so it stays within that method's existing responsibilities). `ListConfig::$description` reads `$this->raw['list-description']`, and `{list-description}` — not `{description}` — is the variable available everywhere else (footer, subject-label, custom aliases, ...).

The rename exists specifically so the list's own description can never collide with a *member's* `description` attribute — a real, commonly-present LDAP person attribute, and just as plausible as a database/CSV column — which, since `Member::$attributes` is fully dynamic (see [Member attributes — fully dynamic](providers-and-members.md#member-attributes--fully-dynamic)), would otherwise show up as `{description}` in the recipient context too, silently shadowing (or being shadowed by) the list's own. Same reasoning as `list-mail` vs. a member's own `mail`.

Like `$displayName`, `ListConfig::$description` is resolved as a template under `ResolutionPurpose::Disclosed` (see [ResolutionPurpose](variables.md#resolutionpurpose)) — it is read directly in `templates/list/manage.latte`/`list/index.latte`/`dashboard.latte`, so `list-description: "{imap-password}"` must not leak that value there, and `list-description: "Announcements for {list-name}"` works as a template.

A `list-description:` key set directly (bypassing the short form) still works and takes priority if somehow both are present in the same merge. The bare `description` key never survives into the final raw config, so it is never itself resolvable as `{description}`.

## Environment variable substitution

`$VAR` in any config value is replaced with the corresponding environment variable at parse time, before lazy variable resolution. This allows secrets to live in `.env` while everything else is in `config.yml`.

- `$VAR` or `${VAR}` syntax supported
- `$VAR`/`${VAR}` may appear anywhere within a string value, not just as the entire value — including nested inside a `{}` template's filter args, e.g. `mail-user: "{list-mail|default:$MAIL_USER}"` or `display-name: "System ({$HOSTNAME})"`. Substitution (`ConfigResolver::substituteEnvVars()`, a brace-aware `preg_replace_callback`) replaces only the `$VAR`/`${VAR}` token itself, leaving the rest of the string — including any surrounding `{...}` — untouched.
- If the environment variable is not set: hard error at startup, do not silently use empty string
- Substitution happens on raw string values only, before `{}` variable resolution
- All config levels support `$VAR` substitution: named blocks, the config.yml root, `list-providers`, and LDAP `description[]` values

## File includes (`!include`)

Any YAML value in `config.yml` (and in `type: yaml` list-provider files, see `YamlListProvider`) can be replaced by the contents of another YAML file, e.g. to move a list's inline members into their own file:

```yaml
list-providers:
  main:
    type: inline
    lists:
      mylist:
        list-mail: mylist@example.org
        members: !include members/mylist.yml
```

- Resolved by `Hengeb\Listig\Config\YamlIncludeResolver` at parse time — before `$VAR` substitution, `use:`/priority merging, and any `{}` variable resolution. The included file's parsed content is spliced into the tree at that node, exactly as if it had been written inline.
- The path is resolved relative to the directory of the file containing the `!include` tag, not always relative to `config.yml` — an included file may itself use `!include`, and paths inside it are relative to its own directory. An absolute path (starting with `/`) is used as-is.
- Circular includes are a hard error at parse time (detected via `realpath`).
- Any other custom YAML tag (e.g. `!foo`) is a hard error — `!include` is the only one supported.
- `YamlListProvider`'s list file goes through the same resolver, so a `type: yaml` provider's `lists:` (or a single list's `members:`/`owners:`) can also be split into separate files.

## Configuration priority (low → high)

0. Code defaults (lowest — ensures keys always have a value; can be overridden at any level). Kept in one table, `ListConfig::DEFAULTS` (every key whose default is a plain value: `archive: off`, `reply-to: list`, `max-per-sender: 5`, `join-policy: invite`, ...), used by the typed getters *and* put under the configured keys in `createContext()` — so `{archive}` in a template is `off` on a list that never set it, not empty. Defaults that depend on other keys (`imap-secure` from the port, `imap-user` from `mail-user`) or mean "none" (`footer`, `list-label`, `smtp-from-name`) are not in the table and stay in their getters
1. `use:` blocks at the config.yml root (in order; later entries override earlier)
2. Direct key-values at the config.yml root
3. `use:` blocks in `list-provider` (merged; do not override direct root-level values)
4. Direct key-values in `list-provider` (override everything from 1–3)
5. Per-list key-values from the provider (LDAP: `description[]`; database: `config-table` rows; inline: list-level keys)
6. Root-level `lists: <name>:` (see [Root-level `lists:`](#root-level-lists)) — highest priority, applies uniformly regardless of provider type.

`members:`/`owners:`/`member-resolver:`/`owner-resolver:`/`senders:`/`restricted-members:` are exempt from this plain-value priority chain entirely — see [Global / provider / list levels](#global--provider--list-levels-members-owners-member-resolver-owner-resolver-senders-restricted-members): all three of their own levels (global, provider, list — the last being the union of level 5 and level 6 above) are always additive, never one overriding another.

## Key value states

Three distinct states for any key:
- **Not present**: code default is used
- **Empty string** (`key:` with no value, or `key: ""`): explicitly set to empty string — overrides any default including code defaults (e.g. disables footer)
- **Non-empty value**: used as-is

This distinction must be preserved through the entire merge chain. For the keys in `ListConfig::DEFAULTS` it holds in the template context too: only an *absent* (or null) key shows its code default, an explicitly empty one stays empty. Use `null` internally for "not present" and `''` for "empty string".
