<?php

declare(strict_types=1);

namespace Hengeb\Listig\Config;

class ConfigResolver
{
    private array $namedBlocks = [];
    private array $defaultConfig = [];
    private array $listProviderConfigs = [];
    private array $filters = [];
    private array $lists = [];
    private array $globalScopedSources = [];
    private array $reliableSpamReporters = [];
    private array $includedFiles = [];

    /** Root keys forming the global level of the three-level (global/provider/list) member/owner/sender/restriction mechanism — see getGlobalScopedSources(). */
    private const array SCOPED_KEYS = ['members', 'owners', 'member-resolver', 'owner-resolver', 'senders', 'restricted-members'];

    public function __construct(string $configPath)
    {
        $config = YamlIncludeResolver::parseFile($configPath);
        // Captured immediately, into our own instance state — not read lazily
        // later via YamlIncludeResolver::getLastParsedFiles(), since a *later*
        // parseFile() call for an unrelated purpose (YamlListProvider's own
        // list file, which shares the same resolver) would otherwise silently
        // overwrite it out from under us. See YamlIncludeResolver's own
        // docblock and CLAUDE.md "Worker loop — config reload".
        $this->includedFiles = YamlIncludeResolver::getLastParsedFiles();
        if (!is_array($config)) {
            throw new \RuntimeException("Invalid config file: $configPath");
        }

        $this->processConfig($config);
    }

    /**
     * Realpaths of config.yml itself plus every file spliced in via
     * `!include`, reachable from it at any depth — see
     * YamlIncludeResolver::$lastParsedFiles for why this exists.
     *
     * @return string[]
     */
    public function getIncludedFiles(): array
    {
        return $this->includedFiles;
    }

    /**
     * `list-providers:` is a map keyed by provider name (not a plain array) — the name
     * is used for error/log messages and, if a provider sets no `type` of its own (see
     * `resolveListConfig()`), as the provider's type.
     *
     * @return array<string, array<string, mixed>>
     */
    public function getListProviderConfigs(): array
    {
        return $this->listProviderConfigs;
    }

    /**
     * Global, list-independent spam filter rules from the top-level `filters:` section.
     *
     * @return array<int, array<string, mixed>>
     */
    public function getFilters(): array
    {
        return $this->filters;
    }

    /**
     * Root-level `lists:` — a map keyed by list name, matched against every list any
     * configured provider produces (LDAP, database, inline, yaml, subaddress) and
     * merged in as an additional, highest-priority per-list source; a name with no
     * matching provider-produced list is instead used to define a brand-new list via
     * an implicit `type: inline` provider. See CLAUDE.md "Root-level lists:".
     *
     * Combined from every source the same way the six scoped keys are (see
     * getGlobalScopedSources()) — the root's own direct `lists:` map plus each
     * root-level `use:`-referenced named block's own `lists:` map, in `use:`
     * order, with the root's own direct value merged in last/highest-priority.
     * Unlike the scoped keys, this is a per-list-name key merge (`array_merge()`,
     * not concatenation) rather than an additive list of independent sources —
     * `lists:` is a map, not a list of entries, so two sources defining the same
     * list just combine that one list's own keys, later source winning on a
     * plain-key conflict (same "use: blocks, then direct overrides" priority as
     * everything else at this level).
     *
     * @return array<string, array<string, mixed>>
     */
    public function getListOverride(string $name): array
    {
        return $this->lists[$name] ?? [];
    }

    /** @return string[] */
    public function getListOverrideNames(): array
    {
        return array_keys($this->lists);
    }

    /**
     * All raw values contributing to $key at the GLOBAL (config.yml root) level —
     * the outermost of the three levels (global, provider, list) every one of the
     * six scoped keys (`members:`/`owners:`/`member-resolver:`/`owner-resolver:`/
     * `senders:`/`restricted-members:`) can be set at. More than one raw value can
     * contribute here: the root's own direct value (if set) first, then each
     * root-level `use:`-referenced named block's own value for $key, in `use:`
     * order — every one of these is an independent additional source, never one
     * overriding another. See CLAUDE.md "Global / provider / list levels".
     *
     * @return array<int, mixed>
     */
    public function getGlobalScopedSources(string $key): array
    {
        return $this->globalScopedSources[$key] ?? [];
    }

    /**
     * Root-level `reliable-spam-reporters:` — extra domains an operator has
     * deliberately chosen to extend SpamRejectionDetector's trust to (see its own
     * docblock). Combined from every source the same way as the six scoped keys'
     * global level (root-direct value first, then each root-level
     * `use:`-referenced named block's own value, in `use:` order) via
     * collectGlobalSources() — but always additive/concatenated here (a flat list
     * of domains, not a map), and with no provider/list level of its own:
     * SpamRejectionDetector is a single, instance-wide trust boundary, not a
     * per-list setting, so unlike the six scoped keys this is never consumed via
     * AbstractListProvider::scopedLevels().
     *
     * @return string[]
     */
    public function getReliableSpamReporters(): array
    {
        return $this->reliableSpamReporters;
    }

    /**
     * Symmetric with getGlobalScopedSources(), one level down: all raw values
     * contributing to $key at the PROVIDER level for one specific provider's raw
     * config — that provider's own direct value (if set) first, then each of the
     * provider's own `use:`-referenced named blocks' value for $key, in that
     * provider's own `use:` order.
     *
     * @param array<string, mixed> $providerConfig the provider's raw list-providers.<name> map
     * @return array<int, mixed>
     */
    public function getProviderScopedSources(string $key, array $providerConfig): array
    {
        $sources = [];
        if (array_key_exists($key, $providerConfig)) {
            $sources[] = $providerConfig[$key];
        }
        foreach (self::normalizeUse($providerConfig['use'] ?? []) as $blockName) {
            if (array_key_exists($key, $this->namedBlocks[$blockName] ?? [])) {
                $sources[] = $this->namedBlocks[$blockName][$key];
            }
        }
        return $sources;
    }

    /**
     * Returns the resolved default config: all use: blocks merged, $VAR already substituted.
     * Used to read global settings like database credentials.
     *
     * @return array<string, string|null>
     */
    public function getResolvedDefault(): array
    {
        $merged = [];
        foreach ($this->defaultConfig['use'] ?? [] as $blockName) {
            $merged = $this->mergeBlock($merged, $this->namedBlocks[$blockName] ?? []);
        }
        return $this->mergeBlock($merged, $this->removeUseKey($this->defaultConfig));
    }

    /**
     * Merges provider-level config with defaults and returns a flat key-value map for a list.
     *
     * @param array<string, string|null> $providerConfig Provider-level config (from list-providers entry)
     * @param array<string, string|null> $listOverrides  Per-list overrides (highest priority)
     */
    public function resolveListConfig(array $providerConfig, array $listOverrides = []): array
    {
        // Priority (low → high):
        // 1. use: blocks in default
        // 2. direct keys in default
        // 3. use: blocks in provider config
        // 4. direct keys in provider config
        // 5. per-list overrides (listOverrides)

        $merged = [];

        // Level 1+2: default block
        $defaultUses = $this->defaultConfig['use'] ?? [];
        foreach ($defaultUses as $blockName) {
            $merged = $this->mergeBlock($merged, $this->namedBlocks[$blockName] ?? []);
        }
        $defaultDirect = $this->removeUseKey($this->defaultConfig);
        $merged = $this->mergeBlock($merged, $defaultDirect);

        // Level 3+4: provider config
        $providerUses = self::normalizeUse($providerConfig['use'] ?? []);
        foreach ($providerUses as $blockName) {
            $block = $this->namedBlocks[$blockName] ?? [];
            // Provider use: blocks do NOT override direct default values
            foreach ($block as $k => $v) {
                if (!array_key_exists($k, $defaultDirect)) {
                    $merged[$k] = $v;
                }
            }
        }
        $providerDirect = $this->removeUseKey($providerConfig);
        $merged = $this->mergeBlock($merged, $providerDirect);

        // Level 5: per-list overrides
        $merged = $this->mergeBlock($merged, $listOverrides);

        // A provider's native storage format (LDAP description[] sub-key,
        // database list_config row, inline/yaml `description:` key) uses the
        // short, natural key `description`, same as every other bare key
        // (reply-to, footer, ...). Renamed here, once, for every provider, to
        // `list-description` — the actual raw/context key ListConfig::$description
        // reads — so it can never collide with a member-level `description`
        // attribute (e.g. a real LDAP person attribute) the way a bare
        // `description` context key would. `list-description` set directly
        // wins if somehow both are present.
        if (array_key_exists('description', $merged)) {
            if (!array_key_exists('list-description', $merged)) {
                $merged['list-description'] = $merged['description'];
            }
            unset($merged['description']);
        }

        return $merged;
    }

    /**
     * The config.yml root is the default block (see CLAUDE.md "Configuration priority").
     * A root key is either:
     * - 'list-providers' / 'filters' / 'lists' / 'reliable-spam-reporters' / SCOPED_KEYS: handled separately below.
     * - 'use': the list of named blocks to merge into the default.
     * - a scalar value: a direct default key-value.
     * - an array/map value: a named block — inert unless referenced via some `use:`
     *   (root, a list-provider's, or a per-list's).
     */
    private function processConfig(array $config): void
    {
        $defaultConfig = [];

        foreach ($config as $key => $value) {
            if ($key === 'list-providers' || $key === 'filters' || $key === 'lists' || $key === 'reliable-spam-reporters' || in_array($key, self::SCOPED_KEYS, true)) {
                continue;
            }
            if ($key === 'use') {
                $defaultConfig['use'] = self::normalizeUse($value);
                continue;
            }
            if (is_array($value)) {
                $this->namedBlocks[$key] = $this->substituteEnvVars($value);
            } else {
                $defaultConfig[$key] = $value;
            }
        }

        $this->defaultConfig = $this->substituteEnvVars($defaultConfig);

        $this->listProviderConfigs = array_map(
            fn(array $p) => $this->substituteEnvVars($p),
            $config['list-providers'] ?? []
        );

        $this->filters = array_map(
            fn(array $f) => $this->substituteEnvVars($f),
            $config['filters'] ?? []
        );

        // Root-level lists: merged from every source (see getListOverride()'s
        // docblock) — use:-referenced named blocks first, in use: order (their
        // content is already $VAR-substituted, see the namedBlocks assignment
        // above), then the root's own direct lists: value merged in last.
        $listsMerged = [];
        foreach ($this->defaultConfig['use'] ?? [] as $blockName) {
            foreach ($this->namedBlocks[$blockName]['lists'] ?? [] as $listName => $override) {
                $listsMerged[$listName] = array_merge($listsMerged[$listName] ?? [], $override);
            }
        }
        foreach ($config['lists'] ?? [] as $listName => $override) {
            $listsMerged[$listName] = array_merge($listsMerged[$listName] ?? [], $this->substituteEnvVars($override));
        }
        $this->lists = $listsMerged;

        // Every raw value contributing to each scoped key at the GLOBAL level —
        // the root's own direct value first, then each root-level use:-referenced
        // named block's own value for the key, in `use:` order. See
        // getGlobalScopedSources().
        foreach (self::SCOPED_KEYS as $key) {
            $this->globalScopedSources[$key] = $this->collectGlobalSources($key, $config);
        }

        // reliable-spam-reporters: — same source-gathering as the six scoped keys
        // above (reused via the same helper), but always concatenated (a flat list
        // of domains, not a map with a merge concept) and with no provider/list
        // level of its own — see getReliableSpamReporters().
        $this->reliableSpamReporters = array_merge(...$this->collectGlobalSources('reliable-spam-reporters', $config));
    }

    /**
     * Every raw value contributing to $key at the GLOBAL (config.yml root) level —
     * the root's own direct value (if set) first, then each root-level
     * `use:`-referenced named block's own value for $key, in `use:` order. Shared
     * by both the six scoped keys (getGlobalScopedSources()) and
     * reliable-spam-reporters (getReliableSpamReporters()) — the two differ only
     * in how the caller combines the returned sources, not in how they're found.
     *
     * @return array<int, mixed>
     */
    private function collectGlobalSources(string $key, array $config): array
    {
        $sources = [];
        if (array_key_exists($key, $config)) {
            $sources[] = $this->substituteEnvVars($config[$key]);
        }
        foreach ($this->defaultConfig['use'] ?? [] as $blockName) {
            if (array_key_exists($key, $this->namedBlocks[$blockName] ?? [])) {
                $sources[] = $this->namedBlocks[$blockName][$key];
            }
        }
        return $sources;
    }

    private function mergeBlock(array $base, array $override): array
    {
        foreach ($override as $key => $value) {
            $base[$key] = $value;
        }
        return $base;
    }

    private function removeUseKey(array $config): array
    {
        unset($config['use']);
        return $config;
    }

    /**
     * `use:` is normally a YAML list (`use: [a, b]` or the `- a` / `- b` block form),
     * but a bare string is also accepted — including more than one name in it
     * (`use: mail-config, list-defaults`) — split the same way
     * `ListConfig::splitCommaList()` handles `personalize:`/`reserved-subaddresses:`,
     * on any run of commas/whitespace. Applied at every level `use:` is actually read
     * (the config.yml root, and a list-provider's own `use:`) — named blocks may not
     * contain their own `use:` at all (see "Configuration priority"), so there's no
     * third place this needs to run.
     */
    private static function normalizeUse(mixed $value): array
    {
        if (is_array($value)) {
            return $value;
        }
        if (!is_string($value) || trim($value) === '') {
            return [];
        }
        return array_values(array_filter(
            array_map('trim', preg_split('/[,\s]+/', trim($value))),
            fn(string $v) => $v !== '',
        ));
    }

    private function substituteEnvVars(mixed $value): mixed
    {
        if (is_string($value)) {
            // $VAR and ${VAR} are two distinct alternatives, not one pattern with
            // both delimiters optional — the previous /\$\{?...\}?/ made the
            // closing '}' optional independently of the opening '{', so it happily
            // swallowed an unrelated '}' immediately after a bare $VAR (e.g. the
            // closing brace of a surrounding {list-mail|default:$MAIL_USER}
            // template), corrupting anything downstream that still needed it.
            return preg_replace_callback('/\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)/', function (array $m): string {
                $envKey = $m[1] !== '' ? $m[1] : $m[2];
                $envValue = getenv($envKey);
                if ($envValue === false) {
                    throw new \RuntimeException("Environment variable '\${$envKey}' is not set (required by config.yml)");
                }
                return $envValue;
            }, $value);
        }

        if (is_array($value)) {
            return array_map(fn($v) => $this->substituteEnvVars($v), $value);
        }

        return $value;
    }
}
