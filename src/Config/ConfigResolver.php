<?php

declare(strict_types=1);

namespace Hengeb\Listig\Config;

class ConfigResolver
{
    private array $namedBlocks = [];
    private array $defaultConfig = [];
    private array $listProviderConfigs = [];
    private array $filters = [];

    public function __construct(string $configPath)
    {
        $config = YamlIncludeResolver::parseFile($configPath);
        if (!is_array($config)) {
            throw new \RuntimeException("Invalid config file: $configPath");
        }

        $this->processConfig($config);
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
        $providerUses = $providerConfig['use'] ?? [];
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
     * - 'list-providers' / 'filters': handled separately below.
     * - 'use': the list of named blocks to merge into the default.
     * - a scalar value: a direct default key-value.
     * - an array/map value: a named block — inert unless referenced via some `use:`
     *   (root, a list-provider's, or a per-list's).
     */
    private function processConfig(array $config): void
    {
        $defaultConfig = [];

        foreach ($config as $key => $value) {
            if ($key === 'list-providers' || $key === 'filters') {
                continue;
            }
            if ($key === 'use') {
                $defaultConfig['use'] = $value;
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

    private function substituteEnvVars(mixed $value): mixed
    {
        if (is_string($value)) {
            return preg_replace_callback('/\$\{?([A-Z_][A-Z0-9_]*)\}?/', function (array $m): string {
                $envKey = $m[1];
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
