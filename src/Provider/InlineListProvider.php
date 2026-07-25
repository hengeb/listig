<?php

declare(strict_types=1);

namespace Hengeb\Listig\Provider;

use Hengeb\Listig\Config\ConfigResolver;
use Hengeb\Listig\Config\ListConfig;
use Hengeb\Listig\Database\DatabaseConnectionFactory;
use Hengeb\Listig\Member\InlineMemberResolver;
use Hengeb\Listig\Member\MemberResolverFactory;
use Hengeb\Listig\Variable\ResolutionPurpose;
use Hengeb\Listig\Variable\VariableResolver;

class InlineListProvider implements ListProvider
{
    private ?array $lists = null;
    private ?array $resolvedConfig = null;
    private readonly MemberResolverFactory $memberResolverFactory;

    public function __construct(
        private readonly string $name,
        private readonly ConfigResolver $configResolver,
        private readonly array $providerConfig,
        private readonly ?DatabaseConnectionFactory $dbFactory = null,
    ) {
        $this->memberResolverFactory = new MemberResolverFactory($this->dbFactory);
    }

    public function getLists(): array
    {
        if ($this->lists !== null) {
            return $this->lists;
        }

        $this->lists = [];
        $defaultMemberResolver = $this->memberResolverFactory->create(
            $this->providerConfig['member-resolver'] ?? null,
            $this->resolvedConfig(),
        );

        foreach ($this->providerConfig['lists'] ?? [] as $listName => $listDef) {
            $listOverrides = array_diff_key($listDef, array_flip(['members', 'owners']));
            $raw = $this->configResolver->resolveListConfig($this->providerConfig, $listOverrides);
            $raw['name'] = $listName;

            // list-mail may be a template (e.g. set once at provider level as
            // "{list-name}@example.org"); resolved here, before a ListConfig exists,
            // so {list-name} must be added to the context explicitly. Left in $raw
            // as-is (not stripped) — ListConfig::createContext() merges its own
            // computed 'list-mail' last, so it always wins over this raw entry.
            // ResolutionPurpose::Disclosed here protects against e.g. a mistaken
            // `list-mail: "{mail-password}"` even though no ListConfig (and
            // therefore no filtered context) exists yet at this point — the
            // blocking happens inside VariableResolver itself, not via a
            // pre-filtered context.
            $mail = VariableResolver::resolve($raw['list-mail'] ?? '', [array_merge($raw, ['list-name' => $listName])], ResolutionPurpose::Disclosed);
            if ($mail === '') {
                throw new \RuntimeException("List '$listName' has no list-mail (resolved to an empty value) in provider '{$this->name}'");
            }

            // Per-list inline members/owners override the default member-resolver
            // independently — e.g. inline owners with members still coming from
            // the configured member-resolver (database/ldap/csv).
            if (isset($listDef['members']) || isset($listDef['owners'])) {
                $memberResolver = new InlineMemberResolver(
                    $listDef['members'] ?? null,
                    $listDef['owners'] ?? null,
                    $defaultMemberResolver,
                );
            } else {
                $memberResolver = $defaultMemberResolver;
            }

            $this->lists[$listName] = new ListConfig($listName, $mail, $raw, $memberResolver);
        }

        return array_values($this->lists);
    }

    public function getList(string $name): ?ListConfig
    {
        $this->getLists();
        return $this->lists[$name] ?? null;
    }

    public function setListConfigValue(string $listName, string $key, string $value): void
    {
        throw new \RuntimeException("Cannot modify an inline (config.yml) list at runtime (provider '{$this->name}').");
    }

    private function resolvedConfig(): array
    {
        return $this->resolvedConfig ??= $this->configResolver->resolveListConfig($this->providerConfig);
    }
}
