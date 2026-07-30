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

class InlineListProvider extends AbstractListProvider
{
    private readonly MemberResolverFactory $memberResolverFactory;

    public function __construct(
        string $name,
        ConfigResolver $configResolver,
        array $providerConfig,
        private readonly ?DatabaseConnectionFactory $dbFactory = null,
    ) {
        parent::__construct($name, $configResolver, $providerConfig);
        $this->memberResolverFactory = new MemberResolverFactory($this->dbFactory);
    }

    /** @see AbstractListProvider::loadLists() */
    protected function loadLists(): array
    {
        $lists = [];
        $defaultMemberResolver = $this->memberResolverFactory->create(
            $this->providerConfig['member-resolver'] ?? null,
            $this->resolvedProviderConfig(),
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

            $lists[$listName] = new ListConfig($listName, $mail, $raw, $memberResolver);
        }

        return $lists;
    }

    public function setListConfigValue(string $listName, string $key, string $value): void
    {
        throw new \RuntimeException("Cannot modify an inline (config.yml) list at runtime (provider '{$this->name}').");
    }
}
