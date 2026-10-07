<?php

declare(strict_types=1);

namespace Hengeb\Listig\Provider;

use Hengeb\Listig\Config\ConfigResolver;
use Hengeb\Listig\Config\ListConfig;
use Hengeb\Listig\Config\RestrictionList;
use Hengeb\Listig\Database\DatabaseConnectionFactory;
use Hengeb\Listig\Member\MemberResolverFactory;
use Hengeb\Listig\Variable\ResolutionPurpose;
use Hengeb\Listig\Variable\VariableResolver;

/**
 * type: subaddress — subaddress-based forwarding lists. Unlike InlineListProvider,
 * `members:` is not resolved into static Member objects here: each entry's `mail`
 * (and optional firstname/lastname/username) is a template containing {subaddress},
 * resolved per incoming mail by MailProcessor. `owners:` uses the normal inline
 * mechanism unchanged, so owner posting rights work exactly like type: inline.
 * getMembers() is always empty for this list type (see "type: subaddress"), so
 * post-access-members is not meaningful for it — every non-owner sender is
 * evaluated as "public" instead.
 */
class SubaddressListProvider extends AbstractListProvider
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

        // member-resolver:/owner-resolver:/owners:/senders:/restricted-members: are
        // excluded from the plain raw-config merge below — see InlineListProvider for
        // the identical pattern and docs/architecture/config.md "Global / provider / list levels".
        // members: is excluded too, but for a different reason here: for type:
        // subaddress it's never a set of real members, it's the {subaddress}-template
        // mechanism (see class docblock) — it's read separately below as
        // $memberTemplates and never fed into the members: composition at all.
        $excludedKeys = array_flip(['member-resolver', 'owner-resolver', 'members', 'owners', 'senders', 'restricted-members']);

        foreach ($this->providerConfig['lists'] ?? [] as $listName => $listDef) {
            // Root-level `lists: <name>:` — see InlineListProvider for the identical
            // pattern and docs/architecture/config.md "Root-level lists:".
            $rootOverride = $this->configResolver->getListOverride($listName);

            $listOverrides = array_diff_key($listDef, $excludedKeys);
            $listOverrides = array_merge($listOverrides, array_diff_key($rootOverride, $excludedKeys));
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

            $memberTemplates = $listDef['members'] ?? [];

            // $listConfig for scopedLevels() combines this provider's own listDef
            // with the root-level lists: override — both are per-list sources, see
            // docs/architecture/config.md "Root-level lists:".
            $listConfig = array_merge($listDef, $rootOverride);

            // getMembers() is always empty for type: subaddress (see class docblock)
            // — member-resolver:/members: are never consulted for the member role
            // here, only owner-resolver:/owners: are.
            $memberResolver = $this->memberResolverFactory->buildComposedResolver(
                [],
                [],
                $this->scopedLevels('owner-resolver', $listConfig),
                $this->scopedLevels('owners', $listConfig),
                $this->resolvedProviderConfig(),
            );

            $raw['senders'] = array_merge(...array_map(
                fn($v) => is_string($v) ? ListConfig::splitCommaList($v) : ($v ?? []),
                $this->scopedLevels('senders', $listConfig),
            ));

            $restrictions = new RestrictionList(array_merge(...array_map(
                fn($v) => is_string($v)
                    ? array_map(fn(string $mail) => ['mail' => $mail], ListConfig::splitCommaList($v))
                    : ($v ?? []),
                $this->scopedLevels('restricted-members', $listConfig),
            )));

            $lists[$listName] = new ListConfig($listName, $mail, $raw, $memberResolver, $memberTemplates, $restrictions);
        }

        return $lists;
    }

    public function setListConfigValue(string $listName, string $key, string $value): void
    {
        throw new \RuntimeException("Cannot modify a type: subaddress list at runtime (provider '{$this->name}').");
    }
}
