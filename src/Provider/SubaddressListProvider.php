<?php

declare(strict_types=1);

namespace Hengeb\Listig\Provider;

use Hengeb\Listig\Config\ConfigResolver;
use Hengeb\Listig\Config\ListConfig;
use Hengeb\Listig\Database\DatabaseConnectionFactory;
use Hengeb\Listig\Member\InlineMemberResolver;
use Hengeb\Listig\Member\MemberResolverFactory;
use Hengeb\Listig\Member\NullMemberResolver;
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
        foreach ($this->providerConfig['lists'] ?? [] as $listName => $listDef) {
            // Root-level `lists: <name>:` — see InlineListProvider for the identical
            // pattern and CLAUDE.md "Root-level lists:".
            $rootOverride = $this->configResolver->getListOverride($listName);
            $excludedKeys = array_flip(['member-resolver', 'owner-resolver', 'members', 'owners']);

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

            $memberResolver  = new InlineMemberResolver([], $listDef['owners'] ?? null, new NullMemberResolver());
            $memberResolver  = $this->memberResolverFactory->applyOverride($memberResolver, $rootOverride, $this->resolvedProviderConfig());
            $memberTemplates = $listDef['members'] ?? [];

            $lists[$listName] = new ListConfig($listName, $mail, $raw, $memberResolver, $memberTemplates);
        }

        return $lists;
    }

    public function setListConfigValue(string $listName, string $key, string $value): void
    {
        throw new \RuntimeException("Cannot modify a type: subaddress list at runtime (provider '{$this->name}').");
    }
}
