<?php

declare(strict_types=1);

namespace Hengeb\Listig\Tests\Config;

use Hengeb\Listig\Config\ConfigResolver;
use PHPUnit\Framework\TestCase;

class ConfigResolverTest extends TestCase
{
    private array $tempFiles = [];

    protected function tearDown(): void
    {
        foreach ($this->tempFiles as $file) {
            @unlink($file);
        }
        $this->tempFiles = [];
    }

    private function resolverFor(string $yaml): ConfigResolver
    {
        $file = tempnam(sys_get_temp_dir(), 'listig_config_test_') . '.yml';
        file_put_contents($file, $yaml);
        $this->tempFiles[] = $file;
        return new ConfigResolver($file);
    }

    // --- $VAR substitution ---

    public function testVarSubstitutionFromEnvironment(): void
    {
        putenv('LISTIG_TEST_VAR=substituted-value');
        $resolver = $this->resolverFor("some-key: \$LISTIG_TEST_VAR\n");
        $this->assertSame('substituted-value', $resolver->getResolvedDefault()['some-key']);
        putenv('LISTIG_TEST_VAR');
    }

    public function testVarSubstitutionWithBraces(): void
    {
        putenv('LISTIG_TEST_VAR=braced-value');
        $resolver = $this->resolverFor("some-key: \"prefix-\${LISTIG_TEST_VAR}-suffix\"\n");
        $this->assertSame('prefix-braced-value-suffix', $resolver->getResolvedDefault()['some-key']);
        putenv('LISTIG_TEST_VAR');
    }

    public function testMissingEnvVarThrowsAtConstruction(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->resolverFor("some-key: \$LISTIG_DEFINITELY_UNDEFINED_VAR\n");
    }

    // --- use: block merging (getResolvedDefault) ---

    public function testUseBlockValuesAreMergedIntoDefault(): void
    {
        $resolver = $this->resolverFor(<<<YAML
        use: [my-block]
        my-block:
          from-block: value
        YAML);
        $this->assertSame('value', $resolver->getResolvedDefault()['from-block']);
    }

    public function testDirectRootValueOverridesUseBlockValue(): void
    {
        $resolver = $this->resolverFor(<<<YAML
        use: [my-block]
        key: direct-value
        my-block:
          key: block-value
        YAML);
        $this->assertSame('direct-value', $resolver->getResolvedDefault()['key']);
    }

    public function testLaterUseBlockOverridesEarlierOne(): void
    {
        $resolver = $this->resolverFor(<<<YAML
        use: [first, second]
        first:
          key: from-first
        second:
          key: from-second
        YAML);
        $this->assertSame('from-second', $resolver->getResolvedDefault()['key']);
    }

    public function testBareCommaStringUseIsNormalizedToAList(): void
    {
        $resolver = $this->resolverFor(<<<YAML
        use: first, second
        first:
          a: 1
        second:
          b: 2
        YAML);
        $default = $resolver->getResolvedDefault();
        $this->assertSame(1, $default['a']);
        $this->assertSame(2, $default['b']);
    }

    // --- root-level lists: merging (getListOverride) ---

    public function testListOverrideFromRootDirect(): void
    {
        $resolver = $this->resolverFor(<<<YAML
        lists:
          testlist:
            archive: public
        YAML);
        $this->assertSame(['archive' => 'public'], $resolver->getListOverride('testlist'));
    }

    public function testListOverrideMergedFromUseReferencedBlock(): void
    {
        // This was a real, confirmed gap: lists: written inside a use:-referenced
        // block (e.g. loaded via !include) was silently invisible before the fix.
        $resolver = $this->resolverFor(<<<YAML
        use: [local-config]
        local-config:
          lists:
            testlist:
              senders: [alice@example.org]
        YAML);
        $this->assertSame(['senders' => ['alice@example.org']], $resolver->getListOverride('testlist'));
    }

    public function testListOverrideCombinesRootDirectAndBlockSourceKeyByKey(): void
    {
        $resolver = $this->resolverFor(<<<YAML
        lists:
          testlist:
            archive: public

        use: [local-config]
        local-config:
          lists:
            testlist:
              senders: [alice@example.org]
        YAML);
        $override = $resolver->getListOverride('testlist');
        $this->assertSame('public', $override['archive']);
        $this->assertSame(['alice@example.org'], $override['senders']);
    }

    public function testListOverrideForUnknownNameIsEmptyArray(): void
    {
        $resolver = $this->resolverFor("language: de\n");
        $this->assertSame([], $resolver->getListOverride('nonexistent'));
    }

    public function testGetListOverrideNames(): void
    {
        $resolver = $this->resolverFor(<<<YAML
        lists:
          alpha: {archive: public}
          beta: {archive: members}
        YAML);
        $names = $resolver->getListOverrideNames();
        sort($names);
        $this->assertSame(['alpha', 'beta'], $names);
    }

    // --- six scoped keys (getGlobalScopedSources) ---

    public function testGlobalScopedSourceFromRootDirect(): void
    {
        $resolver = $this->resolverFor(<<<YAML
        owners:
          - admin@example.org
        YAML);
        $this->assertSame([['admin@example.org']], $resolver->getGlobalScopedSources('owners'));
    }

    public function testGlobalScopedSourcesCombineRootDirectAndUseBlock(): void
    {
        // Also a real, confirmed gap before the fix: owners: (and the other five
        // scoped keys) inside a use:-block was silently inert.
        $resolver = $this->resolverFor(<<<YAML
        owners:
          - root-owner@example.org
        use: [local-config]
        local-config:
          owners:
            - block-owner@example.org
        YAML);
        $sources = $resolver->getGlobalScopedSources('owners');
        $this->assertCount(2, $sources);
        $this->assertContains(['root-owner@example.org'], $sources);
        $this->assertContains(['block-owner@example.org'], $sources);
    }

    public function testGlobalScopedSourceAbsentWhenNotConfigured(): void
    {
        $resolver = $this->resolverFor("language: de\n");
        $this->assertSame([], $resolver->getGlobalScopedSources('owners'));
    }

    public function testAllSixScopedKeysAreExcludedFromNamedBlockTrap(): void
    {
        // Each of these must be readable as its own global-scoped source, not
        // silently swallowed as an inert named block (the exact class of bug
        // this mechanism exists to avoid).
        $resolver = $this->resolverFor(<<<YAML
        members: [a@x.org]
        owners: [b@x.org]
        member-resolver: {type: csv, file: /tmp/x.csv}
        owner-resolver: {type: csv, file: /tmp/x.csv}
        senders: [c@x.org]
        restricted-members:
          - mail: d@x.org
        YAML);
        foreach (['members', 'owners', 'member-resolver', 'owner-resolver', 'senders', 'restricted-members'] as $key) {
            $this->assertNotSame([], $resolver->getGlobalScopedSources($key), "$key must be picked up as a global source");
        }
    }

    // --- reliable-spam-reporters ---

    public function testReliableSpamReportersFromRootDirect(): void
    {
        // This was completely broken before the fix — not just missing use:
        // support, but not working at the root level AT ALL.
        $resolver = $this->resolverFor(<<<YAML
        reliable-spam-reporters:
          - direct-root-domain.example
        YAML);
        $this->assertSame(['direct-root-domain.example'], $resolver->getReliableSpamReporters());
    }

    public function testReliableSpamReportersFromUseBlock(): void
    {
        $resolver = $this->resolverFor(<<<YAML
        use: [local-config]
        local-config:
          reliable-spam-reporters:
            - block-domain.example
        YAML);
        $this->assertSame(['block-domain.example'], $resolver->getReliableSpamReporters());
    }

    public function testReliableSpamReportersCombinesRootAndBlockAdditively(): void
    {
        $resolver = $this->resolverFor(<<<YAML
        reliable-spam-reporters:
          - direct-root-domain.example
        use: [local-config]
        local-config:
          reliable-spam-reporters:
            - block-domain.example
        YAML);
        $domains = $resolver->getReliableSpamReporters();
        sort($domains);
        $this->assertSame(['block-domain.example', 'direct-root-domain.example'], $domains);
    }

    public function testReliableSpamReportersDefaultsToEmptyArray(): void
    {
        $resolver = $this->resolverFor("language: de\n");
        $this->assertSame([], $resolver->getReliableSpamReporters());
    }

    // --- filters: (deliberately NOT merged from use: blocks) ---

    public function testFiltersReadFromRootDirectOnly(): void
    {
        $resolver = $this->resolverFor(<<<YAML
        filters:
          - subject: spam
        YAML);
        $this->assertCount(1, $resolver->getFilters());
    }

    public function testFiltersInsideUseBlockAreNotPickedUp(): void
    {
        // Deliberate, documented behavior: filters: stays a single, global,
        // root-only key — unlike lists:/the six scoped keys, it does not merge
        // from use:-referenced blocks.
        $resolver = $this->resolverFor(<<<YAML
        use: [local-config]
        local-config:
          filters:
            - subject: spam
        YAML);
        $this->assertSame([], $resolver->getFilters());
    }

    // --- list-providers: ---

    public function testListProviderConfigsAreExposed(): void
    {
        $resolver = $this->resolverFor(<<<YAML
        list-providers:
          main:
            type: inline
        YAML);
        $configs = $resolver->getListProviderConfigs();
        $this->assertSame('inline', $configs['main']['type']);
    }

    // --- resolveListConfig priority chain ---

    public function testResolveListConfigProviderDirectOverridesDefaultUseBlock(): void
    {
        $resolver = $this->resolverFor(<<<YAML
        use: [defaults]
        defaults:
          reply-to: list
        YAML);
        $merged = $resolver->resolveListConfig(['reply-to' => 'sender']);
        $this->assertSame('sender', $merged['reply-to']);
    }

    public function testResolveListConfigListOverrideHasHighestPriority(): void
    {
        $resolver = $this->resolverFor("reply-to: list\n");
        $merged = $resolver->resolveListConfig(['reply-to' => 'sender'], ['reply-to' => 'both']);
        $this->assertSame('both', $merged['reply-to']);
    }

    public function testResolveListConfigRenamesDescriptionToListDescription(): void
    {
        $resolver = $this->resolverFor("language: de\n");
        $merged = $resolver->resolveListConfig([], ['description' => 'Some text']);
        $this->assertSame('Some text', $merged['list-description']);
        $this->assertArrayNotHasKey('description', $merged);
    }

    public function testResolveListConfigExplicitListDescriptionWinsOverBareDescription(): void
    {
        $resolver = $this->resolverFor("language: de\n");
        $merged = $resolver->resolveListConfig([], [
            'description' => 'bare',
            'list-description' => 'explicit',
        ]);
        $this->assertSame('explicit', $merged['list-description']);
    }

    // --- getIncludedFiles() (bin/worker.php's own config-reload mtime watch) ---

    public function testGetIncludedFilesContainsOnlyItselfWhenNoIncludes(): void
    {
        $resolver = $this->resolverFor("language: de\n");
        $this->assertCount(1, $resolver->getIncludedFiles());
    }

    public function testGetIncludedFilesListsAnIncludedFileToo(): void
    {
        $dir = sys_get_temp_dir() . '/listig_config_resolver_include_test_' . uniqid();
        mkdir($dir);
        $includedPath = $dir . '/local.yml';
        file_put_contents($includedPath, "owners:\n  - mail: admin@example.org\n");
        $mainPath = $dir . '/main.yml';
        file_put_contents($mainPath, "owners: !include local.yml\n");

        try {
            $resolver = new ConfigResolver($mainPath);

            $this->assertSame(
                [realpath($mainPath), realpath($includedPath)],
                $resolver->getIncludedFiles(),
            );
        } finally {
            @unlink($includedPath);
            @unlink($mainPath);
            @rmdir($dir);
        }
    }
}
