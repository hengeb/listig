<?php

declare(strict_types=1);

namespace Hengeb\Listig\Tests\Variable;

use Hengeb\Listig\Variable\Literal;
use Hengeb\Listig\Variable\ResolutionPurpose;
use Hengeb\Listig\Variable\VariableResolver;
use PHPUnit\Framework\TestCase;

class VariableResolverTest extends TestCase
{
    public function testResolvesSimpleKey(): void
    {
        $this->assertSame('World', VariableResolver::resolve('{greeting}', [['greeting' => 'World']]));
    }

    public function testLiteralTextAroundPlaceholderIsPreserved(): void
    {
        $this->assertSame('Hello World!', VariableResolver::resolve('Hello {greeting}!', [['greeting' => 'World']]));
    }

    public function testLaterContextOverridesEarlier(): void
    {
        $result = VariableResolver::resolve('{key}', [['key' => 'first'], ['key' => 'second']]);
        $this->assertSame('second', $result);
    }

    public function testMissingKeyResolvesToEmptyString(): void
    {
        // A missing key is logged (unless quiet: true, see below) — declare that
        // expectation so PHPUnit doesn't flag it as unexpected test output.
        $this->expectErrorLog();
        $this->assertSame('', VariableResolver::resolve('{missing}', [[]]));
    }

    public function testRecursiveAliasResolution(): void
    {
        $result = VariableResolver::resolve('{alias}', [['alias' => '{real}', 'real' => 'value']]);
        $this->assertSame('value', $result);
    }

    public function testCycleDetectionLeavesPlaceholderLiteral(): void
    {
        $this->expectErrorLog();
        $result = VariableResolver::resolve('{a}', [['a' => '{b}', 'b' => '{a}']]);
        $this->assertSame('{a}', $result);
    }

    public function testBlockedKeyIsClassifiedUnderDisclosed(): void
    {
        $this->expectErrorLog();
        $result = VariableResolver::resolve('{imap-password}', [['imap-password' => 'secret']], ResolutionPurpose::Disclosed);
        $this->assertSame(VariableResolver::CLASSIFIED_PLACEHOLDER, $result);
    }

    public function testBlockedKeyIsResolvedUnderTrusted(): void
    {
        $result = VariableResolver::resolve('{imap-password}', [['imap-password' => 'secret']], ResolutionPurpose::Trusted);
        $this->assertSame('secret', $result);
    }

    public function testLiteralValueIsNeverReResolvedAsTemplate(): void
    {
        // A Literal-wrapped value containing '{' must never be treated as a further
        // template — this is what stops a member's own attribute (e.g. a
        // self-chosen "firstname") from being abused to reach another, unrelated
        // key via a nested {} — see CLAUDE.md "Untrusted input in {} templates".
        $result = VariableResolver::resolve('{firstname}', [[
            'firstname' => new Literal('{secret}'),
            'secret' => 'leaked',
        ]]);
        $this->assertSame('{secret}', $result);
    }

    public function testCallableValueIsNeverReResolvedAsTemplate(): void
    {
        $result = VariableResolver::resolve('{sender-name}', [[
            'sender-name' => fn() => '{secret}',
            'secret' => 'leaked',
        ]]);
        $this->assertSame('{secret}', $result);
    }

    public function testCallableReceivesContextsAndPurpose(): void
    {
        $result = VariableResolver::resolve('{computed}', [[
            'other' => 'value',
            'computed' => function (array $contexts, ResolutionPurpose $purpose) {
                return VariableResolver::lookup('other', $contexts, $purpose);
            },
        ]]);
        $this->assertSame('value', $result);
    }

    public function testQuietSuppressesNotFoundLogButStillReturnsEmptyString(): void
    {
        // Deliberately does NOT call $this->expectErrorLog() — if quiet: true
        // failed to suppress the log, PHPUnit would surface the unexpected
        // error_log() output itself, which doubles as a check that it stayed
        // silent (on top of the return-value assertion below).
        $this->assertSame('', VariableResolver::resolve('{missing}', [[]], quiet: true));
    }

    public function testQuietThreadsThroughRecursiveAliasResolution(): void
    {
        $this->assertSame('', VariableResolver::resolve('{alias}', [['alias' => '{also-missing}']], quiet: true));
    }

    public function testNestedPlaceholderInFilterArgs(): void
    {
        // 'missing' is genuinely absent from the context — deliberately, so the
        // |default: filter's own "empty value" fallback path is what fires.
        $this->expectErrorLog();
        $result = VariableResolver::resolve(
            '{missing|default:system@{domain}}',
            [['domain' => 'example.org']]
        );
        $this->assertSame('system@example.org', $result);
    }

    public function testFilterPipelineChaining(): void
    {
        $result = VariableResolver::resolve('{name|lowercase|default:unknown}', [['name' => 'ALICE']]);
        $this->assertSame('alice', $result);
    }

    public function testFilterPipelineDefaultFiresOnEmptyValue(): void
    {
        $result = VariableResolver::resolve('{name|lowercase|default:unknown}', [['name' => '']]);
        $this->assertSame('unknown', $result);
    }

    public function testDigitAfterBraceIsTreatedAsLiteralNotPlaceholder(): void
    {
        // {5,} is a PCRE quantifier fragment, not a variable — must survive
        // untouched (see SpamFilter's own use of this behavior for filters: regex).
        $this->assertSame('a{5,}b', VariableResolver::resolve('a{5,}b', [[]]));
    }

    public function testLookupWithoutTemplateParsing(): void
    {
        $this->assertSame('value', VariableResolver::lookup('key', [['key' => 'value']]));
        $this->assertNull(VariableResolver::lookup('missing', [[]]));
    }

    public function testBaseKeyIgnoresFilterPipeline(): void
    {
        $this->assertSame('firstname', VariableResolver::baseKey('firstname|lowercase|default:x'));
    }
}
