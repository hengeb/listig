<?php

declare(strict_types=1);

namespace Hengeb\Listig\Tests\Mail;

use Hengeb\Listig\Config\ListConfig;
use Hengeb\Listig\Logging\LogLevel;
use Hengeb\Listig\Logging\Logger;
use Hengeb\Listig\Mail\SpamFilter;
use PhpImap\IncomingMail;
use PHPUnit\Framework\TestCase;

class SpamFilterTest extends TestCase
{
    private function logger(): Logger
    {
        return new Logger(LogLevel::Error); // quiet — debug tracing not needed for these tests
    }

    private function mailWithSubject(string $subject): IncomingMail
    {
        $mail = new IncomingMail();
        $mail->subject = $subject;
        return $mail;
    }

    /**
     * IncomingMail::$textPlain is private with no public setter (its __get()
     * lazily fetches from IMAP data parts) — Reflection is the only way to seed
     * a fixed value for a unit test that has no real IMAP connection at all.
     */
    private function setTextPlain(IncomingMail $mail, string $value): void
    {
        (new \ReflectionProperty($mail, 'textPlain'))->setValue($mail, $value);
    }

    private function list(): ListConfig
    {
        return new ListConfig('mylist', 'mylist@example.org', []);
    }

    public function testLiteralSubstringMatchIsCaseInsensitive(): void
    {
        $filter = new SpamFilter([['subject' => 'VIAGRA']], $this->logger());
        $this->assertSame('reject', $filter->match($this->mailWithSubject('Cheap viagra now!'), $this->list()));
    }

    public function testNoMatchReturnsNull(): void
    {
        $filter = new SpamFilter([['subject' => 'viagra']], $this->logger());
        $this->assertNull($filter->match($this->mailWithSubject('Team meeting notes'), $this->list()));
    }

    public function testRegexPatternMatch(): void
    {
        $filter = new SpamFilter([['subject' => '/^URGENT/i']], $this->logger());
        $this->assertSame('reject', $filter->match($this->mailWithSubject('urgent: please read'), $this->list()));
    }

    public function testMultiConditionRuleRequiresAllConditionsToMatch(): void
    {
        $filter = new SpamFilter([['subject' => 'foo', 'body' => 'bar']], $this->logger());
        $mail = $this->mailWithSubject('foo subject');
        $this->setTextPlain($mail, 'unrelated body');
        $this->assertNull($filter->match($mail, $this->list()), 'only one of two conditions matched, must not fire');
    }

    public function testMultiConditionRuleFiresWhenBothMatch(): void
    {
        $filter = new SpamFilter([['subject' => 'foo', 'body' => 'bar']], $this->logger());
        $mail = $this->mailWithSubject('foo subject');
        $this->setTextPlain($mail, 'contains bar here');
        $this->assertSame('reject', $filter->match($mail, $this->list()));
    }

    public function testDefaultActionIsReject(): void
    {
        $filter = new SpamFilter([['subject' => 'spam']], $this->logger());
        $this->assertSame('reject', $filter->match($this->mailWithSubject('spam mail'), $this->list()));
    }

    public function testExplicitDiscardAction(): void
    {
        $filter = new SpamFilter([['subject' => 'spam', 'action' => 'discard']], $this->logger());
        $this->assertSame('discard', $filter->match($this->mailWithSubject('spam mail'), $this->list()));
    }

    public function testFirstMatchingRuleWins(): void
    {
        $filter = new SpamFilter([
            ['subject' => 'foo', 'action' => 'discard'],
            ['subject' => 'foo', 'action' => 'reject'],
        ], $this->logger());
        $this->assertSame('discard', $filter->match($this->mailWithSubject('foo bar'), $this->list()));
    }

    public function testInvalidActionThrowsAtConstruction(): void
    {
        $this->expectException(\RuntimeException::class);
        new SpamFilter([['subject' => 'x', 'action' => 'not-a-real-action']], $this->logger());
    }

    public function testConfiguredDefaultActionAppliesToRulesWithoutTheirOwn(): void
    {
        $filter = new SpamFilter([['subject' => 'spam']], $this->logger(), 'discard');
        $this->assertSame('discard', $filter->match($this->mailWithSubject('spam mail'), $this->list()));
    }

    public function testConfiguredDefaultActionDoesNotOverrideARulesOwnAction(): void
    {
        $filter = new SpamFilter([['subject' => 'spam', 'action' => 'reject']], $this->logger(), 'discard');
        $this->assertSame('reject', $filter->match($this->mailWithSubject('spam mail'), $this->list()));
    }

    public function testInvalidConfiguredDefaultActionThrowsAtConstruction(): void
    {
        $this->expectException(\RuntimeException::class);
        new SpamFilter([['subject' => 'x']], $this->logger(), 'not-a-real-action');
    }

    public function testUnknownFieldThrowsAtConstruction(): void
    {
        $this->expectException(\RuntimeException::class);
        new SpamFilter([['nonexistent-field' => 'x']], $this->logger());
    }

    public function testEmptyRuleThrowsAtConstruction(): void
    {
        $this->expectException(\RuntimeException::class);
        new SpamFilter([[]], $this->logger());
    }

    public function testInvalidRegexThrowsAtConstruction(): void
    {
        // Must actually be recognized as a regex first (matching open/close
        // delimiter with valid trailing flags) — /(unclosed group/ qualifies as
        // regex-shaped but fails to compile (unbalanced parenthesis).
        $this->expectException(\RuntimeException::class);
        new SpamFilter([['subject' => '/(unclosed group/']], $this->logger());
    }

    public function testPatternWithoutClosingDelimiterIsTreatedAsLiteralNotRegex(): void
    {
        // No second '/' at all -> isRegex() returns false, so this is matched as
        // a plain literal substring — including the leading slash itself.
        $filter = new SpamFilter([['subject' => '/unterminated']], $this->logger());
        $this->assertSame('reject', $filter->match($this->mailWithSubject('see /unterminated here'), $this->list()));
    }

    public function testVariableInPatternIsResolvedAgainstTheSpecificList(): void
    {
        // {list-domain} must resolve against the list actually being checked, not
        // stay a literal, never-matching "{list-domain}" string — this was a
        // real, confirmed bug (see docs/architecture/mail-processing.md "Variable resolution in filter
        // patterns"). Matched against a domain that differs from the substring
        // "MAILER-DAEMON@" alone, so the test can't accidentally pass merely
        // because the literal prefix matched regardless of resolution.
        $filter = new SpamFilter([['from' => 'MAILER-DAEMON@{list-domain}']], $this->logger());

        $matchingMail = new IncomingMail();
        $matchingMail->fromAddress = 'MAILER-DAEMON@example.org';
        $matchingMail->fromName = '';
        $this->assertSame('reject', $filter->match($matchingMail, $this->list()), '{list-domain} must resolve to example.org for this list');

        $nonMatchingMail = new IncomingMail();
        $nonMatchingMail->fromAddress = 'MAILER-DAEMON@some-other-domain.org';
        $nonMatchingMail->fromName = '';
        $this->assertNull($filter->match($nonMatchingMail, $this->list()), 'a different domain must not match — proves {list-domain} was actually substituted, not left as a literal wildcard-ish string');
    }

    public function testFromFieldChecksNameAndAddress(): void
    {
        $filter = new SpamFilter([['from' => 'phisher']], $this->logger());
        $mail = new IncomingMail();
        $mail->fromName = 'Totally Not A Phisher';
        $mail->fromAddress = 'a@example.org';

        $this->assertSame('reject', $filter->match($mail, $this->list()));
    }
}
