<?php

declare(strict_types=1);

namespace Hengeb\Listig\Tests\Config;

use Hengeb\Listig\Config\Enum\AllowLeave;
use Hengeb\Listig\Config\Enum\ArchiveMode;
use Hengeb\Listig\Config\Enum\PostAccess;
use Hengeb\Listig\Config\Enum\ReplyToBehavior;
use Hengeb\Listig\Config\Enum\SenderAddressHeader;
use Hengeb\Listig\Config\ListConfig;
use Hengeb\Listig\Config\RestrictionList;
use Hengeb\Listig\Member\InlineMemberResolver;
use Hengeb\Listig\Member\Member;
use PHPUnit\Framework\TestCase;

class ListConfigTest extends TestCase
{
    private function list(array $raw = [], $memberResolver = new \Hengeb\Listig\Member\NullMemberResolver(), ?RestrictionList $restrictions = null): ListConfig
    {
        return new ListConfig(
            'mylist',
            'mylist@example.org',
            $raw,
            $memberResolver,
            restrictions: $restrictions ?? new RestrictionList([]),
        );
    }

    // --- Name validation ---

    public function testReservedNameThrows(): void
    {
        $this->expectException(\RuntimeException::class);
        new ListConfig('_', 'x@example.org', []);
    }

    public function testInvalidCharacterInNameThrows(): void
    {
        // Rules out e.g. "news.php", which would silently 404 at the nginx layer.
        $this->expectException(\RuntimeException::class);
        new ListConfig('news.php', 'x@example.org', []);
    }

    public function testValidNameWithHyphenAndUnderscoreIsAccepted(): void
    {
        $list = new ListConfig('my-list_1', 'x@example.org', []);
        $this->assertSame('my-list_1', $list->name);
    }

    // --- Enum defaults ---

    public function testDefaults(): void
    {
        $list = $this->list();
        $this->assertSame(ReplyToBehavior::List, $list->replyTo);
        $this->assertSame(PostAccess::Allow, $list->postAccessMembers);
        $this->assertSame(PostAccess::Deny, $list->postAccessPublic);
        $this->assertSame(AllowLeave::Direct, $list->allowLeave);
        $this->assertSame(ArchiveMode::Off, $list->archive);
        $this->assertSame('Archive', $list->archiveFolder);
        $this->assertSame('en', $list->language);
    }

    public function testEnumOverrides(): void
    {
        $list = $this->list([
            'reply-to' => 'both',
            'post-access-members' => 'moderate',
            'post-access-public' => 'allow',
            'allow-leave' => 'moderated',
            'archive' => 'public',
        ]);
        $this->assertSame(ReplyToBehavior::Both, $list->replyTo);
        $this->assertSame(PostAccess::Moderate, $list->postAccessMembers);
        $this->assertSame(PostAccess::Allow, $list->postAccessPublic);
        $this->assertSame(AllowLeave::Moderated, $list->allowLeave);
        $this->assertSame(ArchiveMode::Public, $list->archive);
    }

    // --- Domain / local part ---

    public function testDomainAndLocalPartDerivedFromMail(): void
    {
        $list = new ListConfig('it', 'it@example.org', []);
        $this->assertSame('example.org', $list->domain);
        $this->assertSame('it', $list->localPart);
    }

    // --- max-size parsing ---

    public function testMaxSizeDefaultIs5Megabytes(): void
    {
        $this->assertSame(5_000_000, $this->list()->maxSize);
    }

    public function testMaxSizeParsesMebibytes(): void
    {
        $this->assertSame(5 * 1_048_576, $this->list(['max-size' => '5MiB'])->maxSize);
    }

    public function testMaxSizeParsesPlainMegabytes(): void
    {
        $this->assertSame(10_000_000, $this->list(['max-size' => '10MB'])->maxSize);
    }

    public function testMaxSizeParsesKilobytes(): void
    {
        $this->assertSame(500_000, $this->list(['max-size' => '500K'])->maxSize);
    }

    public function testMaxSizeParsesGigabytes(): void
    {
        $this->assertSame(1_000_000_000, $this->list(['max-size' => '1G'])->maxSize);
    }

    // --- archive-max-age ---

    public function testArchiveMaxAgeDefaultsToNullUnboundedRetention(): void
    {
        $list = $this->list();
        $this->assertNull($list->archiveMaxAge);
        $this->assertNull($list->archiveMaxAgeCutoff);
    }

    public function testArchiveMaxAgeExposesRawStringAndParsedCutoff(): void
    {
        $list = $this->list(['archive-max-age' => '30 days']);
        $this->assertSame('30 days', $list->archiveMaxAge);
        $cutoff = $list->archiveMaxAgeCutoff;
        $this->assertInstanceOf(\DateTimeImmutable::class, $cutoff);
        $diffDays = (new \DateTimeImmutable())->diff($cutoff)->days;
        $this->assertGreaterThanOrEqual(29, $diffDays);
        $this->assertLessThanOrEqual(30, $diffDays);
    }

    public function testArchiveMaxAgeInvalidValueThrows(): void
    {
        $list = $this->list(['archive-max-age' => 'not a real duration!!']);
        $this->expectException(\RuntimeException::class);
        $list->archiveMaxAgeCutoff;
    }

    // --- personalizeKeys ---

    public function testPersonalizeKeysDefaultsToJustListUrl(): void
    {
        $this->assertSame(['list-url'], $this->list()->personalizeKeys);
    }

    public function testPersonalizeKeysOffIsSameAsUnset(): void
    {
        $this->assertSame(['list-url'], $this->list(['personalize' => 'off'])->personalizeKeys);
    }

    public function testPersonalizeKeysParsesCommaSeparatedList(): void
    {
        $keys = $this->list(['personalize' => 'firstname, pronoun'])->personalizeKeys;
        $this->assertSame(['list-url', 'firstname', 'pronoun'], $keys);
    }

    // --- splitCommaList ---

    public function testSplitCommaListSplitsOnCommasAndWhitespace(): void
    {
        $this->assertSame(['a', 'b', 'c'], ListConfig::splitCommaList('a, b  c'));
    }

    public function testSplitCommaListOnEmptyStringReturnsEmptyArray(): void
    {
        $this->assertSame([], ListConfig::splitCommaList('   '));
    }

    // --- authorizedSenders / senders: ---

    public function testAuthorizedSendersFromPlainArray(): void
    {
        $list = $this->list(['senders' => ['chair@example.org']]);
        $this->assertTrue($list->isAuthorizedSender('chair@example.org'));
        $this->assertFalse($list->isAuthorizedSender('nobody@example.org'));
    }

    public function testAuthorizedSendersFromCommaSeparatedString(): void
    {
        // The shape an LDAP description[] entry produces.
        $list = $this->list(['senders' => 'a@example.org, b@example.org']);
        $this->assertTrue($list->isAuthorizedSender('a@example.org'));
        $this->assertTrue($list->isAuthorizedSender('b@example.org'));
    }

    public function testFindAuthorizedSenderReturnsTheMember(): void
    {
        $list = $this->list(['senders' => [['mail' => 'chair@example.org', 'firstname' => 'Chair']]]);
        $found = $list->findAuthorizedSender('chair@example.org');
        $this->assertSame('Chair', $found?->attributes['firstname']);
    }

    // --- isMember / isOwnedBy / mail-aliases ---

    public function testIsMemberAndIsOwnedByDelegateToMemberResolver(): void
    {
        $resolver = new InlineMemberResolver(['alice@example.org'], ['bob@example.org']);
        $list = $this->list([], $resolver);
        $this->assertTrue($list->isMember('alice@example.org'));
        $this->assertFalse($list->isMember('bob@example.org'));
        $this->assertTrue($list->isOwnedBy('bob@example.org'));
        $this->assertFalse($list->isOwnedBy('alice@example.org'));
    }

    public function testIsMemberRecognizesMailAliases(): void
    {
        $resolver = new InlineMemberResolver([['mail' => 'bob@example.org', 'mail-aliases' => ['alt@example.org']]], []);
        $list = $this->list([], $resolver);
        $this->assertTrue($list->isMember('alt@example.org'), 'a member writing from a secondary address must still be recognized');
    }

    // --- restrictions ---

    public function testSenderRestrictionDelegatesToRestrictionListForThisListName(): void
    {
        $restrictions = new RestrictionList([['mail' => 'blocked@x.org']]);
        $list = $this->list([], restrictions: $restrictions);
        $this->assertTrue($list->isSenderRestricted('blocked@x.org'));
        $this->assertFalse($list->isSenderRestricted('other@x.org'));
    }

    public function testReceiverRestrictionRequiresReceiveFalse(): void
    {
        $restrictions = new RestrictionList([['mail' => 'blocked@x.org', 'receive' => false]]);
        $list = $this->list([], restrictions: $restrictions);
        $this->assertTrue($list->isReceiverRestricted('blocked@x.org'));
    }

    // --- resolveMemberDisplayName ---

    public function testResolveMemberDisplayNameUsesFirstnameLastnameAlias(): void
    {
        $list = $this->list(['firstname' => '{givenName}', 'lastname' => '{sn}']);
        $member = new Member('alice@example.org', ['givenName' => 'Alice', 'sn' => 'Wonder']);
        $this->assertSame('Alice Wonder', $list->resolveMemberDisplayName($member));
    }

    public function testResolveMemberDisplayNameFallsBackToEmailWhenNoNameAvailable(): void
    {
        $list = $this->list();
        $member = new Member('bare@example.org', []);
        $this->assertSame('bare@example.org', $list->resolveMemberDisplayName($member));
    }

    public function testResolveMemberDisplayNamePrefersMembersOwnAttributeOverListAlias(): void
    {
        $list = $this->list(['firstname' => '{businessCategory}']);
        $member = new Member('alice@example.org', ['firstname' => 'DirectValue']);
        $this->assertStringContainsString('DirectValue', $list->resolveMemberDisplayName($member));
    }

    // --- createContext basics ---

    public function testCreateContextExposesComputedListVariables(): void
    {
        $list = $this->list(['hostname' => 'lists.example.org']);
        $context = $list->createContext();
        $this->assertSame('mylist', $context['list-name']);
        $this->assertSame('mylist@example.org', $context['list-mail']);
        $this->assertSame('example.org', $context['list-domain']);
        $this->assertSame('https://lists.example.org/mylist', $context['list-url']);
    }

    public function testCreateContextDisplayNameFallsBackToListName(): void
    {
        $context = $this->list()->createContext();
        $this->assertSame('mylist', $context['display-name']);
    }

    // --- supportsUnsubscribe ---

    public function testSupportsUnsubscribePassesThroughToMemberResolver(): void
    {
        // NullMemberResolver never supports removal.
        $list = $this->list();
        $this->assertFalse($list->supportsUnsubscribe);
    }

    public function testMaskedReplyToModes(): void
    {
        $list = new ListConfig('mylist', 'mylist@example.org', ['reply-to' => 'masked-both']);
        $this->assertSame(ReplyToBehavior::MaskedBoth, $list->replyTo);
        $this->assertTrue($list->replyTo->isMasked());
        $this->assertFalse(ReplyToBehavior::Both->isMasked());
    }

    public function testSenderAddressHeaderDefaultsToNever(): void
    {
        $this->assertSame(SenderAddressHeader::Never, $this->list()->senderAddressHeader);
        $list = new ListConfig('mylist', 'mylist@example.org', ['sender-address-header' => 'external']);
        $this->assertSame(SenderAddressHeader::External, $list->senderAddressHeader);
    }

    public function testCanComposeExternal(): void
    {
        $resolver = new \Hengeb\Listig\Member\InlineMemberResolver(['m@example.org'], ['o@example.org']);
        $make = fn(array $raw) => new ListConfig('mylist', 'mylist@example.org', $raw, $resolver);

        // needs a masked mode
        $this->assertFalse($make(['reply-to' => 'both', 'post-access-public' => 'allow'])->canComposeExternal('m@example.org'));
        // needs post-access-public != deny (default)
        $this->assertFalse($make(['reply-to' => 'masked-both'])->canComposeExternal('m@example.org'));

        $both = $make(['reply-to' => 'masked-both', 'post-access-public' => 'moderate', 'post-access-members' => 'deny']);
        $this->assertFalse($both->canComposeExternal('m@example.org'));
        $this->assertTrue($both->canComposeExternal('o@example.org'));
        $this->assertFalse($both->canComposeExternal('stranger@example.org'));

        // masked-sender: members may even with post-access-members: deny
        $sender = $make(['reply-to' => 'masked-sender', 'post-access-public' => 'allow', 'post-access-members' => 'deny']);
        $this->assertTrue($sender->canComposeExternal('m@example.org'));
    }

    public function testSenderNoticeKeys(): void
    {
        $list = new ListConfig('mylist', 'mylist@example.org', []);
        $this->assertSame(\Hengeb\Listig\Config\Enum\SenderNotices::Authenticated, $list->senderNotices);
        $this->assertSame(3600, $list->senderNoticeInterval);

        $list = new ListConfig('mylist', 'mylist@example.org', [
            'sender-notices' => 'never',
            'sender-notice-interval' => '30 minutes',
        ]);
        $this->assertSame(\Hengeb\Listig\Config\Enum\SenderNotices::Never, $list->senderNotices);
        $this->assertSame(1800, $list->senderNoticeInterval);
        $this->assertSame(0, (new ListConfig('l', 'l@example.org', ['sender-notice-interval' => '0']))->senderNoticeInterval);
    }

    public function testInvalidSenderNoticeIntervalFailsFast(): void
    {
        $this->expectException(\RuntimeException::class);
        (new ListConfig('l', 'l@example.org', ['sender-notice-interval' => 'soon']))->senderNoticeInterval;
    }

    public function testTooLargeSenderNoticeIntervalFailsFast(): void
    {
        $this->expectException(\RuntimeException::class);
        (new ListConfig('l', 'l@example.org', ['sender-notice-interval' => '2 days']))->senderNoticeInterval;
    }

    public function testTrustedAuthservIdAcceptsStringCommaListAndYamlList(): void
    {
        $make = fn(array $raw) => (new ListConfig('l', 'l@example.org', $raw))->trustedAuthservIds;
        $this->assertSame([], $make([]));
        $this->assertSame([], $make(['trusted-authserv-id' => '']));
        $this->assertSame(['mx.example.org'], $make(['trusted-authserv-id' => 'MX.example.org']));
        $this->assertSame(['a.example', 'b.example'], $make(['trusted-authserv-id' => 'a.example, B.example']));
        $this->assertSame(['a.example', 'b.example'], $make(['trusted-authserv-id' => ['a.example', 'b.example', 'A.example']]));
    }
}
