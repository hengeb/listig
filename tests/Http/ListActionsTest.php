<?php

declare(strict_types=1);

namespace Hengeb\Listig\Tests\Http;

use Hengeb\Listig\Config\ListConfig;
use Hengeb\Listig\Http\ListActions;
use Hengeb\Listig\Member\InlineMemberResolver;
use Hengeb\Listig\Token\TokenService;
use PHPUnit\Framework\TestCase;

class ListActionsTest extends TestCase
{
    private function actions(): ListActions
    {
        return new ListActions(new TokenService(str_repeat('k', 32)), 'lists.example.org');
    }

    private function list(array $raw = []): ListConfig
    {
        return new ListConfig('news', 'news@example.org', $raw, new InlineMemberResolver(['m@example.org'], ['o@example.org']));
    }

    /** @return string[] */
    private function keys(\Hengeb\Listig\Http\ListNavigation $nav): array
    {
        return array_column($nav->items, 'key');
    }

    public function testOwnerSeesManageArchiveWriteAndComposeInOneRow(): void
    {
        $list = $this->list(['archive' => 'owners', 'reply-to' => 'masked-both', 'post-access-public' => 'allow']);
        $nav = $this->actions()->forViewer($list, ['email' => 'o@example.org']);
        $this->assertSame(['manage', 'archive', 'write', 'compose'], $this->keys($nav));
        $this->assertTrue($nav->canPost);
    }

    public function testMemberGetsInfoInsteadOfManageAndNoArchiveOfAnOwnersOnlyList(): void
    {
        $nav = $this->actions()->forViewer($this->list(['archive' => 'owners']), ['email' => 'm@example.org']);
        $this->assertSame(['info', 'write'], $this->keys($nav));
    }

    public function testWriteIsHiddenWhenPostingIsDenied(): void
    {
        $nav = $this->actions()->forViewer($this->list(['post-access-members' => 'deny']), ['email' => 'm@example.org']);
        $this->assertNotContains('write', $this->keys($nav));
        $this->assertFalse($nav->canPost);
    }

    public function testCurrentPageIsHighlightedButStillListed(): void
    {
        $nav = $this->actions()->forViewer($this->list(['archive' => 'members']), ['email' => 'm@example.org'], 'archive');
        $active = array_filter($nav->items, fn($i) => $i['active']);
        $this->assertSame(['archive'], array_column($active, 'key'));
        $this->assertContains('info', $this->keys($nav));
    }

    public function testArchiveContextRelabelsWriteAsNewTopic(): void
    {
        $nav = $this->actions()->forViewer($this->list(), ['email' => 'm@example.org'], 'archive', true);
        $write = array_values(array_filter($nav->items, fn($i) => $i['key'] === 'write'))[0];
        $this->assertSame('list.actions.new_topic', $write['label']);
        $this->assertSame('mailto:news@example.org', $write['href']);
    }

    public function testAnonymousViewerOfAPublicArchiveGetsOnlyWhatIsPublic(): void
    {
        $list = $this->list(['archive' => 'public', 'post-access-public' => 'allow']);
        $this->assertSame(['archive', 'write'], $this->keys($this->actions()->forViewer($list, null, 'archive', true)));
        $this->assertSame(['archive'], $this->keys($this->actions()->forViewer($this->list(['archive' => 'public']), null)));
    }

    public function testSubaddressListsOfferNoWriteButton(): void
    {
        $list = new ListConfig('news', 'news@example.org', ['post-access-public' => 'allow'], new InlineMemberResolver(['m@example.org'], []), ['{subaddress}@example.org']);
        $this->assertNotContains('write', $this->keys($this->actions()->forViewer($list, ['email' => 'm@example.org'])));
    }

    /** A member store that can persist a removal, so the Unsubscribe button is possible at all. */
    private function removableList(array $raw = [], bool $supportsAddition = false): ListConfig
    {
        $inline = new InlineMemberResolver(['m@example.org', 'o@example.org'], ['o@example.org']);
        $resolver = $this->createStub(\Hengeb\Listig\Member\MemberResolver::class);
        $resolver->method('getMembers')->willReturn($inline->getMembers('news'));
        $resolver->method('getOwners')->willReturn($inline->getOwners('news'));
        $resolver->method('supportsRemoval')->willReturn(true);
        $resolver->method('supportsAddition')->willReturn($supportsAddition);
        return new ListConfig('news', 'news@example.org', $raw + ['archive' => 'members'], $resolver);
    }

    public function testUnsubscribeIsOfferedOnEveryPageToAMemberAndAsksFirst(): void
    {
        $list = $this->removableList();
        $member = ['email' => 'm@example.org'];
        foreach ([['', false], ['info', false], ['archive', true], ['compose', false]] as [$page, $archiveContext]) {
            $nav = $this->actions()->forViewer($list, $member, $page, $archiveContext);
            $items = array_values(array_filter($nav->items, fn($i) => $i['key'] === 'unsubscribe'));
            $this->assertCount(1, $items, "page '$page'");
            $this->assertSame('list.actions.unsubscribe_confirm', $items[0]['confirm']['key'], 'unsubscribing asks first');
            $this->assertSame(['%list%' => 'news'], $items[0]['confirm']['params']);
        }
        $this->assertContains('unsubscribe', $this->keys($this->actions()->forViewer($list, ['email' => 'o@example.org'], 'manage')), 'an owner who is also a member');
        $this->assertNotContains('unsubscribe', $this->keys($this->actions()->forViewer($list, null)), 'guests have nothing to leave');
    }

    public function testLeavingNeedsNoConfirmationWhenOneCanJoinAgainRightAway(): void
    {
        $member = ['email' => 'm@example.org'];
        $confirm = function (array $raw, bool $canAdd) use ($member) {
            $nav = $this->actions()->forViewer($this->removableList($raw, $canAdd), $member, 'info');
            return array_values(array_filter($nav->items, fn($i) => $i['key'] === 'unsubscribe'))[0]['confirm'];
        };

        $this->assertNull($confirm(['join-policy' => 'open', 'visibility' => 'public'], true), 'open + public: undone with one click');
        $this->assertNotNull($confirm(['join-policy' => 'open', 'visibility' => 'public'], false), 'store cannot add members again');
        $this->assertNotNull($confirm(['join-policy' => 'open', 'visibility' => 'members'], true), 'a non-member would no longer see the list');
        $this->assertNotNull($confirm(['join-policy' => 'invite', 'visibility' => 'public'], true), 'only by invitation');
        $this->assertNotNull($confirm(['join-policy' => 'request', 'visibility' => 'public'], true), 'on request');
        $this->assertNotNull($confirm([], true), 'defaults: invite + members');
    }

    public function testJoinIsOfferedOnEveryPageToANonMemberOfAnOpenVisibleList(): void
    {
        $inline = new InlineMemberResolver(['m@example.org'], ['o@example.org']);
        $resolver = $this->createStub(\Hengeb\Listig\Member\MemberResolver::class);
        $resolver->method('getMembers')->willReturn($inline->getMembers('news'));
        $resolver->method('getOwners')->willReturn($inline->getOwners('news'));
        $resolver->method('supportsAddition')->willReturn(true);
        $list = new ListConfig('news', 'news@example.org', ['join-policy' => 'open', 'visibility' => 'public'], $resolver);

        foreach (['', 'info', 'archive'] as $page) {
            $nav = $this->actions()->forViewer($list, ['email' => 'x@example.com'], $page);
            $join = array_values(array_filter($nav->items, fn($i) => $i['key'] === 'join'));
            $this->assertCount(1, $join, "page '$page'");
            $this->assertTrue($join[0]['post']);
            $this->assertSame('/_/api/join/news', $join[0]['href']);
        }
        $this->assertNotContains('join', $this->keys($this->actions()->forViewer($list, ['email' => 'm@example.org'])), 'members have nothing to join');
        $this->assertNotContains('join', $this->keys($this->actions()->forViewer($list, null)), 'guests cannot join');
    }
}
