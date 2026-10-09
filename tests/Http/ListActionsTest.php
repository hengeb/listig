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
}
