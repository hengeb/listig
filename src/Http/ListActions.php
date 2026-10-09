<?php

declare(strict_types=1);

namespace Hengeb\Listig\Http;

use Hengeb\Listig\Config\Enum\AllowLeave;
use Hengeb\Listig\Config\ListConfig;
use Hengeb\Listig\Token\TokenService;

/**
 * The single place that decides which buttons a viewer sees for a list — Info/Manage,
 * Archive, Write, Mail to an external address, Unsubscribe — so the dashboard, the manage
 * and info pages and the archive pages all offer the same set (the current one highlighted)
 * instead of each page building its own, partly different, subset.
 */
final class ListActions
{
    public function __construct(
        private readonly TokenService $tokenService,
        private readonly string $hostname,
    ) {
    }

    /**
     * @param array{email: string}|null $user the session user, null for an anonymous viewer of a public archive
     * @param string $current key of the page being shown, highlighted: 'info', 'manage', 'archive' or '' (none)
     * @param bool $archiveContext label the write button "Start a new topic" — on the archive pages it is
     *     the counterpart of the per-mail "Reply" button
     */
    public function forViewer(ListConfig $list, ?array $user, string $current = '', bool $archiveContext = false): ListNavigation
    {
        $identity = $user['email'] ?? null;
        $items = [];
        $add = function (string $key, string $href, string $label, ?string $title = null) use (&$items, $current): void {
            $items[] = ['key' => $key, 'href' => $href, 'label' => $label, 'title' => $title, 'active' => $key === $current];
        };

        $isOwner = $identity !== null && $list->isOwnedBy($identity);
        if ($identity !== null) {
            $add($isOwner ? 'manage' : 'info', "/{$list->name}", $isOwner ? 'list.actions.manage' : 'list.actions.info');
        }
        if ($list->canViewArchive($identity)) {
            $add('archive', "/{$list->name}/archive", 'list.actions.archive');
        }
        $canPost = $list->canPost($identity);
        if ($canPost) {
            $add(
                'write',
                'mailto:' . $list->mail,
                $archiveContext ? 'list.actions.new_topic' : 'list.actions.write',
                $archiveContext ? 'list.actions.new_topic_title' : 'list.actions.write_title',
            );
        }
        if ($identity !== null && $list->canComposeExternal($identity)) {
            $add('compose', "/{$list->name}/compose", 'list.actions.compose_external');
        }
        if ($identity !== null && $list->isMember($identity) && $list->allowLeave === AllowLeave::Direct && $list->supportsUnsubscribe) {
            $member = $list->findMemberInList($identity);
            // 'u' — short token purpose code, see docs/architecture/security-and-tokens.md "Token Format".
            $token = $this->tokenService->sign('u', $list->name, $member?->attributes['username'] ?? $identity);
            $add('unsubscribe', "https://{$this->hostname}/{$list->name}/unsubscribe?token={$token}", 'list.actions.unsubscribe');
        }

        return new ListNavigation($items, $canPost);
    }
}
