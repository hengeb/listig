<?php

declare(strict_types=1);

namespace Hengeb\Listig\Http\Controller;

use Hengeb\Listig\Config\Enum\AllowLeave;
use Hengeb\Listig\Config\Enum\ArchiveMode;
use Hengeb\Listig\Config\ListConfig;
use Hengeb\Listig\Provider\ListProvider;
use Hengeb\Listig\Token\TokenService;
use Latte\Engine;
use PDO;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Response;
use Symfony\Contracts\Translation\TranslatorInterface;

class ListController
{
    public function __construct(
        private readonly Engine $latte,
        private readonly ListProvider $listProvider,
        private readonly PDO $db,
        private readonly TranslatorInterface $translator,
        private readonly TokenService $tokenService,
        private readonly string $hostname,
        private readonly string $appName,
    ) {
    }

    public function manage(ServerRequestInterface $request, ResponseInterface $response, array $args): ResponseInterface
    {
        $user = $request->getAttribute('user');
        $listName = $args['listname'];

        $list = $this->listProvider->getList($listName);
        if ($list === null) {
            return (new Response())->withStatus(404);
        }

        // {list-url} (https://{hostname}/{list-name}) is embedded in every
        // distributed mail's footer/subject-label, sent to every recipient — not
        // just owners — so a non-owner following that link must not get a bare
        // 403. Show the same reduced, public-safe info the dashboard already
        // shows for this list (name, description, archive link, unsubscribe)
        // instead; only the owner-only management details below this point
        // (moderation queue, delivery/bounce stats) require real ownership.
        if (!$list->isOwnedBy($user['email'])) {
            return $this->renderInfo($request, $response, $list);
        }

        $moderationItems = $this->getModerationItems($listName);
        $queueStatus = $this->getQueueStatus($listName);
        $bounceStats = $this->getBounceStats($listName);

        // This page is inherently about one specific list — set the translator's
        // locale to that list's language for the duration of this (final) render.
        // Safe: each request runs in a fresh container, no long-running worker.
        $this->translator->setLocale($list->language);

        $html = $this->latte->renderToString(__DIR__ . '/../../../templates/list/manage.latte', [
            'user' => $user,
            'list' => $list,
            'moderationItems' => $moderationItems,
            'queueStatus' => $queueStatus,
            'bounceStats' => $bounceStats,
            'memberCount' => count($list->getMembers()),
            'language' => $list->language,
            'translator' => $this->translator,
            'appName' => $this->appName,
        ]);

        $response->getBody()->write($html);
        return $response;
    }

    /**
     * Reduced view for anyone who reaches {list-url} without being an owner —
     * see the comment at its one call site in manage() above. Same building
     * blocks DashboardController::index() already shows for this exact list
     * when the viewer is a subscribed member; only the archive-link visibility
     * differs, since here the viewer might not be a member at all (e.g. a
     * former member revisiting an old mail's footer link after unsubscribing)
     * and 'members'-mode archives must stay hidden from a non-member.
     */
    private function renderInfo(ServerRequestInterface $request, ResponseInterface $response, ListConfig $list): ResponseInterface
    {
        $user = $request->getAttribute('user');
        $userEmail = $user['email'];
        $isMember = $list->isMember($userEmail);

        $showArchiveLink = $list->archive === ArchiveMode::Public
            || ($list->archive === ArchiveMode::Members && $isMember);

        $unsubscribeLink = null;
        if ($isMember && $list->allowLeave === AllowLeave::Direct && $list->supportsUnsubscribe) {
            $member = $list->findMemberInList($userEmail);
            $token = $this->tokenService->sign(
                'unsubscribe',
                $list->name,
                $member?->attributes['username'] ?? $userEmail,
            );
            $unsubscribeLink = "https://{$this->hostname}/{$list->name}/unsubscribe?token={$token}";
        }

        $this->translator->setLocale($list->language);

        $html = $this->latte->renderToString(__DIR__ . '/../../../templates/list/index.latte', [
            'user' => $user,
            'list' => $list,
            'showArchiveLink' => $showArchiveLink,
            'unsubscribeLink' => $unsubscribeLink,
            'language' => $list->language,
            'translator' => $this->translator,
            'appName' => $this->appName,
        ]);

        $response->getBody()->write($html);
        return $response;
    }

    private function getModerationItems(string $listName): array
    {
        $stmt = $this->db->prepare(
            'SELECT * FROM moderation_queue WHERE list_cn = :list ORDER BY created_at DESC'
        );
        $stmt->execute(['list' => $listName]);
        $items = $stmt->fetchAll(PDO::FETCH_ASSOC);

        foreach ($items as &$item) {
            // "Name <mail>", or just the bare address when the sender set no
            // display name — computed here, not in the template, both to match
            // ModerationMailer's identical %sender% formatting for the request
            // mail and because embedding literal '<'/'>' inside a Latte {...}
            // expression confuses its tag parser (confirmed live — it silently
            // mangles the output instead of erroring).
            $senderName = $item['sender_name'] ?? '';
            $item['sender_display'] = $senderName !== '' ? "{$senderName} <{$item['sender_mail']}>" : ($item['sender_mail'] ?? '');
        }

        return $items;
    }

    private function getQueueStatus(string $listName): array
    {
        $stmt = $this->db->prepare(
            "SELECT
                COUNT(CASE WHEN qr.status = 'sent' THEN 1 END) as sent,
                COUNT(CASE WHEN qr.status = 'failed' THEN 1 END) as failed,
                COUNT(*) as total
             FROM queue_recipients qr
             JOIN mail_queue mq ON mq.id = qr.mail_queue_id
             WHERE mq.list_cn = :list"
        );
        $stmt->execute(['list' => $listName]);
        return $stmt->fetch(PDO::FETCH_ASSOC) ?: ['sent' => 0, 'failed' => 0, 'total' => 0];
    }

    private function getBounceStats(string $listName): array
    {
        $stmt = $this->db->prepare(
            "SELECT
                COUNT(CASE WHEN bounced_at > NOW() - INTERVAL 7 DAY THEN 1 END) as last7,
                COUNT(CASE WHEN bounced_at > NOW() - INTERVAL 30 DAY THEN 1 END) as last30
             FROM bounce_log WHERE list_cn = :list"
        );
        $stmt->execute(['list' => $listName]);
        $counts = $stmt->fetch(PDO::FETCH_ASSOC) ?: ['last7' => 0, 'last30' => 0];

        $stmt = $this->db->prepare(
            'SELECT id, sender, subject, message_id, bounced_at FROM bounce_log WHERE list_cn = :list ORDER BY bounced_at DESC LIMIT 20'
        );
        $stmt->execute(['list' => $listName]);
        $recent = $stmt->fetchAll(PDO::FETCH_ASSOC);

        return array_merge($counts, ['recent' => $recent]);
    }
}
