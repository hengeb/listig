<?php

declare(strict_types=1);

namespace Hengeb\Listig\Http\Controller;

use Hengeb\Listig\Provider\ListProvider;
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

        // Check owner access
        if (!$list->isOwnedBy($user['email'])) {
            return (new Response())->withStatus(403);
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
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
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
            'SELECT sender, subject, bounced_at FROM bounce_log WHERE list_cn = :list ORDER BY bounced_at DESC LIMIT 20'
        );
        $stmt->execute(['list' => $listName]);
        $recent = $stmt->fetchAll(PDO::FETCH_ASSOC);

        return array_merge($counts, ['recent' => $recent]);
    }
}
