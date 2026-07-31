<?php

declare(strict_types=1);

namespace Hengeb\Listig\Http\Controller;

use Hengeb\Listig\Archive\ArchiveIndexer;
use Hengeb\Listig\Imap\ImapArchiver;
use Hengeb\Listig\Imap\ImapPoller;
use Hengeb\Listig\Mail\IncomingMailFilter;
use Hengeb\Listig\Mail\MailProcessor;
use Hengeb\Listig\Mail\RejectionNotifier;
use Hengeb\Listig\Provider\ListProvider;
use PDO;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Response;

class ModerationController
{
    public function __construct(
        private readonly PDO $db,
        private readonly ListProvider $listProvider,
        private readonly MailProcessor $mailProcessor,
        private readonly ImapPoller $imapPoller,
        private readonly ImapArchiver $imapArchiver,
        private readonly ArchiveIndexer $archiveIndexer,
        private readonly RejectionNotifier $rejectionNotifier,
    ) {
    }

    public function accept(ServerRequestInterface $request, ResponseInterface $response, array $args): ResponseInterface
    {
        return $this->handle($request, $response, (int) $args['id'], 'accept');
    }

    public function reject(ServerRequestInterface $request, ResponseInterface $response, array $args): ResponseInterface
    {
        return $this->handle($request, $response, (int) $args['id'], 'reject');
    }

    private function handle(ServerRequestInterface $request, ResponseInterface $response, int $id, string $action): ResponseInterface
    {
        $user = $request->getAttribute('user');

        $stmt = $this->db->prepare('SELECT * FROM moderation_queue WHERE id = :id');
        $stmt->execute(['id' => $id]);
        $item = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$item) {
            return $this->json($response, ['error' => 'Not found'], 404);
        }

        $list = $this->listProvider->getList($item['list_cn']);
        if ($list === null) {
            return $this->json($response, ['error' => 'List not found'], 404);
        }

        // Check owner
        if (!$list->isOwnedBy($user['email'])) {
            return $this->json($response, ['error' => 'Forbidden'], 403);
        }

        $uid         = (int) $item['imap_uid'];
        $uidValidity = (int) $item['imap_uidvalidity'];

        if ($action === 'accept') {
            $incomingMail = $this->imapPoller->fetchMailByUid($list, $uid);
            $rawMime      = $this->imapPoller->fetchByUid($list, $uid);

            if ($incomingMail === null || $rawMime === null) {
                $this->db->prepare('DELETE FROM moderation_queue WHERE id = :id')->execute(['id' => $id]);
                return $this->json($response, ['error' => 'Original mail not found in IMAP'], 410);
            }

            $this->mailProcessor->process($incomingMail, $rawMime, $list);
            $this->imapPoller->markSeen($list, $uid, $uidValidity);
            $this->imapArchiver->archiveOrDelete($list, $uid);
            $this->archiveIndexer->index($list, $incomingMail);
        } else {
            // Mirrors ModerationResponseHandler::processReject() (the mail-reply
            // path) — a reject via the manage-page button must notify the sender
            // and clear the mail out of the inbox the same way, not just drop the
            // moderation_queue row.
            $incomingMail = $this->imapPoller->fetchMailByUid($list, $uid);
            if ($incomingMail !== null) {
                $this->rejectionNotifier->notify($list, $incomingMail->fromAddress ?? '', 'reject.moderation_declined');
                $this->imapPoller->markSeen($list, $uid, $uidValidity);
                $this->imapArchiver->archiveOrDelete($list, $uid);
            }
        }

        $this->db->prepare('DELETE FROM moderation_queue WHERE id = :id')->execute(['id' => $id]);

        return $this->json($response, ['status' => 'ok']);
    }

    private function json(ResponseInterface $response, array $data, int $status = 200): ResponseInterface
    {
        $response->getBody()->write(json_encode($data));
        return $response->withStatus($status)->withHeader('Content-Type', 'application/json');
    }
}
