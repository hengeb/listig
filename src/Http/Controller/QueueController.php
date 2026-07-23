<?php

declare(strict_types=1);

namespace Hengeb\Listig\Http\Controller;

use Hengeb\Listig\Provider\ListProvider;
use PDO;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Response;

class QueueController
{
    public function __construct(
        private readonly PDO $db,
        private readonly ListProvider $listProvider,
    ) {
    }

    public function status(ServerRequestInterface $request, ResponseInterface $response, array $args): ResponseInterface
    {
        $user = $request->getAttribute('user');
        $listName = $args['listname'];

        $list = $this->listProvider->getList($listName);
        if ($list === null || !$list->isOwnedBy($user['email'])) {
            return $this->json($response, ['error' => 'Forbidden'], 403);
        }

        $stmt = $this->db->prepare(
            "SELECT qr.id, qr.envelope_to, qr.status, qr.attempts, qr.error, qr.last_attempt_at
             FROM queue_recipients qr
             JOIN mail_queue mq ON mq.id = qr.mail_queue_id
             WHERE mq.list_cn = :list
             ORDER BY qr.last_attempt_at DESC"
        );
        $stmt->execute(['list' => $listName]);

        return $this->json($response, ['recipients' => $stmt->fetchAll(PDO::FETCH_ASSOC)]);
    }

    public function delete(ServerRequestInterface $request, ResponseInterface $response, array $args): ResponseInterface
    {
        $user = $request->getAttribute('user');
        $id = (int) $args['id'];

        $stmt = $this->db->prepare(
            'SELECT mq.list_cn FROM queue_recipients qr JOIN mail_queue mq ON mq.id = qr.mail_queue_id WHERE qr.id = :id'
        );
        $stmt->execute(['id' => $id]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$row) {
            return $this->json($response, ['error' => 'Not found'], 404);
        }

        $list = $this->listProvider->getList($row['list_cn']);
        if ($list === null || !$list->isOwnedBy($user['email'])) {
            return $this->json($response, ['error' => 'Forbidden'], 403);
        }

        $this->db->prepare('DELETE FROM queue_recipients WHERE id = :id')->execute(['id' => $id]);

        return $this->json($response, ['status' => 'deleted']);
    }

    public function retry(ServerRequestInterface $request, ResponseInterface $response, array $args): ResponseInterface
    {
        $user = $request->getAttribute('user');
        $id = (int) $args['id'];

        $stmt = $this->db->prepare(
            'SELECT mq.list_cn FROM queue_recipients qr JOIN mail_queue mq ON mq.id = qr.mail_queue_id WHERE qr.id = :id'
        );
        $stmt->execute(['id' => $id]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$row) {
            return $this->json($response, ['error' => 'Not found'], 404);
        }

        $list = $this->listProvider->getList($row['list_cn']);
        if ($list === null || !$list->isOwnedBy($user['email'])) {
            return $this->json($response, ['error' => 'Forbidden'], 403);
        }

        $this->db->prepare(
            "UPDATE queue_recipients SET status = 'pending', attempts = 0, error = NULL WHERE id = :id"
        )->execute(['id' => $id]);

        return $this->json($response, ['status' => 'queued']);
    }

    private function json(ResponseInterface $response, array $data, int $status = 200): ResponseInterface
    {
        $response->getBody()->write(json_encode($data));
        return $response->withStatus($status)->withHeader('Content-Type', 'application/json');
    }
}
