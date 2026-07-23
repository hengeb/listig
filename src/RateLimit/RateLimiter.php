<?php

declare(strict_types=1);

namespace Hengeb\Listig\RateLimit;

use PDO;

class RateLimiter
{
    public function __construct(
        private readonly PDO $db,
    ) {
    }

    public function isExceeded(string $listCn, string $sender, int $maxPerSender): bool
    {
        $stmt = $this->db->prepare(
            'SELECT COUNT(*) FROM rate_limit WHERE list_cn = :list AND sender = :sender AND sent_at > NOW() - INTERVAL 10 MINUTE'
        );
        $stmt->execute(['list' => $listCn, 'sender' => $sender]);
        $count = (int) $stmt->fetchColumn();

        if ($count >= $maxPerSender) {
            return true;
        }

        $this->record($listCn, $sender);
        return false;
    }

    public function isLoginExceeded(string $email): bool
    {
        // Per-address: max 5/hour
        $stmt = $this->db->prepare(
            "SELECT COUNT(*) FROM rate_limit WHERE list_cn = '__login__' AND sender = :email AND sent_at > NOW() - INTERVAL 1 HOUR"
        );
        $stmt->execute(['email' => $email]);
        if ((int) $stmt->fetchColumn() >= 5) {
            $this->record('__login__', $email);
            return true;
        }

        // Global: max 20/hour
        $stmt = $this->db->prepare(
            "SELECT COUNT(*) FROM rate_limit WHERE list_cn = '__login__' AND sender = '__global__' AND sent_at > NOW() - INTERVAL 1 HOUR"
        );
        $stmt->execute();
        if ((int) $stmt->fetchColumn() >= 20) {
            $this->record('__login__', $email);
            return true;
        }

        $this->record('__login__', $email);
        $this->record('__login__', '__global__');
        return false;
    }

    private function record(string $listCn, string $sender): void
    {
        $stmt = $this->db->prepare(
            'INSERT INTO rate_limit (list_cn, sender, sent_at) VALUES (:list, :sender, NOW())'
        );
        $stmt->execute(['list' => $listCn, 'sender' => $sender]);
    }
}
