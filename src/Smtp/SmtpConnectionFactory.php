<?php

declare(strict_types=1);

namespace Hengeb\Listig\Smtp;

use Hengeb\Listig\Config\ListConfig;
use Hengeb\Listig\Crypto\PasswordCrypto;
use Symfony\Component\Mailer\Transport;
use Symfony\Component\Mailer\Transport\TransportInterface;

class SmtpConnectionFactory
{
    /** @var array<string, TransportInterface> */
    private array $cache = [];
    private string $currentFingerprint = '';

    public function __construct(
        private readonly PasswordCrypto $passwordCrypto,
    ) {
    }

    public function getTransport(ListConfig $list): TransportInterface
    {
        $fingerprint = $this->fingerprint($list);

        if (isset($this->cache[$fingerprint])) {
            return $this->cache[$fingerprint];
        }

        // Close previously cached connection if fingerprint changed
        if ($this->currentFingerprint !== '' && $this->currentFingerprint !== $fingerprint) {
            $old = $this->cache[$this->currentFingerprint] ?? null;
            if ($old !== null) {
                unset($this->cache[$this->currentFingerprint]);
            }
        }

        $dsn = $this->buildDsn($list);
        $transport = Transport::fromDsn($dsn);

        $this->cache[$fingerprint] = $transport;
        $this->currentFingerprint = $fingerprint;

        return $transport;
    }

    private function fingerprint(ListConfig $list): string
    {
        return hash('sha256', implode(':', [
            $list->smtpHost,
            $list->smtpPort,
            $list->smtpUser,
            $list->smtpSecure,
        ]));
    }

    private function buildDsn(ListConfig $list): string
    {
        $scheme = match ($list->smtpSecure) {
            'ssl' => 'smtps',
            'none' => 'smtp',
            default => 'smtp',
        };

        $user = rawurlencode($list->smtpUser);
        $pass = rawurlencode($this->passwordCrypto->decryptIfEncrypted($list->smtpPassword));
        $host = $list->smtpHost;
        $port = $list->smtpPort;

        $query = $list->smtpSecure === 'tls' ? '?verify_peer=false&encryption=tls' : '';

        return "{$scheme}://{$user}:{$pass}@{$host}:{$port}{$query}";
    }
}
