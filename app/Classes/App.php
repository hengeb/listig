<?php
declare(strict_types=1);

namespace Hengeb\Listig;

use Symfony\Component\Yaml\Yaml;
use Predis\Client as RedisClient;
use Symfony\Component\Ldap\Ldap;
use Symfony\Component\Ldap\Exception\InvalidCredentialsException;
use Symfony\Component\Ldap\Entry as LdapEntry;
use PHPMailer\PHPMailer\PHPMailer;
use PhpImap\Mailbox;

class App {
    private array $configuration = [];

    private ?RedisClient $redis = null;
    private ?Ldap $ldapClient = null;

    function __construct(string $configfile)
    {
        $configuration = Yaml::parse(file_get_contents($configfile));

        // replace environment variables
        array_walk_recursive($configuration, function(&$value) {
            if (!is_string($value)) {
                return;
            }
            $value = preg_replace_callback('/\{\$([A-Z_]+)\}|\$([A-Z_]+)/', fn($m) => getenv($m[1] ?: $m[2]) ?: $m[0], $value);
        });

        $this->configuration = $configuration;

        $this->initRedis();
    }

    private function initRedis(): void
    {
        $config = [...[
            'host' => 'localhost',
            'port' => 6379,
        ], ...($this->configuration['redis'] ?? [])];

        $this->redis = new RedisClient($config);
    }

    public function run(): void
    {
        $lists = $this->getListsFromLdap($this->configuration['ldap']);

        foreach ($lists as $list) {
            $this->processList($list, $this->configuration['mail'] ?? []);
        }
    }

    private function getListsFromLdap(array $ldapConfig): array
    {
        // apply defaults
        $config = [...[
            'host' => 'localhost',
            'port' => 389,
            'filter' => '(objectClass=*)',
            'userFilter' => '(objectClass=*)',
        ], ...$ldapConfig];

        $this->ldap = Ldap::create('ext_ldap', [
            'host' => $config['host'],
            'port' => $config['port']
        ]);

        $this->ldap->bind($config['bind-dn'], $config['bind-password']);

        $lists = [];

        $listsEntries = $this->ldap->query($ldapConfig['dn'], $ldapConfig['filter'])->execute();
        foreach ($listsEntries as $listEntry) {
            $listName = $listEntry->getAttribute('cn')[0];
            $lists[$listName] = [
                'name' => $listName,
                'mail' => $mail = $listEntry->getAttribute('mail')[0],
                'domain' => preg_replace('/^.*@/', '', $mail),
                'owners' => array_map(
                    fn($ownerDn) => $this->ldap->query($ownerDn, $ldapConfig['userFilter'])->execute()[0]->getAttribute('mail')[0],
                    $listEntry->getAttribute('owner')
                ),
                'members' => [],
            ];

            foreach ($listEntry->getAttribute('member') as $memberDn) {
                if ($memberDn === $ldapConfig['bind-dn']) {
                    continue;
                }
                try {
                    $userEntry = $this->ldap->query($memberDn, $ldapConfig['userFilter'])->execute()[0];
                } catch (\Exception $e) {
                    continue;
                }
                $lists[$listName]['members'][] = $userEntry->getAttribute('mail')[0];
            }
        }

        return $lists;
    }

    private function parseMailConfig(array $list, array $mailConfig): array
    {
        // set defaults
        $config = [...[
            'type' => 'imap',
            'host' => '{domain}',
            'folder' => 'INBOX',
            'user' => '{mail}',
            'secure' => 'ssl',
            'imap-host' => '{host}',
            'imap-user' => '{user}',
            'imap-secure' => '{secure}',
            'imap-port' => null,
            'smtp-host' => '{host}',
            'smtp-port' => null,
            'smtp-user' => '{user}',
            'smtp-secure' => '{secure}',
        ], ...$mailConfig];

        $config = $this->replaceConfigVariables($config, $list);

        if ($config['type'] !== 'imap'
            || !in_array($config['imap-secure'], ['ssl', 'tls'], true)
            || !in_array($config['smtp-secure'], ['ssl'], true)
        ) {
            throw new \UnexpectedValueException('not implemented');
        }

        $config['imap-port'] = $config['imap-port'] ?: match($config['imap-secure']) {
            'ssl' => 993,
            'tls' => 143,
        };
        $config['smtp-port'] = $config['smtp-port'] ?: match($config['smtp-secure']) {
            'ssl' => 465,
        };

        return $config;
    }

    private function replaceConfigVariables(array $config, array ...$contexts): array
    {
        $contexts[] = $this->configuration;

        foreach ($config as &$setting) {
            if (!is_string($setting)) {
                continue;
            }
            $setting = preg_replace_callback('/\{([a-z_-]+)\}/', function($m) use ($config, $contexts) {
                if (!empty($config[$m[1]]) && !is_array($config[$m[1]])) {
                    return $config[$m[1]];
                }
                foreach ($contexts as &$context) {
                    if (!empty($context[$m[1]]) && !is_array($context[$m[1]])) {
                        return $context[$m[1]];
                    }
                }
                return $m[0];
            }, $setting);
        }

        return $config;
    }

    private function processList(array $list, array $mailConfig): void
    {
        if (!$list['members']) {
            return;
        }

        $config = $this->parseMailConfig($list, $mailConfig);

        $password = $this->redis->get(strtolower($list['mail']));
        if (!$password) {
            echo "missing password for {$list['mail']}\n";
            return;
        }

        $inbox = new Mailbox(
            "{{$config['imap-host']}:{$config['imap-port']}/imap/{$config['imap-secure']}}{$config['folder']}",
            $config['imap-user'],
            $password
        );

         // expunge deleted mails upon mailbox close
        $inbox->setConnectionArgs(CL_EXPUNGE, 0, []);

        try {
            $mailsIds = $inbox->searchMailbox('ALL');
        } catch(\PhpImap\Exceptions\ConnectionException $ex) {
            echo "IMAP connection for {$list['mail']} failed: " . $ex->getMessage() . "\n";
            return;
        }

        if (!$mailsIds) {
            return;
        }

        $outbox = new PHPMailer();
        $outbox->isSMTP();
        $outbox->Host = $config['smtp-host'];
        $outbox->Port = $config['smtp-port'];
        $outbox->SMTPAuth = true;
        $outbox->SMTPSecure = $config['smtp-secure'];
        $outbox->CharSet = "UTF-8";
        $outbox->AllowEmpty = true;

        $outbox->Username = $config['smtp-user'];
        $outbox->Password = $password;

        foreach ($mailsIds as $mailId) {
            $mail = $inbox->getMail($mailId);
            $reportToOwners = false;

            $outbox->setFrom($list['mail'], $mail->senderName);
            $outbox->Subject = $mail->subject;
            $outbox->MessageID = $mail->messageId;
            $outbox->MessageDate = $mail->headers->date;

            $customHeaders = $this->getCustomHeaders($mail, $inbox, $list);

            if (in_array(['Auto-Submitted', 'auto-replied'], $customHeaders, true)) {
                $reportToOwners = true;
            }

            if (!in_array('Reply-To', array_column($customHeaders, 0))) {
                $outbox->addReplyTo($mail->senderAddress, $mail->senderName);
            }

            $this->copyBody($mail, $outbox);
            $this->copyAttachments($mail, $outbox);

            $recipientAddresses = $reportToOwners ? $list['owners'] : $list['members'];
            $isSent = false;
            foreach ($recipientAddresses as $recipientAddress) {
                $outbox->clearAddresses();
                $outbox->addAddress($recipientAddress, $recipientAddress);

                $outbox->clearCustomHeaders();
                foreach ($customHeaders as [$headerName, $headerValue]) {
                    $outbox->addCustomHeader($headerName, $headerValue);
                }
                $outbox->addCustomHeader('X-Forwarded-For', $recipientAddress);

                if ($outbox->send()) {
                    $isSent = true;
                } else {
                    echo $outbox->ErrorInfo . "\n";
                }
            }

            // message could be sent at least to one recipient
            if ($isSent) {
                $inbox->deleteMail($mailId);
            }
        }
    }

    private function getCustomHeaders(\PhpImap\IncomingMail $mail, \PhpImap\Mailbox $inbox, array $list): array
    {
        $customHeaders = [
            ['X-Forwarded-From', $mail->senderAddress],
        ];

        $headers = $this->parseHeaders($mail->headersRaw, $inbox);
        foreach ($headers as [$headerName, $headerValue]) {
            if ($headerName === 'To') {
                $headerName = 'X-Original-To';
            }

            // ignore headers that are handled elsewhere or shall not be copied
            if (in_array($headerName, [
                'Subject',
                'From',
                'Message-ID',
                'Content-Type',
                'MIME-Version',
                'Date',
                'X-Received',
                'Received-Spf',
                'Return-Path',
                'Delivered-To',
                'Authentication-Results',
                'Dkim-Signature',
                'Content-Transfer-Encoding',
                'X-Gm-Message-State',
                'X-Ppp-Message-Id',
                'X-Ppp-Vhost',
                'X-Originating-Ip',
                'X-Recommended-Action',
                'X-Filter-Id',
            ], true)
            || str_starts_with($headerName, 'X-Spam')
            || str_starts_with($headerName, 'X-Google-')
            || str_starts_with($headerName, 'Arc-')
            ) {
                continue;
            }

            if (!in_array($headerName, [
                'Received',
                'Cc',
                'X-No-Archive',
                'Mailing-List',
                'Sender',
                'X-Course-Id',
                'X-Course-Name',
                'Precedence',
                'X-Auto-Response-Suppress',
                'Auto-Submitted',
                'Thread-Topic',
                'Thread-Index',
                'In-Reply-To',
                'Reply-To',
                'Auto-Submitted',
                'X-Forwarded-Message-Id',
                'References',
                'Comments',
                'Keywords',
                'Disposition-Notification-To',
                'Disposition-Notification-Options',
                'Accept-Language',
                'Original-Message-Id',
                'Content-Language',
                'User-Agent',
                'X-Original-From',
                'X-Original-Sender',
                'X-Original-To',
                'X-Report-Abuse-To',
                'X-Mailer',
            ], true)
            && !str_starts_with($headerName, 'List-')
            ) {
                echo "copy unknown header: $headerName: $headerValue\n";
            }

            $customHeaders[] = [$headerName, $headerValue];
        }

        if (!in_array('X-Original-From', array_column($customHeaders, 0))) {
            $customHeaders[] = ['X-Original-From', $mail->senderAddress];
        }
        if (!in_array('X-Original-Sender', array_column($customHeaders, 0))) {
            $customHeaders[] = ['X-Original-Sender', $mail->senderAddress];
        }
        if (!in_array('List-Id', array_column($customHeaders, 0))) {
            $customHeaders[] = ['List-Id', '<' . $list['mail'] . '>'];
            $customHeaders[] = ['List-Post', '<mailto:' . $list['mail'] . '>'];
            $customHeaders[] = ['Sender', '<' . $list['mail'] . '>'];
            // TODO unsubscribe...
        }

        return $customHeaders;
    }

    private function parseHeaders(string $header, \PhpImap\Mailbox $inbox): array
    {
        $header = str_replace("\r\n", "\n", trim($header));
        $header = str_replace("\n ", " ", $header);
        $header = str_replace("\n\t", " ", $header);
        $headers = array_map(
            fn($line) => explode(':', $line, 2),
            array_filter(explode("\n", $header))
        );
        return array_map(
            fn($pair) => [
                $this->getCanonicalHeaderName($pair[0]),
                $inbox->decodeMimeStr(trim($pair[1]))
            ],
            $headers
        );
    }

    private function getCanonicalHeaderName(string $headerName): string
    {
        $headerName = implode('-', array_map('ucfirst', explode('-', strtolower($headerName))));
        return match($headerName) {
            'Mime-Version' => 'MIME-Version',
            'List-Id' => 'List-ID',
            'Message-Id' => 'Message-ID',
            default => $headerName,
        };
    }

    private function copyBody(\PhpImap\IncomingMail $in, PHPMailer $out): void
    {
        if ($in->textHtml) {
            $out->isHTML(true);
            $out->Body = $in->textHtml;
            $out->AltBody = $in->textPlain;
        } else {
            $out->isHTML(false);
            $out->Body = $in->textPlain;
            $out->AltBody = '';
        }
    }

    private function copyAttachments(\PhpImap\IncomingMail $in, PHPMailer $out): void
    {
        foreach ($in->getAttachments() as $attachment) {
            if ($attachment->disposition === 'attachment') {
                $out->addStringAttachment(
                    $attachment->getContents(),
                    $attachment->name,
                    PHPMailer::ENCODING_BASE64,
                    $attachment->getFileInfo(FILEINFO_MIME_TYPE),
                );
            } else {
                $out->addStringEmbeddedImage(
                    $attachment->getContents(),
                    $attachment->contentId,
                    $attachment->name,
                    PHPMailer::ENCODING_BASE64,
                    $attachment->getFileInfo(FILEINFO_MIME_TYPE),
                );
            }
        }
    }

    public function setPassword($mail, $password): void
    {
        $this->redis->set($mail, $password);
    }
}
