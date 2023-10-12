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

    function __construct($configfile)
    {
        $configuration = Yaml::parse(file_get_contents($configfile));

        // replace environment variables
        array_walk_recursive($configuration, function(&$value) {
            if (!is_string($value)) return;
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

    private function getListsFromLdap($ldapConfig): array
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
                if ($memberDn === $ldapConfig['bind-dn']) continue;
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

        // replace variables
        foreach ($config as &$setting) {
            if (!is_string($setting)) continue;
            $setting = preg_replace_callback('/\{([a-z_-]+)\}/', function($m) use (&$list, &$config) {
                // priority of contexts: mail provider settings > list settings > global settings
                if (!empty($config[$m[1]])) return $config[$m[1]];
                if (!empty($list[$m[1]])) return $list[$m[1]];
                if (!empty($this->configuration[$m[1]])) return $this->configuration[$m[1]];
                return $m[0];
            }, $setting);
        }

        if ($config['type'] !== 'imap') throw new \UnexpectedValueException('not implemented');

        if (!in_array($config['imap-secure'], ['ssl', 'tls'], true)) throw new \UnexpectedValueException('not implemented');
        $config['imap-port'] = $config['imap-port'] ?: match($config['imap-secure']) {
            'ssl' => 993,
            'tls' => 143,
        };

        if ($config['smtp-secure'] !== 'ssl') throw new \UnexpectedValueException('not implemented');
        $config['smtp-port'] = $config['smtp-port'] ?: match($config['smtp-secure']) {
            'ssl' => 465,
        };

        return $config;
    }

    private function processList(array $list, array $mailConfig): void
    {
        if (!$list['members']) return;

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
        } catch(\PhpImap\Exception $ex) {
            error_log("IMAP connection failed: " . $ex->getMessage());
            die(1);
        }

        $outbox = null;

        foreach ($mailsIds as $mailId) {
            $mail = $inbox->getMail($mailId);
            $reportToOwners = false;

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
            foreach ($recipientAddresses as $recipientAddress) {
                $outbox->clearAddresses();
                $outbox->addAddress($recipientAddress, $recipientAddress);

                $outbox->clearCustomHeaders();
                foreach ($customHeaders as [$headerName, $headerValue]) {
                    $outbox->addCustomHeader($headerName, $headerValue);
                }
                $outbox->addCustomHeader('X-Forwarded-For', $recipientAddress);

                if ($outbox->send()) {
                    $inbox->deleteMail($mailId);
                } else {
                    echo $outbox->ErrorInfo . "\n";
                    exit;
                }
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

            if (in_array($headerName, [
                'List-Id',
                'List-Help',
                'List-Unsubscribe',
                'X-No-Archive',
                'List-Post',
                'List-Subscribe',
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
                'Cc',
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
            ], true)) {
                $customHeaders[] = [$headerName, $headerValue];
            } elseif (!in_array($headerName, [
                // ignore headers that are handled elsewhere or shall not be copied
                'Subject',
                'From',
                'Message-ID',
                'Content-Type',
                'MIME-Version',
                'Date',
                'Received',
                'X-Received',
                'Return-Path',
                'Delivered-To',
                'X-Spam-Level',
                'X-Spamd-Bar',
                'X-Spam-Checker-Version',
                'X-Spam-Status',
                'X-Spam',
                'Authentication-Results',
                'Dkim-Signature',
                'Content-Transfer-Encoding',
                'Arc-Message-Signature',
                'Arc-Authentication-Results',
                'Arc-Seal',
                'X-Google-Dkim-Signature',
                'X-Gm-Message-State',
                'X-Google-Smtp-Source',
                'X-Ppp-Message-Id',
                'X-Ppp-Vhost',
                'X-Originating-Ip',
                'X-Spampanel-Domain',
                'X-Spampanel-Username',
                'X-Spampanel-Outgoing-Class',
                'X-Spampanel-Outgoing-Evidence',
                'X-Recommended-Action',
                'X-Filter-Id',
                'Received-Spf',
            ], true)) {
                echo "copy unknown header: $headerName: $headerValue\n";
                $customHeaders[] = [$headerName, $headerValue];
            }
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
        $header = str_replace("\r\n", "\n", $header);
        $header = str_replace("\n ", " ", trim($header));
        $header = str_replace("\n\t", " ", trim($header));
        $headers = array_map(fn($line) => explode(':', $line, 2), array_filter(explode("\n", trim($header))));
        return array_map(fn($pair) => [$this->getCanonicalHeaderName($pair[0]), $inbox->decodeMimeStr(trim($pair[1]))], $headers);
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