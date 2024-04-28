<?php
declare(strict_types=1);

namespace Hengeb\Listig;

use Symfony\Component\Yaml\Yaml;
use Predis\Client as RedisClient;
use Symfony\Component\Ldap\Ldap;
use PHPMailer\PHPMailer\PHPMailer;
use PhpImap\Mailbox;

class App {
    private array $configuration = [];

    /** @var RedisClient[] */
    private array $redisClients = [];

    /** @var Ldap[] */
    private array $ldapClients = [];

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

        // set some defaults

        if (!isset($this->configuration['ldap'])) {
            $this->configuration['ldap'] = [];
        }
        if (!isset($this->configuration['redis'])) {
            $this->configuration['redis'] = [];
        }
        if (!isset($this->configuration['mail'])) {
            $this->configuration['mail'] = ['type' => 'imap'];
        }

        foreach ($this->configuration as $configName => &$config) {
            $config['config-name'] = $configName;
            if (!isset($config['type'])) {
                $config['type'] = $configName;
            }
        }
    }

    private function getRedisClient(string $configName): RedisClient
    {
        if (!isset($this->redisClients[$configName])) {
            $config = [...[
                'host' => 'localhost',
                'port' => 6379,
            ], ... $this->configuration[$configName] ?? []];
            $this->redisClients[$configName] = new RedisClient($config);
        }
        return $this->redisClients[$configName];
    }

    private function getLdapConfig(string $configName): array
    {
        return [...[
            'config-name' => 'ldap',
            'type' => 'ldap',
            'host' => 'localhost',
            'port' => 389,
            'filter' => '(objectClass=mailGroup)',
            'user-filter' => '(objectClass=inetOrgPerson)',
            'password-provider' => 'redis',
        ], ...$this->configuration[$configName] ?? []];
    }

    private function getLdapClient(array|string $config): Ldap
    {
        if (!is_array($config)) {
            $config = $this->getLdapConfig($config);
        }
        $configName = $config['config-name'];
        if (!isset($this->ldapClients[$configName])) {
            $this->ldapClients[$configName] = Ldap::create('ext_ldap', [
                'host' => $config['host'],
                'port' => $config['port']
            ]);
            $this->ldapClients[$configName]->bind($config['bind-dn'], $config['bind-password']);

        }
        return $this->ldapClients[$configName];
    }

    public function run(): void
    {
        $listConfigurations = array_filter($this->configuration, fn($c) => $c['type'] === 'list-collection') ?: [[]];
        foreach ($listConfigurations as $configName => $config) {
            $config = [...[
                'list-provider' => 'ldap',
                'subject-prefix' => "[{list-label}] ",
                'rewrite-sender-name' => "{sender-name}",
                'mail-configuration' => 'mail',
                'list-label' => '{list-name}',
            ], ... $config];

            if (empty($this->configuration[$config['list-provider']])) {
                throw new \UnexpectedValueException($configName . ': list-provider setting is invalid');
            }

            switch ($this->configuration[$config['list-provider']]['type']) {
                case 'ldap':
                    $lists = $this->getListsFromLdap($config['list-provider']);
                    break;
                default:
                    throw new \UnexpectedValueException('not implemented');
                    break;
            }

            foreach ($lists as $list) {
                $this->processList([... $config, ... $list]);
            }
        }
    }

    private function getListsFromLdap(string $ldapConfigName): array
    {
        $ldapConfig = $this->getLdapConfig($ldapConfigName);
        $ldap = $this->getLdapClient($ldapConfig);

        if (empty($this->configuration[$ldapConfig['password-provider']])) {
            throw new \UnexpectedValueException($ldapConfigName . ': password-provider setting is invalid');
        }
        $passwordProviderConfig = $this->configuration[$ldapConfig['password-provider']];

        if ($passwordProviderConfig['type'] !== 'redis') {
            throw new \UnexpectedValueException('not implemented');
        }
        $redis = $this->getRedisClient($ldapConfig['password-provider']);

        $lists = [];

        $listsEntries = $ldap->query($ldapConfig['dn'], $ldapConfig['filter'])->execute();
        foreach ($listsEntries as $listEntry) {
            $listName = $listEntry->getAttribute('cn')[0];
            $listAddress = $listEntry->getAttribute('mail')[0];

            $listPassword = $redis->get(strtolower($listAddress));
            if (!$listPassword) {
                error_log("missing password for {$listAddress}");
                continue;
            }

            $lists[$listName] = [
                'list-name' => $listName,
                'list-address' => $listAddress,
                'list-sender' => str_replace('@', '+bounces@', $listAddress),
                'list-password' => $listPassword,
                'domain' => preg_replace('/^.*@/', '', $listAddress),
                'owners' => array_map(
                    fn($ownerDn) => $ldap->query($ownerDn, $ldapConfig['user-filter'])->execute()[0]->getAttribute('mail')[0],
                    $listEntry->getAttribute('owner') ?? []
                ),
                'members' => [],
            ];

            // set list config variables from description attribute(s)
            foreach ($listEntry->getAttribute('description') ?? [] as $description) {
                // description attribute might be the list label or a json encoded array
                $data = json_decode($description, true);
                if ($data === null) {
                    $lists[$listName]['list-label'] = $description;
                    continue;
                }
                foreach ($data as $key=>$value) {
                    if (!isset($lists[$listName][$key]) || $key === 'list-label') {
                        $lists[$listName][$key] = $value;
                    }
                }
            }

            foreach ($listEntry->getAttribute('member') as $memberDn) {
                if ($memberDn === $ldapConfig['bind-dn']) {
                    continue;
                }
                try {
                    $userEntry = $ldap->query($memberDn, $ldapConfig['user-filter'])->execute()[0];
                } catch (\Exception $e) {
                    continue;
                }
                $lists[$listName]['members'][] = $userEntry->getAttribute('mail')[0];
            }
        }

        return $lists;
    }

    private function getMailServerConfig(array $list): array
    {
        if (empty($this->configuration[$list['mail-configuration']])) {
            throw new \UnexpectedValueException($list['list-name'] . ': mail-configuration is invalid');
        }
        // set defaults
        $config = [...[
            'type' => 'imap',
            'host' => '{domain}',
            'folder' => 'INBOX',
            'user' => '{list-address}',
            'password' => '{list-password}',
            'secure' => 'ssl',
            'imap-host' => '{host}',
            'imap-user' => '{user}',
            'imap-password' => '{password}',
            'imap-secure' => '{secure}',
            'imap-port' => null,
            'smtp-host' => '{host}',
            'smtp-port' => null,
            'smtp-user' => '{user}',
            'smtp-password' => '{password}',
            'smtp-secure' => '{secure}',
        ], ...$this->configuration[$list['mail-configuration']]];

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

    private function replaceConfigVariables(mixed $config, array ...$contexts): mixed
    {
        if (!is_array($config)) {
            if (!is_string($config)) {
                return $config;
            }

            // allow up to 3 iterations of replacements
            for ($i = 1; $i <= 3; $i++) {
                $config = preg_replace_callback('/\{([a-z_-]+)\}/', function($m) use ($contexts) {
                    if (isset($config[$m[1]]) && !is_array($config[$m[1]])) {
                        return $config[$m[1]];
                    }
                    foreach ($contexts as &$context) {
                        if (isset($context[$m[1]]) && !is_array($context[$m[1]])) {
                            return $context[$m[1]];
                        }
                    }
                    return $m[0];
                }, $config, -1, $count);
                if (!$count) {
                    break;
                }
            }

            return $config;
        }

        $contexts[] = $this->configuration;

        foreach ($config as $name=>&$setting) {
            $setting = $this->replaceConfigVariables($setting, $config, ... $contexts);
        }

        return $config;
    }

    private function processList(array $list): void
    {
        if (!$list['members']) {
            return;
        }

        $mailServerConfig = $this->getMailServerConfig($list);

        $inbox = new Mailbox(
            "{{$mailServerConfig['imap-host']}:{$mailServerConfig['imap-port']}/imap/{$mailServerConfig['imap-secure']}}{$mailServerConfig['folder']}",
            $mailServerConfig['imap-user'],
            $mailServerConfig['imap-password']
        );

        // expunge deleted mails upon mailbox close
        $inbox->setConnectionArgs(CL_EXPUNGE, 0, []);

        try {
            $mailsIds = $inbox->searchMailbox('ALL');
        } catch(\PhpImap\Exceptions\ConnectionException $ex) {
            error_log("IMAP connection for {$list['list-address']} failed: " . $ex->getMessage());
            return;
        }

        if (!$mailsIds) {
            return;
        }

        foreach ($mailsIds as $mailId) {
            $mail = $inbox->getMail($mailId);

            $outbox = $this->createNewMail($mailServerConfig);

            $mailConfig = [
                'subject' => $mail->subject,
                'sender-name' => $mail->senderName ?: preg_replace('/^(.+?)[@+].*$/', '$1', $mail->senderAddress),
            ];

            $subjectPrefix = $this->replaceConfigVariables($list['subject-prefix'], $mailConfig, $list);
            $subject = $mail->subject;
            if (!str_contains(strtolower($subject), strtolower(($subjectPrefix)))) {
                $subject = "$subjectPrefix$subject";
            }

            $senderName = $this->replaceConfigVariables($list['rewrite-sender-name'], $mailConfig, $list);

            $outbox->setFrom($list['list-address'], $senderName);
            $outbox->Sender = $list['list-sender'];
            $outbox->Subject = $subject;
            $outbox->MessageID = $mail->messageId;
            $outbox->MessageDate = $mail->headers->date;

            $customHeaders = $this->getCustomHeaders($mail, $inbox, $list);

            if (!in_array('Reply-To', array_column($customHeaders, 0))) {
                $outbox->addReplyTo($mail->senderAddress, $mail->senderName);
            }

            $this->copyBody($mail, $outbox);
            $this->copyAttachments($mail, $outbox);

            $reportToOwners = in_array(['Auto-Submitted', 'Auto-Replied'], $customHeaders, true)
              || in_array(['Auto-Submitted', 'auto-replied'], $customHeaders, true)
              || count($mail->to) === 1 && strtolower(array_keys($mail->to[0])) === strtolower($list['list-sender']);

            $recipientAddresses = $reportToOwners ? $list['owners'] : $list['members'];

            // exclude recipients who are already listed in the To or CC header.
            $recipientAddressesFiltered = array_filter($recipientAddresses, fn($address) =>
                !in_array(strtolower($address), array_map('strtolower', array_keys(array_merge($mail->to, $mail->cc))), true)
            );

            $isSent = false;
            $isSpam = false;
            foreach ($recipientAddressesFiltered as $recipientAddress) {
                $outbox->clearAddresses();
                $outbox->clearEnvelopeTo();
                $outbox->addEnvelopeTo($recipientAddress);

                foreach ($mail->to as $address=>$name) {
                    $outbox->addAddress($address, $name ?? '');
                }
                foreach ($mail->cc as $address=>$name) {
                    $outbox->addCC($address, $name ?? '');
                }

                $outbox->clearCustomHeaders();
                foreach ($customHeaders as [$headerName, $headerValue]) {
                    $outbox->addCustomHeader($headerName, $headerValue);
                }
                $outbox->addCustomHeader('X-Forwarded-For', $recipientAddress);

                if ($outbox->send()) {
                    $isSent = true;
                } elseif (str_contains($outbox->ErrorInfo, 'Spam message rejected')) {
                    error_log("Spam message was rejected by the server, skipping.");
                    $isSpam = true;
                    break;
                } else {
                    error_log('message could not be sent: ' . $outbox->ErrorInfo);
                }
            }

            // message could be sent at least to one recipient or was identified as spam
            if ($isSent || $isSpam || count($recipientAddressesFiltered) === 0) {
                $inbox->deleteMail($mailId);
            }

            $outbox->smtpClose();
        }
    }

    private function createNewMail(array $mailServerConfig): Outbox
    {
        $outbox = new Outbox();
        $outbox->isSMTP();
        $outbox->Host = $mailServerConfig['smtp-host'];
        $outbox->Port = $mailServerConfig['smtp-port'];
        $outbox->SMTPAuth = true;
        $outbox->SMTPSecure = $mailServerConfig['smtp-secure'];
        $outbox->SMTPKeepAlive = true;
        $outbox->CharSet = "UTF-8";
        $outbox->AllowEmpty = true;

        $outbox->Username = $mailServerConfig['smtp-user'];
        $outbox->Password = $mailServerConfig['smtp-password'];

        return $outbox;
    }

    private function getCustomHeaders(\PhpImap\IncomingMail $mail, \PhpImap\Mailbox $inbox, array $list): array
    {
        $customHeaders = [
            ['X-Forwarded-From', $mail->senderAddress],
            ['X-Original-To', $mail->toString],
        ];

        $headers = $this->parseHeaders($mail->headersRaw, $inbox);
        foreach ($headers as [$headerName, $headerValue]) {
            // ignore headers that are handled elsewhere or shall not be copied
            if (in_array($headerName, [
                'Subject',
                'From',
                'Sender',
                'To',
                'Cc',
                'Message-ID',
                'Content-Type',
                'MIME-Version',
                'Date',
                'X-Received',
                'Received',
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
                'X-No-Archive',
                'Mailing-List',
                'X-Course-Id',
                'X-Course-Name',
                'Precedence',
                'X-Auto-Response-Suppress',
                'Auto-Submitted',
                'Thread-Topic',
                'Thread-Index',
                'In-Reply-To',
                'Reply-To',
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
                error_log("copy unknown header: $headerName: $headerValue");
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
            $customHeaders[] = ['List-Id', '<' . $list['list-address'] . '>'];
            $customHeaders[] = ['List-Post', '<mailto:' . $list['list-address'] . '>'];
            $customHeaders[] = ['Sender', '<' . $list['list-sender'] . '>'];
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

    public function setPassword($mail, $password, $redisConfigName = 'redis'): void
    {
        $redis = $this->getRedisClient($redisConfigName);
        $redis->set($mail, $password);
    }
}
