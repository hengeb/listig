#!/usr/bin/env php
<?php

declare(strict_types=1);

use Hengeb\Listig\Archive\ArchiveIndexer;
use Hengeb\Listig\Imap\ImapArchiver;
use Hengeb\Listig\Imap\ImapMailboxFactory;
use Hengeb\Listig\Imap\ImapPoller;
use Hengeb\Listig\Mail\BounceHandler;
use Hengeb\Listig\Mail\HeaderFilter;
use Hengeb\Listig\Mail\IncomingMailFilter;
use Hengeb\Listig\Mail\MailProcessor;
use Hengeb\Listig\Mail\RejectionNotifier;
use Hengeb\Listig\Moderation\ModerationChecker;
use Hengeb\Listig\Moderation\ModerationMailer;
use Hengeb\Listig\Moderation\ModerationResponseHandler;
use Hengeb\Listig\Provider\ListProvider;
use Hengeb\Listig\Queue\QueueSender;

require_once __DIR__ . '/../vendor/autoload.php';

// Load .env
$envFile = __DIR__ . '/../.env';
if (file_exists($envFile)) {
    foreach (file($envFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        if (str_starts_with($line, '#') || !str_contains($line, '=')) {
            continue;
        }
        [$key, $value] = explode('=', $line, 2);
        $_ENV[trim($key)] = trim($value);
        putenv(trim($key) . '=' . trim($value));
    }
}

$container = require __DIR__ . '/../config/container.php';

$listProvider              = $container->get(ListProvider::class);
$imapPoller                = $container->get(ImapPoller::class);
$imapArchiver               = $container->get(ImapArchiver::class);
$archiveIndexer             = $container->get(ArchiveIndexer::class);
$imapMailboxFactory         = $container->get(ImapMailboxFactory::class);
$mailFilter                 = $container->get(IncomingMailFilter::class);
$headerFilter               = $container->get(HeaderFilter::class);
$mailProcessor              = $container->get(MailProcessor::class);
$moderationMailer           = $container->get(ModerationMailer::class);
$moderationChecker          = $container->get(ModerationChecker::class);
$moderationResponseHandler  = $container->get(ModerationResponseHandler::class);
$bounceHandler              = $container->get(BounceHandler::class);
$rejectionNotifier          = $container->get(RejectionNotifier::class);
$queueSender                = $container->get(QueueSender::class);
$db                         = $container->get(PDO::class);

$sleepSeconds = (int) ($_ENV['WORKER_SLEEP_SECONDS'] ?? getenv('WORKER_SLEEP_SECONDS') ?: 60);
$batchSize    = (int) ($_ENV['QUEUE_BATCH_SIZE'] ?? getenv('QUEUE_BATCH_SIZE') ?: 50);

error_log('Listig worker started');

while (true) {
    $cycleStart = microtime(true);

    // 1. Process each list
    foreach ($listProvider->getLists() as $list) {
        try {
            $mails = $imapPoller->poll($list);
        } catch (\Throwable $e) {
            error_log("Listig: IMAP poll failed for list {$list->name}: " . $e->getMessage());
            continue;
        }

        foreach ($mails as $mailData) {
            $uid         = $mailData['uid'];
            $uidValidity = $mailData['uidvalidity'];
            $rawMime     = $mailData['mime'];
            $mail        = $mailData['mail']; // IncomingMail

            try {
                // Owner replies to +accept-{token}/+reject-{token} — handled separately,
                // never subject to the normal incoming-mail filter chain.
                if ($moderationResponseHandler->handle($mail, $list)) {
                    $imapPoller->markSeen($list->name, $uid, $uidValidity);
                    continue;
                }

                $authResults = $headerFilter->readAuthResults($mail->headersRaw ?? '');
                $result      = $mailFilter->filter($mail, $list, $rawMime, $authResults);

                if ($result->isDiscard) {
                    $imapPoller->markSeen($list->name, $uid, $uidValidity);
                    continue;
                }

                if ($result->isBounce) {
                    $bounceHandler->handle($list, $mail, $rawMime);
                    $imapPoller->markSeen($list->name, $uid, $uidValidity);
                    $imapArchiver->archiveOrDelete($list, $uid);
                    continue;
                }

                if ($result->isReject) {
                    $rejectionNotifier->notify($list, $mail->fromAddress ?? '', $result->reason);
                    $imapPoller->markSeen($list->name, $uid, $uidValidity);
                    $imapArchiver->archiveOrDelete($list, $uid);
                    continue;
                }

                if ($result->isModeration) {
                    $moderationMailer->send($list, $uid, $uidValidity, $rawMime);
                    $imapPoller->markSeen($list->name, $uid, $uidValidity);
                    continue;
                }

                if ($result->isDistribute) {
                    $mailProcessor->process($mail, $rawMime, $list);
                    $imapPoller->markSeen($list->name, $uid, $uidValidity);
                    $imapArchiver->archiveOrDelete($list, $uid);
                    $archiveIndexer->index($list, $mail);
                }
            } catch (\Throwable $e) {
                error_log("Listig: Error processing mail UID $uid for list {$list->name}: " . $e->getMessage());
            }
        }

        // Delete inbox mails older than 30 days
        try {
            $imapArchiver->deleteOldMails($list);
        } catch (\Throwable $e) {
            error_log("Listig: deleteOldMails failed for list {$list->name}: " . $e->getMessage());
        }
    }

    // 2. Check overdue moderation items
    try {
        $moderationChecker->checkOverdue();
    } catch (\Throwable $e) {
        error_log("Listig: ModerationChecker failed: " . $e->getMessage());
    }

    // 3. Send queue batch
    try {
        $queueSender->sendBatch($batchSize);
    } catch (\Throwable $e) {
        error_log("Listig: QueueSender failed: " . $e->getMessage());
    }

    // 4. Cleanup
    try {
        $queueSender->purgeStaleFailedEntries();
        $db->exec("DELETE FROM imap_seen WHERE seen_at < NOW() - INTERVAL 31 DAY");
        $db->exec("DELETE FROM rate_limit WHERE sent_at < NOW() - INTERVAL 1 HOUR");
        $db->exec("DELETE FROM bounce_log WHERE bounced_at < NOW() - INTERVAL 90 DAY");
    } catch (\Throwable $e) {
        error_log("Listig: Cleanup failed: " . $e->getMessage());
    }

    // Drop cached IMAP connections before the (potentially long) sleep so the next
    // cycle starts fresh rather than risking a stale/dropped connection going unnoticed.
    $imapMailboxFactory->reset();

    // 5. Sleep
    $elapsed   = microtime(true) - $cycleStart;
    $remaining = $sleepSeconds - (int) $elapsed;
    if ($remaining > 0) {
        sleep($remaining);
    }
}
