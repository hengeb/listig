#!/usr/bin/env php
<?php

declare(strict_types=1);

use Hengeb\Listig\Archive\ArchiveIndexer;
use Hengeb\Listig\Imap\ImapArchiver;
use Hengeb\Listig\Imap\ImapMailboxFactory;
use Hengeb\Listig\Imap\ImapPoller;
use Hengeb\Listig\Config\ListConfig;
use Hengeb\Listig\Mail\BounceHandler;
use Hengeb\Listig\Mail\HeaderFilter;
use Hengeb\Listig\Mail\IncomingMailFilter;
use Hengeb\Listig\Mail\MailProcessor;
use Hengeb\Listig\Mail\ProcessingFailureNotifier;
use Hengeb\Listig\Mail\ProcessingFailureTracker;
use Hengeb\Listig\Mail\RejectionNotifier;
use Hengeb\Listig\Moderation\ModerationChecker;
use Hengeb\Listig\Moderation\ModerationMailer;
use Hengeb\Listig\Moderation\ModerationResponseHandler;
use Hengeb\Listig\Provider\ListProvider;
use Hengeb\Listig\Queue\QueueSender;
use PhpImap\IncomingMail;

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

// config.yml is parsed lazily, on first access to any container entry that needs
// it (ConfigResolver's own constructor, triggered by the very first ->get() below)
// — so a config error (invalid YAML, a $VAR referenced in config.yml with no
// matching environment variable, an invalid `filters:` regex, ...) surfaces here,
// not at "$container = require ...". Catching it turns what would otherwise be an
// uncaught-exception fatal error (a raw stack trace on stderr) into one clear,
// actionable log line — still fails fast (same philosophy as the error itself:
// don't start against broken config), just without the noise. supervisord's
// [program:worker] autorestart=true still retries afterwards, same as it would for
// an uncaught fatal error; that retry loop is expected until the config is fixed.
try {
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
    $processingFailureTracker   = $container->get(ProcessingFailureTracker::class);
    $processingFailureNotifier  = $container->get(ProcessingFailureNotifier::class);
    $queueSender                = $container->get(QueueSender::class);
    $db                         = $container->get(PDO::class);

    $sleepSeconds = $container->get('worker.sleep-seconds');
    $batchSize    = $container->get('worker.batch-size');

    if ($container->get('app.hostname.resolved') === '') {
        error_log(
            "Listig: WARNING: 'hostname' is not set in config.yml — falling back to gethostname() "
            . "('" . (gethostname() ?: 'localhost') . "'), which is almost always wrong in a "
            . "containerized deployment behind a reverse proxy. Set 'hostname: your-public-domain.example.org' "
            . "explicitly (see CLAUDE.md)."
        );
    }
} catch (\Throwable $e) {
    error_log('Listig: FATAL: could not start worker, config.yml is invalid: ' . $e->getMessage());
    exit(1);
}

// Watched so a change to config.yml on disk (edited in place, or a fresh
// docker compose up after editing it) causes a clean self-restart instead of
// running indefinitely on a stale, already-parsed configuration — see "Worker
// loop — config reload" in CLAUDE.md. clearstatcache() is required: PHP caches
// filemtime() per-process, so without it every check in this same process
// would keep returning the mtime from the very first call.
$configPath  = $container->get('config.path');
$configMtime = @filemtime($configPath) ?: null;

/**
 * Processes a single already-fetched incoming mail through the full filter
 * pipeline. Uses `return` (not `continue`) for every terminal outcome so the
 * caller has exactly one place — right after this call returns without
 * throwing — to clear any processing_failures bookkeeping for this UID (see
 * ProcessingFailureTracker), regardless of which branch below actually
 * handled it.
 */
$processIncomingMail = function (
    IncomingMail $mail,
    string $rawMime,
    int $uid,
    int $uidValidity,
    ListConfig $list,
) use (
    $moderationResponseHandler,
    $headerFilter,
    $mailFilter,
    $bounceHandler,
    $imapPoller,
    $imapArchiver,
    $rejectionNotifier,
    $moderationMailer,
    $mailProcessor,
    $archiveIndexer,
): void {
    // Owner replies to +accept-{token}/+reject-{token} — handled separately,
    // never subject to the normal incoming-mail filter chain. This is the
    // reply mail's own UID (not the original moderated mail's, which
    // ModerationResponseHandler::processAccept()/processReject() already
    // archives/deletes via its own uid from the token payload) — without
    // archiveOrDelete() here too, every accept/reject reply piled up in the
    // inbox forever, marked seen but never actually removed, unlike every
    // other terminal outcome (bounce/reject/distribute) below.
    if ($moderationResponseHandler->handle($mail, $list)) {
        $imapPoller->markSeen($list, $uid, $uidValidity);
        $imapArchiver->archiveOrDelete($list, $uid);
        return;
    }

    $authResults = $headerFilter->readAuthResults($mail->headersRaw ?? '');
    $result      = $mailFilter->filter($mail, $list, $rawMime, $authResults);

    if ($result->isDiscard) {
        $imapPoller->markSeen($list, $uid, $uidValidity);
        // True for a `filters:` rule with `action: discard` (see
        // SpamFilter/FilterResult::$forceDelete) — unlike the X-Loop
        // discard, that one is meant to actually go away, deleted
        // outright regardless of the list's own archive: setting.
        if ($result->forceDelete) {
            $imapArchiver->delete($list, $uid);
        }
        return;
    }

    if ($result->isBounce) {
        $bounceHandler->handle($list, $mail, $rawMime);
        $imapPoller->markSeen($list, $uid, $uidValidity);
        $imapArchiver->archiveOrDelete($list, $uid);
        return;
    }

    if ($result->isReject) {
        $rejectionNotifier->notify($list, $mail, $rawMime, $result->reason, $result->reasonParams);
        $imapPoller->markSeen($list, $uid, $uidValidity);
        // forceDelete (a `filters:` spam match, see FilterResult) skips
        // the list's own archive: setting entirely — every other reject
        // reason still goes through the normal archiveOrDelete().
        if ($result->forceDelete) {
            $imapArchiver->delete($list, $uid);
        } else {
            $imapArchiver->archiveOrDelete($list, $uid);
        }
        return;
    }

    if ($result->isModeration) {
        $moderationMailer->send($list, $mail, $uid, $uidValidity, $rawMime);
        $imapPoller->markSeen($list, $uid, $uidValidity);
        return;
    }

    if ($result->isDistribute) {
        $mailProcessor->process($mail, $rawMime, $list);
        $imapPoller->markSeen($list, $uid, $uidValidity);
        $imapArchiver->archiveOrDelete($list, $uid);
        $archiveIndexer->index($list, $mail);
    }
};

error_log('Listig worker started');

while (true) {
    clearstatcache(true, $configPath);
    $currentConfigMtime = @filemtime($configPath) ?: null;
    if ($currentConfigMtime !== $configMtime) {
        error_log('Listig: config.yml changed on disk — restarting worker to reload configuration.');
        exit(0);
    }

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
                $processIncomingMail($mail, $rawMime, $uid, $uidValidity, $list);
                $processingFailureTracker->clear($list->name, $uid, $uidValidity);
            } catch (\Throwable $e) {
                error_log("Listig: Error processing mail UID $uid for list {$list->name}: " . $e->getMessage());

                // Without a bound, a mail that reliably crashes processing (a
                // malformed header, an unexpected library exception, ...) would be
                // re-fetched and re-crash on every single cycle forever — never
                // marked seen, never archived, with no signal beyond this log line.
                // See ProcessingFailureTracker.
                $attempts = $processingFailureTracker->recordFailure($list->name, $uid, $uidValidity, $e->getMessage());
                if ($attempts < ProcessingFailureTracker::MAX_ATTEMPTS) {
                    continue;
                }

                error_log(
                    "Listig: Giving up on mail UID $uid for list {$list->name} after $attempts failed attempts — "
                    . 'notifying the owner(s) and archiving.'
                );
                try {
                    $processingFailureNotifier->notify($list, $mail, $rawMime, $e, $attempts);
                    $imapPoller->markSeen($list, $uid, $uidValidity);
                    $imapArchiver->archiveOrDelete($list, $uid);
                    $processingFailureTracker->clear($list->name, $uid, $uidValidity);
                } catch (\Throwable $giveUpError) {
                    // A failure while giving up (owner notify, mark seen, archive)
                    // must not crash the whole worker cycle — log it and leave the
                    // processing_failures row in place so this mail is retried
                    // again next cycle (attempts keeps climbing, give-up is
                    // attempted again) instead of silently vanishing from tracking.
                    error_log("Listig: Failed to finalize give-up for UID $uid, list {$list->name}: " . $giveUpError->getMessage());
                }
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
        // Safety net only — a row here is normally cleared within one cycle of
        // reaching ProcessingFailureTracker::MAX_ATTEMPTS (see above); this just
        // catches one that got stuck (e.g. the give-up notification/archive call
        // itself kept failing) so it doesn't linger in the table forever.
        $db->exec("DELETE FROM processing_failures WHERE last_attempt_at < NOW() - INTERVAL 31 DAY");
    } catch (\Throwable $e) {
        error_log("Listig: Cleanup failed: " . $e->getMessage());
    }

    // Drop cached IMAP connections before the (potentially long) sleep so the next
    // cycle starts fresh rather than risking a stale/dropped connection going unnoticed.
    $imapMailboxFactory->reset();

    // Drop each list-provider's cached directory data (LDAP entries, DB
    // config-table rows, a type: yaml file's contents, ...) too — without this,
    // a provider that succeeded once would keep serving that same result for
    // the worker's entire lifetime (see CLAUDE.md "Worker loop — config
    // reload"), so e.g. an LDAP description[] edit would only ever take effect
    // after a full process restart, not on the next cycle.
    $listProvider->reset();

    // 5. Sleep
    $elapsed   = microtime(true) - $cycleStart;
    $remaining = $sleepSeconds - (int) $elapsed;
    if ($remaining > 0) {
        sleep($remaining);
    }
}
