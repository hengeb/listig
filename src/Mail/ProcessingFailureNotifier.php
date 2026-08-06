<?php

declare(strict_types=1);

namespace Hengeb\Listig\Mail;

use Hengeb\Listig\Config\ListConfig;
use PhpImap\IncomingMail;
use Symfony\Contracts\Translation\TranslatorInterface;

/**
 * Tells the list owners that an incoming mail could not be processed after
 * ProcessingFailureTracker::MAX_ATTEMPTS attempts and has been given up on —
 * the incoming-processing counterpart to QueueSender's own "3 failed delivery
 * attempts, notify the owner" notice (see "queue.failure_notice"), just for a
 * mail that crashed while being *received* rather than one that failed to
 * *send*. The original mail is attached as message/rfc822, same as
 * BounceHandler/ModerationMailer, so the owner can actually see what triggered
 * it — the exception message alone (e.g. a raw symfony/mime error) is rarely
 * meaningful to a non-developer.
 */
class ProcessingFailureNotifier
{
    public function __construct(
        private readonly NotificationMailer $notificationMailer,
        private readonly TranslatorInterface $translator,
    ) {
    }

    public function notify(ListConfig $list, IncomingMail $mail, ?string $rawMime, \Throwable $exception, int $attempts): void
    {
        $locale = $list->language;

        $this->notificationMailer->sendToOwners(
            $list,
            $this->translator->trans('processing_failure.owner_notice.subject', [
                '%list%' => $list->displayName,
            ], null, $locale),
            $this->translator->trans('processing_failure.owner_notice.body', [
                '%list%' => $list->displayName,
                '%subject%' => $mail->subject ?? '',
                '%sender%' => $mail->fromAddress ?? '',
                '%attempts%' => (string) $attempts,
                '%error%' => $exception->getMessage(),
            ], null, $locale),
            $rawMime,
            'original.eml',
            'message/rfc822',
        );
    }
}
