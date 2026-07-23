<?php

declare(strict_types=1);

namespace Hengeb\Listig\Mail;

use Hengeb\Listig\Config\ListConfig;
use Symfony\Contracts\Translation\TranslatorInterface;

/**
 * Notifies a sender that their mail to a list was not delivered. Shared by the
 * IncomingMailFilter reject path (bin/worker.php) and the moderation reject
 * path (ModerationResponseHandler) — both send the same kind of notice, just
 * with a different reason.
 */
class RejectionNotifier
{
    public function __construct(
        private readonly NotificationMailer $notificationMailer,
        private readonly TranslatorInterface $translator,
    ) {
    }

    /** @param string $reasonKey Translation key, e.g. 'reject.size_exceeded' (see translations/messages.*.yaml) */
    public function notify(ListConfig $list, string $senderEmail, string $reasonKey, array $reasonParams = []): void
    {
        if ($senderEmail === '') {
            return;
        }

        $locale = $list->language;
        $reason = $this->translator->trans($reasonKey, $reasonParams, null, $locale);

        $this->notificationMailer->send(
            $list,
            $senderEmail,
            $this->translator->trans('reject.notice.subject', ['%list%' => $list->displayName], null, $locale),
            $this->translator->trans('reject.notice.body', [
                '%list%' => $list->displayName,
                '%mail%' => $list->mail,
                '%reason%' => $reason,
            ], null, $locale),
        );
    }
}
