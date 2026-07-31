<?php

declare(strict_types=1);

namespace Hengeb\Listig\Mail;

use Hengeb\Listig\Config\ListConfig;
use PhpImap\IncomingMail;
use Symfony\Contracts\Translation\TranslatorInterface;

/**
 * Notifies a sender that their mail to a list was not delivered. Shared by the
 * IncomingMailFilter reject path (bin/worker.php) and the moderation reject
 * path (ModerationController/ModerationResponseHandler) — both send the same
 * kind of notice, just with a different reason.
 */
class RejectionNotifier
{
    public function __construct(
        private readonly NotificationMailer $notificationMailer,
        private readonly TranslatorInterface $translator,
    ) {
    }

    /**
     * @param string $reasonKey Translation key, e.g. 'reject.size_exceeded' (see translations/messages.*.yaml)
     * @param string|null $rawMime The original mail's raw MIME, attached as message/rfc822
     *     so the sender can tell which of their mails this notice is about — best-effort,
     *     silently omitted (not the whole notice) when unavailable (e.g. a moderation
     *     reject where the mail has already left the inbox by the time this runs).
     */
    public function notify(ListConfig $list, IncomingMail $mail, ?string $rawMime, string $reasonKey, array $reasonParams = []): void
    {
        $senderEmail = $mail->fromAddress ?? '';
        if ($senderEmail === '') {
            return;
        }

        $locale = $list->language;
        $reason = $this->translator->trans($reasonKey, $reasonParams, null, $locale);
        // Same fallback as ModerationMailer/ArchiveIndexer for the same field —
        // an unparseable/absent Date header must not block sending the notice.
        $mailDate = date('Y-m-d H:i:s', strtotime($mail->date ?? '') ?: time());

        $this->notificationMailer->send(
            $list,
            $senderEmail,
            $this->translator->trans('reject.notice.subject', ['%list%' => $list->displayName], null, $locale),
            $this->translator->trans('reject.notice.body', [
                '%list%' => $list->displayName,
                '%mail%' => $list->mail,
                '%subject%' => $mail->subject ?? '',
                '%date%' => $mailDate,
                '%reason%' => $reason,
            ], null, $locale),
            $rawMime,
            $rawMime !== null ? 'original.eml' : null,
            $rawMime !== null ? 'message/rfc822' : null,
        );
    }
}
