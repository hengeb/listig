<?php

declare(strict_types=1);

namespace Hengeb\Listig\Mail;

use Hengeb\Listig\Config\ListConfig;
use PDO;
use PhpImap\IncomingMail;
use Symfony\Contracts\Translation\TranslatorInterface;

/**
 * Records a bounce in bounce_log and forwards the original bounce mail to the
 * list owners. Extracted from bin/worker.php to keep that file a thin loop and
 * match the rest of the codebase's constructor-injected, class-based design.
 */
class BounceHandler
{
    public function __construct(
        private readonly PDO $db,
        private readonly NotificationMailer $notificationMailer,
        private readonly TranslatorInterface $translator,
    ) {
    }

    public function handle(ListConfig $list, IncomingMail $mail, string $rawMime): void
    {
        $this->logBounce($list->name, $mail);
        $this->forwardToOwners($list, $mail, $rawMime);
    }

    private function logBounce(string $listCn, IncomingMail $mail): void
    {
        $stmt = $this->db->prepare(
            'INSERT INTO bounce_log (list_cn, sender, subject, bounced_at) VALUES (:list, :sender, :subject, NOW())'
        );
        $stmt->execute([
            'list'    => $listCn,
            'sender'  => $mail->fromAddress ?? '',
            'subject' => $mail->subject,
        ]);
    }

    private function forwardToOwners(ListConfig $list, IncomingMail $mail, string $rawMime): void
    {
        $sender  = $mail->fromAddress ?? 'unknown';
        $subject = $mail->subject ?? '';
        $locale  = $list->language;

        $this->notificationMailer->sendToOwners(
            $list,
            $this->translator->trans('bounce.owner_notice.subject', [
                '%list%' => $list->displayName,
                '%sender%' => $sender,
            ], null, $locale),
            $this->translator->trans('bounce.owner_notice.body', [
                '%list%' => $list->displayName,
                '%sender%' => $sender,
                '%subject%' => $subject,
            ], null, $locale),
            $rawMime,
            'bounce.eml',
            'message/rfc822',
        );
    }
}
