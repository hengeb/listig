<?php

declare(strict_types=1);

namespace Hengeb\Listig\Moderation;

use Hengeb\Listig\Archive\ArchiveIndexer;
use Hengeb\Listig\Config\ListConfig;
use Hengeb\Listig\Imap\ImapArchiver;
use Hengeb\Listig\Imap\ImapPoller;
use Hengeb\Listig\Mail\MailProcessor;
use Hengeb\Listig\Mail\RejectionNotifier;
use Hengeb\Listig\Token\TokenService;
use PDO;
use PhpImap\IncomingMail;

/**
 * Detects owner replies to the +accept-{token}/+reject-{token} addresses generated
 * by ModerationMailer and processes the moderation decision.
 */
class ModerationResponseHandler
{
    private const TOKEN_MAX_AGE = 7 * 24 * 3600;

    public function __construct(
        private readonly PDO $db,
        private readonly TokenService $tokenService,
        private readonly MailProcessor $mailProcessor,
        private readonly ImapPoller $imapPoller,
        private readonly ImapArchiver $imapArchiver,
        private readonly RejectionNotifier $rejectionNotifier,
        private readonly ArchiveIndexer $archiveIndexer,
    ) {
    }

    /**
     * @return bool true if the mail was a moderation response and has been fully
     *              handled (caller should mark it seen and skip normal filtering).
     */
    public function handle(IncomingMail $mail, ListConfig $list): bool
    {
        $action = $this->detectAction($mail, $list->name);
        if ($action === null) {
            return false;
        }

        [$purpose, $token] = $action;

        try {
            $payload = $this->tokenService->verify($token, $purpose, self::TOKEN_MAX_AGE);
        } catch (\InvalidArgumentException $e) {
            error_log("Listig: Invalid moderation $purpose token for list {$list->name}: " . $e->getMessage());
            return true;
        }

        // Payload shape set by ModerationMailer::send(): [listCn, imapUid, imapUidvalidity]
        [$listCn, $uid, $uidValidity] = $payload;
        $uid = (int) $uid;
        $uidValidity = (int) $uidValidity;

        if ($listCn !== $list->name) {
            error_log("Listig: Moderation token list mismatch for list {$list->name}");
            return true;
        }

        if (!$list->isOwnedBy($mail->fromAddress ?? '')) {
            error_log("Listig: Moderation $purpose rejected — sender is not an owner of {$list->name}");
            return true;
        }

        // uid/uidvalidity come from the token itself (HMAC-verified above), not from a
        // DB lookup — moderation_queue is only consulted to check the item is still
        // pending (idempotency: a re-sent reminder or a double-click must not re-process it).

        $stmt = $this->db->prepare(
            'SELECT id FROM moderation_queue WHERE list_cn = :list AND imap_uid = :uid AND imap_uidvalidity = :validity'
        );
        $stmt->execute(['list' => $list->name, 'uid' => $uid, 'validity' => $uidValidity]);
        $item = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($item === false) {
            error_log("Listig: Moderation item not found for list {$list->name} UID $uid (already processed?)");
            return true;
        }

        if ($purpose === 'accept') {
            $this->processAccept($list, $uid, $uidValidity);
        } else {
            $this->processReject($list, $uid, $uidValidity);
        }

        $this->db->prepare('DELETE FROM moderation_queue WHERE id = :id')->execute(['id' => $item['id']]);

        return true;
    }

    /** @return array{0: string, 1: string}|null [purpose, token] */
    private function detectAction(IncomingMail $mail, string $listName): ?array
    {
        $pattern = '/^' . preg_quote($listName, '/') . '\+(accept|reject)-(.+)@/i';
        foreach (array_keys($mail->to) as $address) {
            if (preg_match($pattern, $address, $m)) {
                return [strtolower($m[1]), $m[2]];
            }
        }
        return null;
    }

    private function processAccept(ListConfig $list, int $uid, int $uidValidity): void
    {
        $incomingMail = $this->imapPoller->fetchMailByUid($list, $uid);
        $rawMime = $this->imapPoller->fetchByUid($list, $uid);

        if ($incomingMail === null || $rawMime === null) {
            error_log("Listig: Moderation accept failed — original mail UID $uid no longer on IMAP for list {$list->name}");
            return;
        }

        $this->mailProcessor->process($incomingMail, $rawMime, $list);
        $this->imapPoller->markSeen($list->name, $uid, $uidValidity);
        $this->imapArchiver->archiveOrDelete($list, $uid);
        $this->archiveIndexer->index($list, $incomingMail);
    }

    private function processReject(ListConfig $list, int $uid, int $uidValidity): void
    {
        $incomingMail = $this->imapPoller->fetchMailByUid($list, $uid);
        if ($incomingMail === null) {
            error_log("Listig: Moderation reject — original mail UID $uid no longer on IMAP for list {$list->name}");
            return;
        }

        $this->rejectionNotifier->notify($list, $incomingMail->fromAddress ?? '', 'reject.moderation_declined');
        $this->imapPoller->markSeen($list->name, $uid, $uidValidity);
        $this->imapArchiver->archiveOrDelete($list, $uid);
    }
}
