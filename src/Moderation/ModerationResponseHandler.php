<?php

declare(strict_types=1);

namespace Hengeb\Listig\Moderation;

use Hengeb\Listig\Archive\ArchiveIndexer;
use Hengeb\Listig\Config\ListConfig;
use Hengeb\Listig\Imap\ImapArchiver;
use Hengeb\Listig\Imap\ImapPoller;
use Hengeb\Listig\Mail\HeaderFilter;
use Hengeb\Listig\Mail\MailProcessor;
use Hengeb\Listig\Mail\RejectionNotifier;
use Hengeb\Listig\Token\ListFingerprint;
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
        private readonly HeaderFilter $headerFilter,
    ) {
    }

    /**
     * @return bool true if the mail was a moderation response and has been fully
     *              handled (caller should mark it seen and skip normal filtering).
     */
    public function handle(IncomingMail $mail, ListConfig $list): bool
    {
        // localPart, matching ModerationMailer's own accept/reject address —
        // see the comment there for why this must not be $list->name.
        $action = $this->detectAction($mail, $list->localPart);
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

        // Payload shape set by ModerationMailer::send(): [ListFingerprint::of($list->name), moderation_queue.id]
        // — a short fingerprint, not the list's own (unboundedly long) name, since
        // these tokens are embedded in an email address local-part (RFC 5321's
        // 64-byte limit); see ListFingerprint's own docblock. The row's own id,
        // not imap_uid/imap_uidvalidity directly — those are read back from the
        // row itself below, same idea as BounceHandler's queue_recipients.id.
        [$listFingerprint, $itemId] = $payload;
        $itemId = (int) $itemId;

        if ($listFingerprint !== ListFingerprint::of($list->name)) {
            error_log("Listig: Moderation token list mismatch for list {$list->name}");
            return true;
        }

        if (!$list->isOwnedBy($mail->fromAddress ?? '')) {
            error_log("Listig: Moderation $purpose rejected — sender is not an owner of {$list->name}");
            return true;
        }

        // The token's own id (HMAC-verified above) identifies the moderation_queue
        // row; uid/uidvalidity are read back from that row rather than carried in
        // the token itself. This DB lookup also doubles as the idempotency check
        // it always was: a re-sent reminder or a double-click, after the item was
        // already accepted/rejected once and its row deleted below, correctly
        // finds nothing and stops here rather than re-processing it.

        $stmt = $this->db->prepare(
            'SELECT id, list_cn, imap_uid, imap_uidvalidity FROM moderation_queue WHERE id = :id'
        );
        $stmt->execute(['id' => $itemId]);
        $item = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($item === false || $item['list_cn'] !== $list->name) {
            error_log("Listig: Moderation item not found for list {$list->name} id $itemId (already processed?)");
            return true;
        }

        $uid = (int) $item['imap_uid'];
        $uidValidity = (int) $item['imap_uidvalidity'];

        if ($purpose === 'accept') {
            $this->processAccept($list, $uid, $uidValidity);
        } else {
            $this->processReject($list, $uid, $uidValidity);
        }

        $this->db->prepare('DELETE FROM moderation_queue WHERE id = :id')->execute(['id' => $item['id']]);

        return true;
    }

    /**
     * @return array{0: string, 1: string}|null [purpose, token]
     */
    private function detectAction(IncomingMail $mail, string $localPart): ?array
    {
        // Not $mail->to: PhpImap\Mailbox lowercases every recipient address it
        // parses (mb_strtolower(), see possiblyGetEmailAndNameFromRecipient())
        // before $mail->to is ever populated, which corrupts the case-sensitive
        // base64 token embedded in the local-part — TokenService::verify() would
        // then always fail signature verification for a genuine reply. The raw
        // To header still has the address exactly as the sending mail client
        // wrote it, case included.
        $toHeader = $this->headerFilter->readHeader($mail->headersRaw ?? '', 'To') ?? '';
        $pattern = '/' . preg_quote($localPart, '/') . '\+(accept|reject)-(.+?)@/i';
        if (preg_match($pattern, $toHeader, $m)) {
            return [strtolower($m[1]), $m[2]];
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
        $this->imapPoller->markSeen($list, $uid, $uidValidity);
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
        // Best-effort — a missing raw MIME (mail gone between the two fetches)
        // still lets the notice go out, just without the attachment; see
        // RejectionNotifier::notify()'s own $rawMime docblock.
        $rawMime = $this->imapPoller->fetchByUid($list, $uid);

        $this->rejectionNotifier->notify($list, $incomingMail, $rawMime, 'reject.moderation_declined');
        $this->imapPoller->markSeen($list, $uid, $uidValidity);
        $this->imapArchiver->archiveOrDelete($list, $uid);
    }
}
