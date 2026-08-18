<?php

declare(strict_types=1);

namespace Hengeb\Listig\Mail;

use Hengeb\Listig\Config\ListConfig;
use Hengeb\Listig\Queue\QueueSender;
use Hengeb\Listig\Queue\SpamRejectionDetector;
use Hengeb\Listig\Token\TokenService;
use PDO;
use PhpImap\IncomingMail;
use Symfony\Contracts\Translation\TranslatorInterface;

/**
 * Records a bounce in bounce_log and forwards the original bounce mail to the
 * list owners. Extracted from bin/worker.php to keep that file a thin loop and
 * match the rest of the codebase's constructor-injected, class-based design.
 *
 * Also applies an automatic action for certain, well-recognized bounce causes
 * — today, only a spam-rejection reported by a reliable domain, which aborts
 * every other still-pending queued copy of the same original mail (see
 * applyAutomaticAction()/BounceCauseClassifier). This exists because a bounce
 * can arrive asynchronously, via IMAP, *while* QueueSender is still working
 * through the rest of the same batch across later worker cycles — without
 * this, a mail one reliable provider has already rejected as spam kept being
 * sent to every remaining recipient regardless. See CLAUDE.md "Automatic
 * bounce actions".
 *
 * RFC 3464 delivery-status notifications carry no cryptographic
 * authentication at all — every field in a DSN's body (Final-Recipient, the
 * attached original message's own Message-ID, Diagnostic-Code) is plain text
 * an attacker fully controls, whether or not they have any genuine
 * relationship to the domain they claim. Trusting that content directly
 * would let *any* sender able to deliver mail into this list's own inbox
 * forge a "spam" bounce for an address they merely claim, and get Listig to
 * abort delivery to every real recipient of a batch that address was never
 * actually part of. Two independent mechanisms close this (see
 * resolveVerifiedRecipient()/isAuthenticatedOrigin(), and CLAUDE.md
 * "Automatic bounce actions" for the full reasoning):
 *
 * 1. **Who this bounce concerns** is never read from the DSN's own claims —
 *    QueueSender::sendOne() assigns each recipient a unique, HMAC-signed
 *    bounce address (`{list->localPart}+bounce+{token}@{list->domain}`,
 *    VERP-style); resolveVerifiedRecipient() decodes *that* token from
 *    wherever the DSN actually got delivered back to, and looks up the real
 *    queue_recipients row it names. A forged bounce cannot claim to be about
 *    an address it wasn't actually sent to, since it would need a token it
 *    has no way to derive.
 * 2. **Whether this bounce is genuine at all** — even bound to the *correct*
 *    recipient, the DSN's content (does it really say "spam"?) is still just
 *    text; a malicious member could read their own token (e.g. via a
 *    provider that exposes Return-Path on "view original") and hand-craft a
 *    fake bounce for their own row. isAuthenticatedOrigin() requires the
 *    incoming bounce to be genuinely DKIM-authenticated for the recipient's
 *    own domain *and* delivered with a null envelope-from (Return-Path: <>)
 *    — a combination only that domain's own automated postmaster
 *    infrastructure can produce, since a reputable provider's ordinary
 *    user-facing submission path does not let an authenticated end user send
 *    with a null envelope sender (a defense against backscatter/spam abuse,
 *    not a Listig-specific convention).
 *
 * A bounce-forward is itself an outgoing mail (via NotificationMailer), which
 * means it can itself bounce — and that new bounce would, without the two
 * guards in handle() below, be forwarded again, producing another
 * notification for the owner's server to possibly reject again, and so on.
 * Confirmed live: a single spam-rejected distributed mail produced roughly
 * 100 consecutive bounces this way before these guards existed. See
 * isBounceOnOwnNotification() (the primary fix) and the bounce-log circuit
 * breaker in handle() (the last-resort safety net) — plus
 * NotificationMailer's own null-sender envelope and X-Listig-Auto/
 * Auto-Submitted headers, which this class's detection depends on.
 */
class BounceHandler
{
    /** Trips the circuit breaker once more than this many bounces have been logged for a list within CIRCUIT_BREAKER_WINDOW_MINUTES — see handle(). */
    private const int CIRCUIT_BREAKER_THRESHOLD = 5;

    /** Rolling window (minutes) the circuit breaker counts bounces over — see handle(). */
    private const int CIRCUIT_BREAKER_WINDOW_MINUTES = 15;

    public function __construct(
        private readonly PDO $db,
        private readonly NotificationMailer $notificationMailer,
        private readonly TranslatorInterface $translator,
        private readonly HeaderFilter $headerFilter,
        private readonly QueueSender $queueSender,
        private readonly BounceCauseClassifier $bounceCauseClassifier,
        private readonly TokenService $tokenService,
        private readonly SpamRejectionDetector $spamRejectionDetector,
    ) {
    }

    public function handle(ListConfig $list, IncomingMail $mail, string $rawMime): void
    {
        $this->logBounce($list->name, $mail);

        if ($this->isBounceOnOwnNotification($rawMime)) {
            return;
        }

        // The automatic action (e.g. aborting the rest of a spam-rejected
        // batch) is a protective measure against the underlying distributed
        // mail itself, independent of whether the owner actually gets
        // notified about this particular bounce below — it still runs even
        // while the circuit breaker is suppressing forwards, since a burst of
        // bounces is exactly the situation where it matters most.
        $autoAction = $this->applyAutomaticAction($list, $rawMime);

        if ($this->circuitBreakerTripped($list->name)) {
            return;
        }

        $this->forwardToOwners($list, $mail, $rawMime, $autoAction);
    }

    /**
     * Resolves+verifies which recipient this bounce genuinely concerns,
     * confirms the bounce is authentically from that recipient's own
     * domain's automated infrastructure, classifies its (now-trustworthy)
     * reason text (via BounceCauseClassifier) and, if it maps to a known
     * cause, executes the matching automatic action — always returns a
     * translated description for the owner notice's own "Automatic
     * response:" line, never null: the overwhelmingly common case (bounce
     * doesn't resolve to a verified recipient, isn't authenticated, or no
     * cause recognized) still gets an explicit "none"
     * (bounce.auto_action.none) rather than the line silently disappearing,
     * so an owner reading the notice always knows whether Listig reacted or
     * not, not just when it did.
     *
     * Extension point for future causes (see BounceCause's own docblock) —
     * e.g. a permanent "user unknown" bounce could eventually drive a
     * block-or-remove-member action instead of Spam's abort-batch one: add a
     * new BounceCause case, a new check in BounceCauseClassifier, and a new
     * match arm below. Both verification steps above already apply
     * uniformly to any cause, not just Spam, since they concern *whether
     * this bounce can be trusted at all*, not what its content says.
     */
    private function applyAutomaticAction(ListConfig $list, string $rawMime): string
    {
        $recipient = $this->resolveVerifiedRecipient($list, $rawMime);
        if ($recipient === null) {
            return $this->noAutomaticAction($list);
        }

        if (!$this->isAuthenticatedOrigin($rawMime, $recipient['envelopeTo'])) {
            return $this->noAutomaticAction($list);
        }

        $reason = $this->extractDiagnostic($rawMime);
        $cause  = $this->bounceCauseClassifier->classify($reason);
        if ($cause === null) {
            return $this->noAutomaticAction($list);
        }

        return match ($cause) {
            BounceCause::Spam => $this->abortBatchForBounce($list, $recipient['batchId']),
        };
    }

    /**
     * Decodes and verifies the per-recipient bounce token QueueSender::sendOne()
     * assigned (see the class docblock) from wherever this bounce actually
     * arrived addressed to, and looks up the real queue_recipients row it
     * names. This is the *only* trustworthy source for "which recipient/batch
     * does this bounce concern" — never the DSN's own self-reported
     * Final-Recipient or attached-message Message-ID, both of which an
     * attacker fully controls.
     *
     * Returns null if no token could be found or it fails to verify (wrong
     * signature, expired, wrong purpose), if it names a different list than
     * the one this bounce arrived on (defense in depth against a stale/
     * cross-list token, same principle as UnsubscribeController's own check),
     * or if the row it names no longer exists (already cleaned up after
     * fully sending — nothing left to act on either way).
     *
     * @return array{envelopeTo: string, batchId: ?string}|null
     */
    private function resolveVerifiedRecipient(ListConfig $list, string $rawMime): ?array
    {
        $token = $this->extractBounceToken($rawMime);
        if ($token === null) {
            return null;
        }

        try {
            [$listCn, $recipientId] = $this->tokenService->verify($token, 'bounce', QueueSender::BOUNCE_TOKEN_MAX_AGE);
        } catch (\InvalidArgumentException $e) {
            error_log("Listig: Invalid bounce token for list {$list->name}: " . $e->getMessage());
            return null;
        }

        if ($listCn !== $list->name) {
            error_log("Listig: Bounce token list mismatch for list {$list->name}");
            return null;
        }

        $recipient = $this->queueSender->findRecipientById((int) $recipientId);
        if ($recipient === null || $recipient['listCn'] !== $list->name) {
            return null;
        }

        return ['envelopeTo' => $recipient['envelopeTo'], 'batchId' => $recipient['batchId']];
    }

    /**
     * Extracts the bounce token from the address this bounce was actually
     * delivered to — checked against To/Delivered-To/X-Original-To, in that
     * order, since which header carries the real final-delivery address
     * depends on the receiving mail server's own conventions; a standard DSN
     * addresses itself to the original envelope-from (the per-recipient
     * bounce address QueueSender::sendOne() set), so To is normally enough.
     *
     * Reads the *raw*, unparsed header text (HeaderFilter::readHeader()),
     * not $mail->to — PhpImap\Mailbox lowercases every parsed recipient
     * address (mb_strtolower()) before $mail->to is populated, which would
     * corrupt the case-sensitive base64 token, exactly the same reason
     * ModerationResponseHandler::detectAction() reads the raw To header
     * instead of $mail->to for the accept/reject token.
     */
    private function extractBounceToken(string $rawMime): ?string
    {
        foreach (['To', 'Delivered-To', 'X-Original-To'] as $header) {
            $value = $this->headerFilter->readHeader($rawMime, $header);
            if ($value !== null && preg_match('/\+bounce\+([A-Za-z0-9_.\-]+)@/', $value, $m)) {
                return $m[1];
            }
        }
        return null;
    }

    /**
     * Whether this bounce is trustworthy enough to act on its own content at
     * all — independent of which BounceCause the content might indicate, see
     * the class docblock for the full threat model. $envelopeTo is the real,
     * token-verified recipient address (never anything read from the DSN's
     * own claims). Three conditions, all required:
     *
     * 1. $envelopeTo's domain is one SpamRejectionDetector already trusts to
     *    have an authoritative verdict about its own mail
     *    (SpamRejectionDetector::BUILTIN_DOMAINS / the optional
     *    reliable-spam-reporters: config.yml key) — the same trust boundary
     *    the synchronous SMTP-rejection path already uses. A self-hosted or
     *    otherwise unknown domain's own bounce, even a perfectly
     *    DKIM-authenticated and null-envelope one, proves the message is a
     *    genuine automated DSN from that domain — not that its "spam"
     *    opinion is worth trusting instance-wide.
     * 2. Delivered with a null envelope-from (Return-Path: <>, RFC 3464/5321's
     *    own convention for a DSN — the same one NullSenderEnvelope uses for
     *    Listig's own outgoing notifications). Reputable providers do not let
     *    an ordinary authenticated user submit mail with a null envelope
     *    sender via their normal submission path (a defense against
     *    backscatter/spam abuse on their end, not a Listig-specific
     *    assumption) — so this rules out a forged bounce sent through the
     *    recipient's own real account.
     * 3. DKIM-authenticated (Authentication-Results' dkim=pass) for *that
     *    same* domain (header.d=, not the message's own claimed From/Sender)
     *    — rules out a forged bounce sent from outside the domain's own
     *    infrastructure entirely, e.g. an attacker's own mail server.
     *
     * Only a genuinely automated system running on the recipient's own
     * domain's infrastructure can satisfy both 2 and 3 at once: sending
     * through that domain's real systems gets a real DKIM signature (3), but
     * only its own internal postmaster/bounce-generation systems — not an
     * ordinary user's own submission — get to use a null envelope-from (2).
     */
    private function isAuthenticatedOrigin(string $rawMime, string $envelopeTo): bool
    {
        if (!$this->spamRejectionDetector->isReliableDomain($envelopeTo)) {
            return false;
        }

        if (!$this->hasNullReturnPath($rawMime)) {
            return false;
        }

        $authResults = $this->headerFilter->readAuthResults($rawMime);
        if (($authResults['dkim'] ?? null) !== 'pass') {
            return false;
        }

        $dkimDomain = $authResults['dkimDomain'] ?? null;
        if ($dkimDomain === null) {
            return false;
        }

        return $dkimDomain === $this->spamRejectionDetector->domainOf($envelopeTo);
    }

    /**
     * Whether the bounce mail's own Return-Path header (added by Listig's
     * own receiving mail server at final delivery, not attacker-controlled)
     * is the empty/null form (Return-Path: <>). Reads the *outer* bounce's
     * own header — the "first occurrence anywhere in the raw bounce" this
     * relies on is safe here for the same reason extractDiagnostic() already
     * documents: a standard DSN's own trace headers always precede the
     * attached original message, so this can't accidentally match a stale
     * Return-Path from the original message's own prior delivery history.
     */
    private function hasNullReturnPath(string $rawMime): bool
    {
        $value = $this->headerFilter->readHeader($rawMime, 'Return-Path');
        return $value !== null && trim($value) === '<>';
    }

    /**
     * A reliable domain's own automated infrastructure (see
     * isAuthenticatedOrigin()) genuinely reported this recipient's copy as
     * spam via an async DSN, not a live SMTP rejection — QueueSender's own
     * synchronous path (SpamRejectionDetector, checked inside sendOne())
     * only ever sees a live send() failure, so this is the async
     * equivalent: discard every other still-pending queued copy of the same
     * original mail, found via the verified recipient's own batch_id, rather
     * than keep sending a message a reliable provider has already rejected
     * as spam to everyone else too.
     *
     * Falls back to noAutomaticAction() if the verified recipient's row had
     * no batch_id, or nothing was actually still pending by the time this
     * ran — nothing happened, so the owner notice should say so rather than
     * claim an abort that didn't do anything.
     */
    private function abortBatchForBounce(ListConfig $list, ?string $batchId): string
    {
        if ($batchId === null) {
            return $this->noAutomaticAction($list);
        }

        $discarded = $this->queueSender->discardPendingBatch(
            $batchId,
            'Aborted: an authenticated async bounce from a reliable domain reported this mail as spam',
        );

        if ($discarded === 0) {
            return $this->noAutomaticAction($list);
        }

        return $this->translator->trans(
            'bounce.auto_action.abort_batch',
            ['%count%' => $discarded],
            null,
            $list->language,
        );
    }

    private function noAutomaticAction(ListConfig $list): string
    {
        return $this->translator->trans('bounce.auto_action.none', [], null, $list->language);
    }

    /**
     * True if the message/rfc822 attachment of this bounce is itself one of
     * Listig's own auto-generated notifications (NotificationMailer's
     * X-Listig-Auto header) — i.e. this is a bounce *on a bounce forward*,
     * not a bounce on an original member/owner-authored mail. This is what
     * actually breaks the loop: forwardToOwners() sends every bounce
     * notification through NotificationMailer, which stamps that same header
     * on its own output, so a bounce on *that* forward is recognized here and
     * dropped rather than being treated as a brand-new bounce and forwarded
     * again.
     *
     * Mirrors extractOriginalSender()'s own approach of searching only from
     * the first message/rfc822 marker onward — a standard bounce carries the
     * original message as a message/rfc822 part after the human-readable
     * explanation and delivery-status parts, so this can't accidentally match
     * something in the outer bounce's own headers instead.
     */
    private function isBounceOnOwnNotification(string $rawMime): bool
    {
        $pos = stripos($rawMime, 'message/rfc822');
        if ($pos === false) {
            return false;
        }
        return $this->headerFilter->readHeader(substr($rawMime, $pos), NotificationMailer::AUTO_HEADER) !== null;
    }

    /**
     * Last-resort safety net beyond isBounceOnOwnNotification(): that check
     * only catches a bounce whose own X-Listig-Auto header survived intact in
     * the attached original message — a bounce generator that reformats,
     * truncates, or otherwise mangles the attached original (some do) could
     * still slip through undetected. If a list has already logged more than
     * $threshold bounces within the last $windowMinutes minutes (the just-
     * logged one from handle() included), stop forwarding entirely until it
     * cools down, rather than let a fast loop through whatever gap remains.
     * Uses bounce_log's own idx_list_time index (list_cn, bounced_at) — a
     * single indexed COUNT(*), not a new query shape.
     */
    private function circuitBreakerTripped(
        string $listCn,
        int $threshold = self::CIRCUIT_BREAKER_THRESHOLD,
        int $windowMinutes = self::CIRCUIT_BREAKER_WINDOW_MINUTES,
    ): bool {
        $cutoff = (new \DateTimeImmutable())->modify("-{$windowMinutes} minutes")->format('Y-m-d H:i:s');

        $stmt = $this->db->prepare(
            'SELECT COUNT(*) FROM bounce_log WHERE list_cn = :list AND bounced_at > :cutoff'
        );
        $stmt->execute(['list' => $listCn, 'cutoff' => $cutoff]);

        $count = (int) $stmt->fetchColumn();
        if ($count > $threshold) {
            error_log(
                "Listig: Bounce circuit breaker tripped for list $listCn ($count bounces in the last "
                . "$windowMinutes minutes) — not forwarding to owners until it cools down."
            );
            return true;
        }

        return false;
    }

    private function logBounce(string $listCn, IncomingMail $mail): void
    {
        // Lets the manage page's bounce table offer a click-through preview, the
        // same way ArchiveIndexer keys an archived_mail row — null when archive
        // is off (the bounce mail gets deleted, not archived, by
        // ImapArchiver::archiveOrDelete() right after this) or the bounce mail
        // simply had no Message-ID; either way BounceController degrades to a
        // "mail unavailable" preview rather than erroring, same as the archive
        // viewer already does for a missing mail.
        $messageId = $this->headerFilter->readMessageId($mail->headersRaw ?? '');

        $stmt = $this->db->prepare(
            'INSERT INTO bounce_log (list_cn, sender, subject, message_id, bounced_at) VALUES (:list, :sender, :subject, :message_id, NOW())'
        );
        $stmt->execute([
            'list'       => $listCn,
            'sender'     => $mail->fromAddress ?? '',
            'subject'    => $mail->subject,
            'message_id' => $messageId,
        ]);
    }

    private function forwardToOwners(ListConfig $list, IncomingMail $mail, string $rawMime, string $autoAction): void
    {
        $sender  = $mail->fromAddress ?? 'unknown';
        $subject = $mail->subject ?? '';
        $locale  = $list->language;

        $unknown = $this->translator->trans('bounce.unknown', [], null, $locale);
        $reason          = $this->extractDiagnostic($rawMime) ?? $unknown;
        $failedRecipient = $this->extractFailedRecipient($rawMime) ?? $unknown;
        $originalSender  = $this->extractOriginalSender($rawMime) ?? $unknown;

        $this->notificationMailer->sendToOwners(
            $list,
            $this->translator->trans('bounce.owner_notice.subject', [
                '%list%' => $list->displayName,
                '%sender%' => $sender,
            ], null, $locale),
            // %auto_action% is always present — applyAutomaticAction() never
            // returns null, so the owner can always see whether Listig
            // reacted automatically, not just when it did (see its docblock).
            $this->translator->trans('bounce.owner_notice.body', [
                '%list%' => $list->displayName,
                '%sender%' => $sender,
                '%subject%' => $subject,
                '%reason%' => $reason,
                '%failed_recipient%' => $failedRecipient,
                '%original_sender%' => $originalSender,
                '%auto_action%' => $autoAction,
            ], null, $locale),
            $rawMime,
            'bounce.eml',
            'message/rfc822',
        );
    }

    /**
     * RFC 3464 delivery-status field carrying the actual failure reason, e.g.
     * "smtp; 550 5.1.1 <user@example.com>: Recipient address rejected: User
     * unknown". Diagnostic-Code is preferred over the terser numeric Status
     * (e.g. "5.1.1") when both are present. HeaderFilter::readHeader() finds the
     * first occurrence anywhere in the raw bounce — safe here because a standard
     * DSN always has its own delivery-status part (where this lives) before the
     * attached original message, so it can't accidentally match something inside
     * the original mail's own body/headers instead.
     */
    private function extractDiagnostic(string $rawMime): ?string
    {
        return $this->headerFilter->readHeader($rawMime, 'Diagnostic-Code')
            ?? $this->headerFilter->readHeader($rawMime, 'Status');
    }

    /**
     * RFC 3464's Final-Recipient/Original-Recipient fields — the address delivery
     * actually failed for. Values look like "rfc822;user@example.com", so the
     * "rfc822;" address-type prefix is stripped.
     *
     * Display only (the owner notice's %failed_recipient%) — never used for
     * the automatic-action decision, which relies solely on the token-verified
     * recipient (resolveVerifiedRecipient()), not this self-reported DSN claim.
     */
    private function extractFailedRecipient(string $rawMime): ?string
    {
        $value = $this->headerFilter->readHeader($rawMime, 'Final-Recipient')
            ?? $this->headerFilter->readHeader($rawMime, 'Original-Recipient');
        return $value !== null ? preg_replace('/^rfc822;\s*/i', '', $value) : null;
    }

    /**
     * Who originally posted the mail that bounced — read from the From: header
     * of the *attached original message*, not the outer bounce's own From:
     * (typically MAILER-DAEMON@..., not useful here). A standard bounce carries
     * the original message as a message/rfc822 part after the human-readable
     * explanation and delivery-status parts, so searching for the first From:
     * header only from that point onward skips the outer one.
     */
    private function extractOriginalSender(string $rawMime): ?string
    {
        $pos = stripos($rawMime, 'message/rfc822');
        if ($pos === false) {
            return null;
        }
        return $this->headerFilter->readHeader(substr($rawMime, $pos), 'From');
    }
}
