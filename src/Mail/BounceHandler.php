<?php

declare(strict_types=1);

namespace Hengeb\Listig\Mail;

use Hengeb\Listig\Config\Enum\BounceAction;
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
 * (see BounceCause/BounceCauseClassifier) — a spam-rejection reported by a
 * reliable domain aborts every other still-pending queued copy of the same
 * original mail; a permanent "user/mailbox unknown" (or an escalated,
 * repeatedly-recurring "mailbox full") applies the list's own configurable
 * `bounce-action` (none/mark-invalid/restrict/remove, via
 * BounceMemberActionExecutor) instead. A single, temporary "mailbox full"
 * bounce only defers that recipient's *future* sends by `bounce-defer-days`
 * (handleMailboxFull()) rather than acting immediately. This exists because a
 * bounce can arrive asynchronously, via IMAP, *while* QueueSender is still
 * working through the rest of the same batch across later worker cycles —
 * without the spam case specifically, a mail one reliable provider has
 * already rejected as spam kept being sent to every remaining recipient
 * regardless. See CLAUDE.md "Automatic bounce actions".
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
 * resolveVerifiedRecipient()/isDkimAuthenticated(), and CLAUDE.md
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
 * 2. **Whether this bounce is genuine enough to act on** — even bound to the
 *    *correct* recipient, the DSN's content (does it really say "spam"?) is
 *    still just text; a malicious member could in principle read their own
 *    token (e.g. via a provider that exposes Return-Path on "view original")
 *    and hand-craft a fake bounce for their own row. What this actually lets
 *    them do is deliberately self-limited, though: the token only ever
 *    resolves to *their own* queue_recipients row (see 1 above) — so a
 *    forged bounce can never claim to be about anyone but the forger
 *    themselves. For BounceCause::UserUnknown/MailboxFull, whose actions
 *    (mark-invalid/restrict/remove/defer) only ever touch that one
 *    recipient's own subscription, that residual risk amounts to "a member
 *    can deliberately sabotage their own subscription" — no worse than what
 *    they could already achieve by running a real mail server for their own
 *    domain that genuinely bounces its own mail, or by just asking to be
 *    unsubscribed. A required null envelope-from (Return-Path: <>, RFC 3464/
 *    5321's own DSN convention) is still enforced for every cause — it costs
 *    nothing to keep and rules out a bounce sent through a reputable
 *    provider's ordinary authenticated-user submission path, which doesn't
 *    allow a null envelope sender — but DKIM authentication is *not*
 *    additionally required for these two causes. BounceCause::Spam is the
 *    one exception: its action (aborting delivery to every *other* pending
 *    recipient of the batch) reaches beyond the bounced recipient
 *    themselves, so a forged self-bounce there would let a malicious member
 *    disrupt delivery to people who never consented to anything — that blast
 *    radius is what justifies requiring either isDkimAuthenticated()
 *    (DKIM-verified for the recipient's own domain — the async-DSN shape) or
 *    isFromTrustedRelay() (the bounce genuinely arrived over a connection
 *    from the operator's own configured outbound relay — the live-SMTP-
 *    rejection-reflected-by-our-own-relay shape, for which DKIM from the
 *    recipient's domain is structurally never available) on top of the
 *    null-envelope check, plus the further reliable-domain bar in
 *    abortBatchForBounce() — see all three docblocks.
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

    /**
     * Fixed prefix for queue_recipients.error whenever markBounced() records
     * an authenticated bounce — distinct from an ordinary SMTP failure's own
     * (arbitrary) error text, so countRecentBounces() can query specifically
     * for bounce-caused failures rather than any delivery failure.
     */
    private const string ERROR_TAG_PREFIX = 'BOUNCE:';

    public function __construct(
        private readonly PDO $db,
        private readonly NotificationMailer $notificationMailer,
        private readonly TranslatorInterface $translator,
        private readonly HeaderFilter $headerFilter,
        private readonly QueueSender $queueSender,
        private readonly BounceCauseClassifier $bounceCauseClassifier,
        private readonly TokenService $tokenService,
        private readonly SpamRejectionDetector $spamRejectionDetector,
        private readonly BounceMemberActionExecutor $memberActionExecutor,
        private readonly int $bounceDeferDays,
        private readonly int $bounceEscalateAfter,
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
     * e.g. a permanent "user unknown" bounce drives a configurable
     * mark-invalid/restrict/remove action instead of Spam's abort-batch one:
     * add a new BounceCause case, a new check in BounceCauseClassifier, and a
     * new match arm below. Recipient resolution, the final-outcome gate, and
     * the null-envelope check all apply uniformly to any cause, not just
     * Spam, since they concern *whether this bounce can be trusted at all* —
     * as does the retroactive markBounced() call right before the match,
     * which corrects that one recipient's own queue_recipients row for every
     * recognized cause, not just the ones with a further automatic action.
     * The DKIM check is the one exception, gated to Spam only *after*
     * classification — see the class docblock's point 2 for why.
     */
    private function applyAutomaticAction(ListConfig $list, string $rawMime): string
    {
        $recipient = $this->resolveVerifiedRecipient($list, $rawMime);
        if ($recipient === null) {
            return $this->noAutomaticAction($list);
        }

        if (!$this->isFinalDeliveryOutcome($rawMime)) {
            return $this->noAutomaticAction($list);
        }

        if (!$this->hasNullReturnPath($rawMime)) {
            return $this->noAutomaticAction($list);
        }

        $reason = $this->extractClassificationText($rawMime);
        $cause  = $this->bounceCauseClassifier->classify($reason);
        if ($cause === null) {
            return $this->noAutomaticAction($list);
        }

        // Spam's action reaches beyond the bounced recipient (aborts
        // delivery to every other pending recipient of the batch too), so it
        // alone needs a cryptographic/connection-level bar on top of the
        // null-envelope check above — UserUnknown/MailboxFull deliberately
        // don't require either, since their actions only ever affect the
        // token-verified recipient's own subscription (see the class
        // docblock's point 2). Two independent, alternative ways to satisfy
        // this for Spam (either is sufficient — see isFromTrustedRelay()'s
        // own docblock for why a second path exists at all):
        // - isDkimAuthenticated(): the *recipient's own domain* generated
        //   and signed this bounce itself (an async DSN sent after
        //   accepting the mail into its own queue).
        // - isFromTrustedRelay(): the bounce was relayed back by the
        //   *operator's own* outbound relay, reflecting a rejection it
        //   received live during its own SMTP session with the recipient's
        //   domain — a shape that can never carry DKIM from that domain at
        //   all, since the domain itself never generated an outbound
        //   message.
        if (
            $cause === BounceCause::Spam
            && !$this->isDkimAuthenticated($rawMime, $recipient['envelopeTo'])
            && !$this->isFromTrustedRelay($rawMime)
        ) {
            return $this->noAutomaticAction($list);
        }

        // Corrects the historical record for this one row (e.g. 'sent' ->
        // 'failed') regardless of which specific cause matched — see
        // QueueSender::markBounced()'s own docblock. retry_not_before is only
        // ever set for MailboxFull; every other cause passes null.
        $retryNotBefore = $cause === BounceCause::MailboxFull
            ? (new \DateTimeImmutable())->modify("+{$this->bounceDeferDays} days")
            : null;
        $this->queueSender->markBounced($recipient['recipientId'], self::errorTagFor($cause), $retryNotBefore);

        return match ($cause) {
            BounceCause::Spam => $this->abortBatchForBounce($list, $recipient['envelopeTo'], $recipient['batchId']),
            BounceCause::UserUnknown => $this->applyConfiguredAction($list, $recipient['envelopeTo'], $cause),
            BounceCause::MailboxFull => $this->handleMailboxFull($list, $recipient['envelopeTo']),
        };
    }

    /**
     * RFC 3464's per-recipient Action: field (message/delivery-status part) —
     * `delayed` means the sending MTA is still retrying and this is merely an
     * interim courtesy notice, not a final outcome; acting on it (aborting a
     * batch, marking an address invalid, ...) based on a delivery that might
     * still succeed would be premature. Treated as a required gate for
     * *every* cause, including the pre-existing Spam one — a "delayed"
     * notice whose text happens to mention "spam" was never meant to trigger
     * anything either. Absent entirely (some non-standard bounce generators
     * omit it) is treated as "final" rather than blocking everything — the
     * pre-existing behavior before this check existed, and the same
     * fail-open choice already made for every other best-effort DSN field
     * extraction in this class.
     */
    private function isFinalDeliveryOutcome(string $rawMime): bool
    {
        $action = $this->headerFilter->readHeader($rawMime, 'Action');
        return $action === null || strtolower(trim($action)) === 'failed';
    }

    /**
     * The automatic action for a hard bounce (BounceCause::UserUnknown) or an
     * escalated repeated soft bounce (BounceCause::MailboxFull, via
     * handleMailboxFull()) — dispatches on the list's own configured
     * `bounce-action` (see CLAUDE.md "Automatic bounce actions"). `none`
     * (the default) still returns a description distinct from
     * noAutomaticAction()'s own "none" — here, a cause *was* recognized, an
     * operator has simply chosen not to act on it automatically, which is
     * worth saying explicitly rather than looking identical to "nothing
     * matched at all".
     */
    private function applyConfiguredAction(ListConfig $list, string $envelopeTo, BounceCause $cause): string
    {
        $reasonCode = self::reasonCodeFor($cause);

        return match ($list->bounceAction) {
            BounceAction::None => $this->translator->trans('bounce.auto_action.recognized_no_action', [
                '%cause%' => $this->translator->trans('bounce.cause.' . strtolower($reasonCode), [], null, $list->language),
            ], null, $list->language),
            BounceAction::MarkInvalid => $this->memberActionExecutor->markInvalid($list, $envelopeTo, $reasonCode),
            BounceAction::Restrict => $this->memberActionExecutor->restrict($list, $envelopeTo, $reasonCode),
            BounceAction::Remove => $this->memberActionExecutor->remove($list, $envelopeTo),
        };
    }

    /**
     * A reliable domain's own automated infrastructure genuinely reported
     * this recipient's mailbox as full — a temporary condition, so the first
     * (few) occurrence(s) only defer this recipient's *future* sends by
     * `bounce-defer-days` (the retry_not_before markBounced() already set
     * above), rather than acting immediately. Once countRecentBounces()
     * shows the configured `bounce-escalate-after` threshold reached — i.e.
     * this address kept bouncing even after being given time to recover —
     * escalate to the same configurable action a permanent bounce would
     * trigger (applyConfiguredAction()).
     */
    private function handleMailboxFull(ListConfig $list, string $envelopeTo): string
    {
        $count = $this->queueSender->countRecentBounces(
            $list->name,
            $envelopeTo,
            self::errorTagFor(BounceCause::MailboxFull),
        );

        if ($count >= $this->bounceEscalateAfter) {
            return $this->applyConfiguredAction($list, $envelopeTo, BounceCause::MailboxFull);
        }

        return $this->translator->trans('bounce.auto_action.mailbox_full_deferred', [
            '%days%' => $this->bounceDeferDays,
            '%count%' => $count,
        ], null, $list->language);
    }

    private static function reasonCodeFor(BounceCause $cause): string
    {
        return match ($cause) {
            BounceCause::Spam => 'SPAM',
            BounceCause::UserUnknown => 'USER_UNKNOWN',
            BounceCause::MailboxFull => 'MAILBOX_FULL',
        };
    }

    private static function errorTagFor(BounceCause $cause): string
    {
        return self::ERROR_TAG_PREFIX . self::reasonCodeFor($cause);
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
     * or if the row it names no longer exists (aged out of
     * QueueSender::purgeCompletedEntries()'s 30-day retention — nothing left
     * to act on either way).
     *
     * @return array{recipientId: int, envelopeTo: string, batchId: ?string}|null
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

        $recipientId = (int) $recipientId;
        $recipient = $this->queueSender->findRecipientById($recipientId);
        if ($recipient === null || $recipient['listCn'] !== $list->name) {
            return null;
        }

        return ['recipientId' => $recipientId, 'envelopeTo' => $recipient['envelopeTo'], 'batchId' => $recipient['batchId']];
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
     * DKIM-authenticated (Authentication-Results' dkim=pass) for *that same*
     * domain (header.d=, not the message's own claimed From/Sender) as the
     * token-verified recipient's own address — rules out a bounce sent from
     * outside that domain's infrastructure entirely, e.g. an attacker's own
     * mail server forging a "spam" report for a recipient they have no
     * relationship to.
     *
     * Only ever checked for BounceCause::Spam (see applyAutomaticAction()) —
     * not a generic authenticity gate for every cause. UserUnknown/
     * MailboxFull don't call this at all: their actions
     * (mark-invalid/restrict/remove/defer) only ever affect the one,
     * token-verified recipient's own subscription, so the worst a forged
     * bounce could do there is let that same recipient sabotage their own
     * subscription — no worse than what they could already do with real mail
     * infrastructure of their own (see the class docblock's point 2). Spam's
     * action reaches every *other* pending recipient of the batch too, which
     * is what justifies the extra cryptographic bar here, on top of the
     * null-envelope check already required for every cause.
     *
     * Deliberately does **not** also require $envelopeTo's domain to be one
     * SpamRejectionDetector already trusts (BUILTIN_DOMAINS/
     * reliable-spam-reporters:) — that's abortBatchForBounce()'s own,
     * additional check, since "is this bounce genuinely DKIM-signed by the
     * claimed domain" and "do we trust that domain's opinion instance-wide"
     * are two independent questions.
     */
    private function isDkimAuthenticated(string $rawMime, string $envelopeTo): bool
    {
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
     * A second, alternative way to authenticate a BounceCause::Spam bounce
     * when isDkimAuthenticated() structurally can never pass — confirmed
     * live in production: a recipient's own mail server can reject a
     * message as spam *during the live SMTP session itself* (Diagnostic-Code
     * type "smtp;" per RFC 3464 — the diagnostic text is the literal SMTP
     * reply quoted verbatim). When the operator's own outbound mail routes
     * through their own relay/smarthost rather than connecting directly to
     * the recipient's MX, Listig's own QueueSender::sendOne() never sees
     * that live rejection at all — its own send() to the local relay
     * succeeds, and only the relay's own later, independent delivery
     * attempt to the recipient's domain fails. That relay then generates
     * *its own* bounce notification reflecting the failure, which is what
     * eventually reaches Listig via IMAP. Nothing about that shape involves
     * the recipient's domain generating or signing anything — no DSN of
     * theirs ever exists to DKIM-authenticate, by construction, the exact
     * same reason DNS-failure bounces (BounceCause::UserUnknown via
     * "unable to route") can never carry DKIM either.
     *
     * The trustworthy signal isn't the bounce's *content* (any of it — From,
     * Diagnostic-Code, an operator-domain claim — is attacker-supplied text
     * an outsider submitting mail into Listig's own inbox fully controls,
     * exactly like every other DSN field this class already refuses to
     * trust directly) but the *connection(s)* it actually arrived over:
     * HeaderFilter::readAllConnectingIps() walks every Received: header the
     * outer bounce carries — added by whichever mail server actually
     * observed each hop, never attacker-influenced, same trust level
     * already relied on for Return-Path — and this method rejects if *any*
     * of them is a genuinely public IP (HeaderFilter::isPublicIp() — false
     * for RFC 1918/4193 private ranges, loopback, and other reserved
     * ranges).
     *
     * A single topmost-header check would NOT be enough — confirmed live: a
     * combined send+receive mail server (Postfix handing a message to its
     * own mailbox via LMTP, a common self-hosted setup) always shows its
     * own private IP on that final, innermost hop *regardless of whether the
     * message was genuinely generated locally or merely externally
     * SMTP-submitted and then delivered locally*, so that hop alone can't
     * distinguish a real bounce from a forged one submitted straight into
     * Listig's inbox. Walking *every* hop closes that gap: a real Postfix-
     * generated bounce's earlier hop has no "from" clause at all
     * (`Received: by HOST (Postfix)` — proof of purely local injection,
     * never touched an external connection), while a forged bounce
     * submitted via SMTP would show a genuine "from ATTACKER-HOST (...
     * [ATTACKER-IP])" hop the receiving server itself added — impossible
     * for the attacker to suppress or fake away, regardless of what other
     * Received-looking text they stuff into their own submitted body,
     * since the real one is always prepended above it by trusted
     * infrastructure.
     *
     * Deliberately config-free: no operator setting names a "trusted relay"
     * — every hop is judged purely by whether it ever left a private
     * network (RFC 1918/4193, loopback, ...), which needs no configuration
     * to evaluate and covers the common case (a single self-hosted mail
     * server, or a small private network of them, handling both outbound
     * sending and inbound delivery) with zero setup. A deployment whose real
     * relay path genuinely crosses a public IP boundary (e.g. an external
     * smarthost/SaaS relay) simply won't authenticate via this path for
     * BounceCause::Spam — isDkimAuthenticated() remains available whenever
     * the recipient's own domain does sign an async DSN, and otherwise the
     * bounce is still logged and forwarded to the owner, just without the
     * automatic batch-abort.
     */
    private function isFromTrustedRelay(string $rawMime): bool
    {
        // Scoped to the outer bounce's own headers only — the quoted
        // original message's own historical Received chain (which may pass
        // through any number of unrelated third-party systems, see
        // extractOriginalSender()'s identical scoping) says nothing about
        // whether *this* bounce is genuine.
        $pos = $this->findQuotedOriginalOffset($rawMime);
        $outerHeaders = $pos === null ? $rawMime : substr($rawMime, 0, $pos);

        foreach ($this->headerFilter->readAllConnectingIps($outerHeaders) as $ip) {
            if (HeaderFilter::isPublicIp($ip)) {
                return false;
            }
        }

        return true;
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
     * A domain's own automated infrastructure (already proven authentic by
     * the null envelope-from check in applyAutomaticAction() plus
     * isDkimAuthenticated() — matching DKIM) reported this recipient's copy
     * as spam via an async DSN, not a live SMTP rejection — QueueSender's own
     * synchronous path (SpamRejectionDetector, checked inside sendOne()) only
     * ever sees a live send() failure, so this is the async equivalent:
     * discard every other still-pending queued copy of the same original
     * mail, found via the verified recipient's own batch_id, rather than
     * keep sending a message this domain has already rejected as spam to
     * everyone else too.
     *
     * Unlike UserUnknown/MailboxFull, this action's blast radius reaches
     * *every other pending recipient of the batch*, not just the one whose
     * copy actually bounced — so, on top of isDkimAuthenticated()'s origin
     * authenticity check (which only proves *this* domain genuinely said
     * so), this additionally requires $envelopeTo's domain to be one
     * SpamRejectionDetector already trusts to have an authoritative opinion
     * about its own mail instance-wide (BUILTIN_DOMAINS/
     * reliable-spam-reporters:, the same boundary the synchronous
     * SMTP-rejection path uses). Without this second gate, a genuine
     * subscriber running their own small/self-hosted mail server could
     * report their *own*, real, authenticated bounce as "spam" and get
     * Listig to stop delivering to every other recipient too — a
     * self-authenticated claim is enough to act on that one person's own
     * subscription, but not enough to extrapolate to everyone else's.
     *
     * Falls back to noAutomaticAction() if the domain isn't reliable, the
     * verified recipient's row had no batch_id, or nothing was actually
     * still pending by the time this ran — nothing happened, so the owner
     * notice should say so rather than claim an abort that didn't do
     * anything.
     */
    private function abortBatchForBounce(ListConfig $list, string $envelopeTo, ?string $batchId): string
    {
        if (!$this->spamRejectionDetector->isReliableDomain($envelopeTo)) {
            return $this->noAutomaticAction($list);
        }

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
     * Position of whichever marker starts the quoted original message this
     * bounce is reporting on — `message/rfc822` (a full attached original,
     * Postfix's own convention, confirmed live for the DNS-failure/spam
     * bounce from this operator's own relay) or `text/rfc822-headers` (RFC
     * 3798's headers-only variant, confirmed live from web.de, which never
     * uses `message/rfc822` at all for this). Returns the earlier of the two
     * if somehow both appear, or null if neither does.
     *
     * A single fixed marker isn't enough — confirmed live as a real gap, not
     * just a theoretical one: every method here that scopes a search to "the
     * outer bounce only" (isFromTrustedRelay(), isBounceOnOwnNotification())
     * or "the quoted original only" (extractOriginalSender(),
     * hasQuotedSpamFlag()) previously looked for `message/rfc822` alone.
     * Against a web.de bounce (no `message/rfc822` anywhere, only
     * `text/rfc822-headers`), that made `stripos()` return `false`
     * unconditionally — so extractOriginalSender() always showed "unknown"
     * for this shape of bounce, and worse, isFromTrustedRelay() had nothing
     * to cut the raw text at all, silently letting the *quoted original's
     * own* Received: chain (which passes through whichever infrastructure
     * originally relayed that message — a genuinely public IP in the
     * confirmed case, unrelated to whether *this bounce* is genuine) leak
     * into the hop-scan meant to cover only the bounce's own transport.
     */
    private function findQuotedOriginalOffset(string $rawMime): ?int
    {
        $positions = [];
        foreach (['message/rfc822', 'text/rfc822-headers'] as $marker) {
            $pos = stripos($rawMime, $marker);
            if ($pos !== false) {
                $positions[] = $pos;
            }
        }
        return $positions === [] ? null : min($positions);
    }

    /**
     * True if the quoted original message of this bounce is itself one of
     * Listig's own auto-generated notifications (NotificationMailer's
     * X-Listig-Auto header) — i.e. this is a bounce *on a bounce forward*,
     * not a bounce on an original member/owner-authored mail. This is what
     * actually breaks the loop: forwardToOwners() sends every bounce
     * notification through NotificationMailer, which stamps that same header
     * on its own output, so a bounce on *that* forward is recognized here and
     * dropped rather than being treated as a brand-new bounce and forwarded
     * again.
     *
     * Searches only from findQuotedOriginalOffset() onward — a standard
     * bounce carries the original message (however it's quoted) after the
     * human-readable explanation and delivery-status parts, so this can't
     * accidentally match something in the outer bounce's own headers
     * instead.
     */
    private function isBounceOnOwnNotification(string $rawMime): bool
    {
        $pos = $this->findQuotedOriginalOffset($rawMime);
        if ($pos === null) {
            return false;
        }
        return $this->headerFilter->readHeader(substr($rawMime, $pos), NotificationMailer::AUTO_HEADER) !== null;
    }

    /**
     * True if the quoted original message's own headers — the message this
     * bounce is reporting on, not the bounce's own outer headers — carry a
     * positive SpamAssassin-style spam-classification header
     * (`X-Spam-Flag: YES` or `X-Spam-Status: Yes`). Both are SpamAssassin's
     * own conventions, but widely emulated across many self-hosted and
     * hosted mail systems (Rspamd included, in compatibility mode) — not
     * specific to any one provider. Confirmed live: web.de's own inbound
     * filter tags a rejected message this way *before* generating the
     * bounce, then echoes the (now-tagged) original headers back via a
     * `text/rfc822-headers` part.
     *
     * Only the header's *value* counts, not merely its presence — "NO" is
     * exactly as common as "YES", and the header *name* itself already
     * contains the substring "spam" regardless of value, so a naive
     * presence check (or blindly concatenating this text into what
     * SpamRejectionDetector::containsSpamIndicator() scans) would treat
     * `X-Spam-Flag: NO` as a positive match too.
     *
     * Scoped to *after* findQuotedOriginalOffset() specifically because the
     * outer bounce carries its own, unrelated spam-flag header — confirmed
     * live as a real, easy-to-conflate gotcha in this exact production
     * bounce: the outer DSN had `X-Spam-Flag: NO` (web.de's own opinion of
     * the notification *it* was sending out) while the quoted original had
     * `X-Spam-Flag: YES` (web.de's opinion of the message that actually got
     * rejected) — reading the *first* occurrence anywhere in the raw text,
     * as HeaderFilter::readHeader() normally does, would have found the
     * wrong one here.
     *
     * No separate authentication of its own is needed: this is just another
     * piece of content inside a bounce whose *origin* (not its content) is
     * already gated by the null-envelope/isDkimAuthenticated()/
     * isFromTrustedRelay() checks in applyAutomaticAction() before
     * classification ever runs — same trust boundary Diagnostic-Code/Status
     * already rely on.
     */
    private function hasQuotedSpamFlag(string $rawMime): bool
    {
        $pos = $this->findQuotedOriginalOffset($rawMime);
        if ($pos === null) {
            return false;
        }

        $quoted = substr($rawMime, $pos);
        foreach (['X-Spam-Flag', 'X-Spam-Status'] as $header) {
            $value = $this->headerFilter->readHeader($quoted, $header);
            if ($value !== null && stripos(trim($value), 'yes') === 0) {
                return true;
            }
        }

        return false;
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
     *
     * Display only (the owner notice's %reason%) — see
     * extractClassificationText() for what BounceCauseClassifier actually
     * sees, which is deliberately not just this.
     */
    private function extractDiagnostic(string $rawMime): ?string
    {
        return $this->headerFilter->readHeader($rawMime, 'Diagnostic-Code')
            ?? $this->headerFilter->readHeader($rawMime, 'Status');
    }

    /**
     * Unlike extractDiagnostic() (display only, prefers the more readable
     * Diagnostic-Code and stops there), this concatenates *both*
     * Diagnostic-Code and Status and hands the combination to
     * BounceCauseClassifier — confirmed live as a real, not just
     * theoretical, gap: a genuine Postfix "domain doesn't exist" bounce had
     * `Diagnostic-Code: X-Postfix; Host or domain name not found. Name
     * service error for name=... type=AAAA: Host not found` (no status code
     * anywhere in that free text at all) alongside a perfectly clean,
     * separate `Status: 5.4.4` — which extractDiagnostic()'s own
     * "Diagnostic-Code wins if present" preference meant the classifier
     * never even saw. Many MTAs split the same information this way: a
     * human-readable explanation in one field, the machine-readable
     * Enhanced Status Code in the other, with no guarantee either field
     * alone carries what BounceCauseClassifier needs — so classification
     * gets both, while the owner notice still shows only the more readable
     * one.
     *
     * A third source, hasQuotedSpamFlag(), covers bounces whose
     * Diagnostic-Code/Status carry nothing classifiable at all — confirmed
     * live: a web.de bounce's own delivery-status part had only the
     * generic, uninformative `Status: 5.0.0` ("other/undefined", RFC 3463
     * §3.8) with no Diagnostic-Code at all, yet the *quoted original*
     * message's own headers (see hasQuotedSpamFlag()'s docblock) carried a
     * clear `X-Spam-Flag: YES`. Appending the literal word "spam" on a
     * positive match reuses SpamRejectionDetector::containsSpamIndicator()
     * — already checked first by BounceCauseClassifier — with no change
     * needed there at all.
     */
    private function extractClassificationText(string $rawMime): ?string
    {
        $diagnostic = $this->headerFilter->readHeader($rawMime, 'Diagnostic-Code');
        $status     = $this->headerFilter->readHeader($rawMime, 'Status');
        $spamFlag   = $this->hasQuotedSpamFlag($rawMime) ? 'spam' : null;
        $combined   = trim(($diagnostic ?? '') . ' ' . ($status ?? '') . ' ' . ($spamFlag ?? ''));
        return $combined === '' ? null : $combined;
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
     * of the *quoted original message*, not the outer bounce's own From:
     * (typically MAILER-DAEMON@..., not useful here). A standard bounce carries
     * the original message (however it's quoted, see
     * findQuotedOriginalOffset()) after the human-readable explanation and
     * delivery-status parts, so searching for the first From: header only
     * from that point onward skips the outer one.
     */
    private function extractOriginalSender(string $rawMime): ?string
    {
        $pos = $this->findQuotedOriginalOffset($rawMime);
        if ($pos === null) {
            return null;
        }
        return $this->headerFilter->readHeader(substr($rawMime, $pos), 'From');
    }
}
