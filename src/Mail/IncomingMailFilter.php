<?php

declare(strict_types=1);

namespace Hengeb\Listig\Mail;

use Hengeb\Listig\Config\Enum\PostAccess;
use Hengeb\Listig\Config\Enum\ReplyToBehavior;
use Hengeb\Listig\Config\ListConfig;
use Hengeb\Listig\RateLimit\RateLimiter;
use PhpImap\IncomingMail;

class IncomingMailFilter
{
    public function __construct(
        private readonly RateLimiter $rateLimiter,
        private readonly HeaderFilter $headerFilter,
        private readonly SpamFilter $spamFilter,
        private readonly ReplyTargetStore $replyTargetStore,
        private readonly ReplyThreadStore $replyThreadStore,
        private readonly SenderAuthenticator $senderAuthenticator,
    ) {
    }

    public function filter(IncomingMail $mail, ListConfig $list, string $rawMime, array $authResults): FilterResult
    {
        $unfolded = $this->headerFilter->unfold($mail->headersRaw ?? '');

        // 1. X-Loop
        if (preg_match('/^X-Loop:/mi', $unfolded)) {
            return FilterResult::discard();
        }

        // 2. Spam filter (globally configured, but matched with this list's own
        // context — see SpamFilter's docblock on why a rule's pattern needs $list).
        // Both actions force-delete the mail outright (never archived, regardless
        // of the list's own archive: setting) — see FilterResult::$forceDelete.
        //
        // Deliberately before bounce detection (3), the opposite of every other
        // check below it (which all stay after bounce detection, since a real
        // bounce may legitimately fail auth/lack a valid subaddress/etc.) — a
        // spam-content match is meant to take precedence *even* over a mail that
        // also looks like a bounce, specifically so an operator can write a
        // filters: rule to silently drop particular unwanted bounces (e.g. a
        // known noisy auto-responder) without them going through the normal
        // bounce-log + forward-to-owner pipeline at all. Confirmed live: a rule
        // matching a MAILER-DAEMON-from mail applied and the mail never reached
        // isBounce() below, unlike before this reordering.
        $spamAction = $this->spamFilter->match($mail, $list);
        if ($spamAction === 'discard') {
            return FilterResult::discard(forceDelete: true);
        }
        if ($spamAction === 'reject') {
            return FilterResult::reject('reject.spam', forceDelete: true);
        }

        // 3. Bounce detection
        if ($this->isBounce($mail, $unfolded)) {
            return FilterResult::bounce();
        }

        // 3b. Auto-reply (out-of-office etc.) — not a bounce, nothing to act on
        if ($this->isAutoReply($mail, $unfolded)) {
            return FilterResult::discard(forceDelete: true);
        }

        // 4. Subaddress validation (type: subaddress lists only)
        if ($list->subaddressMemberTemplates !== null) {
            $subaddress = SubaddressExtractor::extract($mail, $list);
            if ($subaddress !== null && $this->isReservedSubaddress($subaddress, $list)) {
                return FilterResult::reject('reject.reserved_subaddress');
            }
            if ($subaddress === null && $list->requiresSubaddress) {
                return FilterResult::reject('reject.missing_subaddress');
            }
        }

        // 5. Authentication-Results
        if (($authResults['spf'] ?? null) === 'fail' || ($authResults['dkim'] ?? null) === 'fail') {
            return FilterResult::reject('reject.auth_failed');
        }

        // 6. Size
        if (strlen($rawMime) > $list->maxSize) {
            return FilterResult::reject('reject.size_exceeded', ['%max_size%' => $list->maxSize]);
        }

        // 7. Post-access — owners always allowed; members/public independently
        // allow/deny/moderate (see checkPostAccess()). Only 'deny' is decided
        // here; 'moderate' falls through to the rate limiter first, same as
        // 'allow' — moderated senders are not exempt from rate limiting.
        //
        // A mail to a masked-reply address (`{localPart}+r-{TOKEN}@…`, see
        // ReplyTargetStore / docs/architecture/masked-replies.md "Masked reply addresses") has its own
        // rules instead, see checkMaskedReply(). Not applicable to type:
        // subaddress lists, whose `+…` addresses mean something else.
        $senderEmail = $mail->fromAddress ?? '';
        $replyToken = $list->subaddressMemberTemplates === null
            ? $this->replyTargetStore->extractToken($mail, $list)
            : null;
        $accessResult = $replyToken !== null
            ? $this->checkMaskedReply($list, $senderEmail, $replyToken)
            : $this->checkPostAccess($list, $senderEmail);
        if ($accessResult !== null) {
            return $accessResult;
        }

        // 7b. A mail to a `+re-{TOKEN}` address (the archive's "reply to this mail" button)
        // must still name an archived mail — an expired token or a deleted/pruned mail is
        // rejected with a hint rather than silently posted as a new thread (ADR-0020).
        $threadToken = $replyToken === null ? $this->replyThreadStore->extractToken($mail, $list) : null;
        if ($threadToken !== null && $this->replyThreadStore->resolve($list, $threadToken) === null) {
            return FilterResult::reject('reject.reply_thread_unknown');
        }

        // 7c. A From address the receiving server could not verify (post-access-unauthenticated,
        // ADR-0024). After the access checks, so a sender who may not post at all is told that
        // first; before the rate limit, so a mail that is held or refused does not count. Applies to
        // every sender class equally — a forged owner address is the worst case. A mail that cannot
        // be moderated (a private `+r-` relay never reaches the list) is refused instead of held.
        $unverifiedMode = $list->postAccessUnauthenticated;
        $heldAsUnverified = false;
        if ($unverifiedMode !== PostAccess::Allow
            && !$this->senderAuthenticator->isAuthenticated($mail->headersRaw ?? '', $senderEmail, $list->trustedAuthservIds)
        ) {
            $moderable = $replyToken === null || $list->replyTo->relayMode() === ReplyToBehavior::MaskedBoth;
            if ($unverifiedMode === PostAccess::Deny || !$moderable) {
                return FilterResult::reject('reject.unauthenticated');
            }
            $heldAsUnverified = true;
        }

        // 8. Rate limit
        if ($this->rateLimiter->isExceeded($list->name, $senderEmail, $list->maxPerSender)) {
            return FilterResult::reject('reject.rate_limited');
        }

        // masked-sender replies never reach the list, so they are never moderated either.
        $moderable = $replyToken === null || $list->replyTo->relayMode() === ReplyToBehavior::MaskedBoth;
        if ($moderable && ($heldAsUnverified || $this->requiresModeration($list, $senderEmail))) {
            // A moderation item nobody can ever accept/reject is worse than an
            // outright rejection — without this, the mail would silently vanish
            // (ModerationMailer::send() logs and no-ops on empty owners) with no
            // feedback to the sender at all.
            if (empty($list->getOwners())) {
                return FilterResult::reject('reject.no_owners');
            }
            return FilterResult::moderation();
        }

        return FilterResult::distribute();
    }

    private function isBounce(IncomingMail $mail, string $unfolded): bool
    {
        // Auto-Submitted present and != 'no'. PhpImap\Mailbox::getMailHeaderFieldValue()
        // (which populates $mail->autoSubmitted) is typed to always return string, never
        // null, using '' for "header absent" — despite IncomingMailHeader's own @var
        // string|null docblock claiming otherwise. Checking only "!== null" was always
        // false→true here (an empty string is never null), so every mail lacking an
        // Auto-Submitted header — i.e. essentially all normal mail — was misclassified
        // as a bounce and forwarded to the owner instead of ever reaching distribute().
        //
        // `auto-replied` (RFC 3834: out-of-office and similar responders) is
        // deliberately *not* a bounce signal on its own — see isAutoReply(). Only
        // `auto-generated` (DSNs, system notices) and other values count here.
        $autoSubmitted = strtolower(trim($mail->autoSubmitted ?? ''));
        if ($autoSubmitted !== '' && $autoSubmitted !== 'no' && $autoSubmitted !== 'auto-replied') {
            return true;
        }

        // multipart/report; report-type=delivery-status
        if (preg_match('/^Content-Type:\s*multipart\/report[^;]*;\s*report-type\s*=\s*delivery-status/mi', $unfolded)) {
            return true;
        }

        // From contains MAILER-DAEMON or postmaster
        $from = strtolower(($mail->fromAddress ?? '') . ' ' . ($mail->fromName ?? ''));
        if (str_contains($from, 'mailer-daemon') || str_contains($from, 'postmaster')) {
            return true;
        }

        // Subject matches bounce patterns
        if (preg_match('/^(delivery status|mail delivery failed|undelivered mail)/i', $mail->subject ?? '')) {
            return true;
        }

        return false;
    }

    /**
     * A human-facing auto-responder (out-of-office): `Auto-Submitted: auto-replied`
     * (RFC 3834), `X-Auto-Response-Suppress` or `Precedence: auto_reply`. Only
     * consulted after isBounce() has ruled out real DSNs/system mail, so anything
     * reaching here carries no delivery-failure information. Silently dropped —
     * logging it in bounce_log and forwarding it to the owners would be pure noise
     * and could trip BounceHandler's circuit breaker, suppressing real bounces.
     */
    private function isAutoReply(IncomingMail $mail, string $unfolded): bool
    {
        if (strtolower(trim($mail->autoSubmitted ?? '')) === 'auto-replied') {
            return true;
        }
        return (bool) preg_match('/^(X-Auto-Response-Suppress:|Precedence:\s*auto_reply)/mi', $unfolded);
    }

    /**
     * A `restricted-members:` hit (see ListConfig::isSenderRestricted() /
     * RestrictionList — global, provider, or list level, see docs/architecture/config.md "Global
     * / provider / list levels") is checked first and overrides everything
     * below it, including owner status: a global ban is meant to be absolute,
     * even for someone who's still an owner. Owners and `senders:` (see
     * ListConfig::$authorizedSenders — a poster without becoming a
     * member/owner, e.g. a board that shouldn't receive owner-only bounce
     * mail) then always pass, no config key of their own (see
     * docs/reference/list-config-keys.md, "post-access-members"/"post-access-public"). A member or public sender
     * with PostAccess::Deny is rejected here; Allow and Moderate both pass —
     * the Allow/Moderate distinction is decided later, by requiresModeration(),
     * after rate limiting has had a chance to run.
     */
    private function checkPostAccess(ListConfig $list, string $senderEmail): ?FilterResult
    {
        if ($list->isSenderRestricted($senderEmail)) {
            return FilterResult::reject('reject.sender_restricted');
        }

        if ($list->isOwnedBy($senderEmail) || $list->isAuthorizedSender($senderEmail)) {
            return null;
        }

        $isMember = $list->isMember($senderEmail);
        $mode = $isMember ? $list->postAccessMembers : $list->postAccessPublic;

        if ($mode === PostAccess::Deny) {
            return FilterResult::reject($isMember ? 'reject.members_denied' : 'reject.public_denied');
        }

        return null;
    }

    /**
     * Access rules for a mail to a `+r-{TOKEN}` address: only a member, owner or `senders:`
     * address may use it (an outsider holding a leaked token is rejected), and the target
     * must still resolve. `restricted-members:` applies as always. `post-access-members`
     * applies only to masked-both, whose reply is also distributed to the group —
     * masked-sender reaches a single person and never the list, so deny/moderate don't
     * apply there.
     */
    private function checkMaskedReply(ListConfig $list, string $senderEmail, string $token): ?FilterResult
    {
        if ($list->replyTo->relayMode() === null) {
            return FilterResult::reject('reject.reply_not_enabled');
        }
        if ($list->isSenderRestricted($senderEmail)) {
            return FilterResult::reject('reject.sender_restricted');
        }
        if (!$list->isMember($senderEmail) && !$list->isOwnedBy($senderEmail) && !$list->isAuthorizedSender($senderEmail)) {
            return FilterResult::reject('reject.reply_not_allowed');
        }
        if ($this->replyTargetStore->resolve($list, $token) === null) {
            return FilterResult::reject('reject.reply_target_unknown');
        }
        return $list->replyTo->relayMode() === ReplyToBehavior::MaskedBoth ? $this->checkPostAccess($list, $senderEmail) : null;
    }

    /**
     * Owners and `senders:` are never moderated — see checkPostAccess() and docs/architecture/moderation.md
     * "Moderation".
     */
    private function requiresModeration(ListConfig $list, string $senderEmail): bool
    {
        if ($list->isOwnedBy($senderEmail) || $list->isAuthorizedSender($senderEmail)) {
            return false;
        }

        $mode = $list->isMember($senderEmail) ? $list->postAccessMembers : $list->postAccessPublic;
        return $mode === PostAccess::Moderate;
    }

    private function isReservedSubaddress(string $subaddress, ListConfig $list): bool
    {
        $lower = strtolower($subaddress);
        if ($lower === 'bounce') {
            return true;
        }
        if (str_starts_with($lower, 'accept-') || str_starts_with($lower, 'reject-')) {
            return true;
        }
        return in_array($lower, $list->reservedSubaddresses, true);
    }
}
