<?php

declare(strict_types=1);

namespace Hengeb\Listig\Mail;

use Hengeb\Listig\Config\Enum\PostAccess;
use Hengeb\Listig\Config\ListConfig;
use Hengeb\Listig\RateLimit\RateLimiter;
use PhpImap\IncomingMail;

class IncomingMailFilter
{
    public function __construct(
        private readonly RateLimiter $rateLimiter,
        private readonly HeaderFilter $headerFilter,
        private readonly SpamFilter $spamFilter,
    ) {
    }

    public function filter(IncomingMail $mail, ListConfig $list, string $rawMime, array $authResults): FilterResult
    {
        $unfolded = $this->headerFilter->unfold($mail->headersRaw ?? '');

        // 1. X-Loop
        if (preg_match('/^X-Loop:/mi', $unfolded)) {
            return FilterResult::discard();
        }

        // 2. Bounce detection
        if ($this->isBounce($mail, $unfolded)) {
            return FilterResult::bounce();
        }

        // 3. Subaddress validation (type: subaddress lists only)
        if ($list->subaddressMemberTemplates !== null) {
            $subaddress = SubaddressExtractor::extract($mail, $list);
            if ($subaddress !== null && $this->isReservedSubaddress($subaddress, $list)) {
                return FilterResult::reject('reject.reserved_subaddress');
            }
            if ($subaddress === null && $list->requiresSubaddress) {
                return FilterResult::reject('reject.missing_subaddress');
            }
        }

        // 4. Spam filter (global, list-independent — see filters: in config.yml)
        if ($this->spamFilter->matches($mail)) {
            return FilterResult::reject('reject.spam');
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
        $senderEmail = $mail->fromAddress ?? '';
        $accessResult = $this->checkPostAccess($list, $senderEmail);
        if ($accessResult !== null) {
            return $accessResult;
        }

        // 8. Rate limit
        if ($this->rateLimiter->isExceeded($list->name, $senderEmail, $list->maxPerSender)) {
            return FilterResult::reject('reject.rate_limited');
        }

        if ($this->requiresModeration($list, $senderEmail)) {
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
        $autoSubmitted = $mail->autoSubmitted;
        if ($autoSubmitted !== null && $autoSubmitted !== '' && strtolower(trim($autoSubmitted)) !== 'no') {
            return true;
        }

        // X-Auto-Response-Suppress present
        if (preg_match('/^X-Auto-Response-Suppress:/mi', $unfolded)) {
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
     * Owners always pass (no config key of their own — see CLAUDE.md
     * "post-access-members"/"post-access-public"). A member or public sender
     * with PostAccess::Deny is rejected here; Allow and Moderate both pass —
     * the Allow/Moderate distinction is decided later, by requiresModeration(),
     * after rate limiting has had a chance to run.
     */
    private function checkPostAccess(ListConfig $list, string $senderEmail): ?FilterResult
    {
        if ($list->isOwnedBy($senderEmail)) {
            return null;
        }

        $isMember = $list->isMember($senderEmail);
        $mode = $isMember ? $list->postAccessMembers : $list->postAccessPublic;

        if ($mode === PostAccess::Deny) {
            return FilterResult::reject($isMember ? 'reject.members_denied' : 'reject.public_denied');
        }

        return null;
    }

    /** Owners are never moderated — see checkPostAccess() and CLAUDE.md "Moderation". */
    private function requiresModeration(ListConfig $list, string $senderEmail): bool
    {
        if ($list->isOwnedBy($senderEmail)) {
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
