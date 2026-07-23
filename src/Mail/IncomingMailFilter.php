<?php

declare(strict_types=1);

namespace Hengeb\Listig\Mail;

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

        // 7. Post-access
        $senderEmail = $mail->fromAddress ?? '';
        $accessResult = $this->checkPostAccess($list, $senderEmail);
        if ($accessResult !== null) {
            return $accessResult;
        }

        // 8. Rate limit
        if ($this->rateLimiter->isExceeded($list->name, $senderEmail, $list->maxPerSender)) {
            return FilterResult::reject('reject.rate_limited');
        }

        if ($list->moderation->value === 'on') {
            return FilterResult::moderation();
        }

        return FilterResult::distribute();
    }

    private function isBounce(IncomingMail $mail, string $unfolded): bool
    {
        // Auto-Submitted present and != 'no'
        $autoSubmitted = $mail->autoSubmitted;
        if ($autoSubmitted !== null && strtolower(trim($autoSubmitted)) !== 'no') {
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

    private function checkPostAccess(ListConfig $list, string $senderEmail): ?FilterResult
    {
        $postAccess = $list->postAccess;

        if ($postAccess->value === 'all') {
            return null;
        }

        $isMember = $list->isMember($senderEmail);
        $isOwner  = $list->isOwnedBy($senderEmail);

        if ($postAccess->value === 'owners' && !$isOwner) {
            return FilterResult::reject('reject.owners_only');
        }
        if ($postAccess->value === 'members' && !$isMember && !$isOwner) {
            return FilterResult::reject('reject.members_only');
        }

        return null;
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
