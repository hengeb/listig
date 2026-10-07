<?php

declare(strict_types=1);

namespace Hengeb\Listig\Mail;

use Hengeb\Listig\Config\Enum\SenderNotices;
use Hengeb\Listig\Config\ListConfig;
use Hengeb\Listig\RateLimit\RateLimiter;
use PhpImap\IncomingMail;

/**
 * The single place that decides whether a sender gets a notice about their mail
 * (reject or moderation-pending) and whether the original is attached — see
 * ADR-0018. Listig only sees mail the upstream MTA already accepted, so every
 * notice to a forged From address is backscatter.
 */
class SenderNoticePolicy
{
    /** Reasons that are never notified, whatever `sender-notices` says: forged-looking or spam mail. */
    private const array NEVER_NOTIFY_REASONS = ['reject.auth_failed', 'reject.spam'];

    /** The original is large by definition here; not attached even for authenticated senders. */
    private const array NO_ATTACHMENT_REASONS = ['reject.size_exceeded'];

    public function __construct(
        private readonly SenderAuthenticator $authenticator,
        private readonly RateLimiter $rateLimiter,
        private readonly HeaderFilter $headerFilter,
    ) {
    }

    /**
     * @param string|null $reasonKey the reject reason translation key; null for the moderation-pending notice
     */
    public function decide(ListConfig $list, IncomingMail $mail, ?string $reasonKey): NoticeDecision
    {
        $decision = $this->evaluate($list, $mail, $reasonKey);
        if (!$decision->send && $decision->suppressReason !== 'no_sender') {
            $at = strrpos($mail->fromAddress ?? '', '@');
            error_log(sprintf(
                'Listig: sender notice suppressed (%s) for list %s — reason %s, sender domain %s, Message-ID %s',
                $decision->suppressReason,
                $list->name,
                $reasonKey ?? 'moderation.pending',
                $at === false ? '-' : substr($mail->fromAddress, $at + 1),
                $this->headerFilter->readMessageId($mail->headersRaw ?? '') ?? '-',
            ));
        }
        return $decision;
    }

    private function evaluate(ListConfig $list, IncomingMail $mail, ?string $reasonKey): NoticeDecision
    {
        $sender = strtolower($mail->fromAddress ?? '');
        if ($sender === '') {
            return NoticeDecision::suppress('no_sender');
        }

        $mode = $list->senderNotices;
        if ($mode === SenderNotices::Never) {
            return NoticeDecision::suppress('disabled');
        }
        if ($reasonKey !== null && in_array($reasonKey, self::NEVER_NOTIFY_REASONS, true)) {
            return NoticeDecision::suppress('forged_or_spam');
        }

        $authenticated = $this->authenticator->isAuthenticated($mail->headersRaw ?? '', $sender);
        if ($mode === SenderNotices::Authenticated && !$authenticated) {
            return NoticeDecision::suppress('unauthenticated');
        }

        // Last, so a suppressed notice never uses up the address's quota.
        if ($this->rateLimiter->isNoticeThrottled($sender, $list->senderNoticeInterval)) {
            return NoticeDecision::suppress('throttled');
        }

        return NoticeDecision::send($authenticated && !in_array($reasonKey, self::NO_ATTACHMENT_REASONS, true));
    }
}
