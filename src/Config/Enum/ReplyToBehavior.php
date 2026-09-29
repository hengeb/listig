<?php

declare(strict_types=1);

namespace Hengeb\Listig\Config\Enum;

enum ReplyToBehavior: string
{
    case List = 'list';
    case Sender = 'sender';
    /** Reply-To set to both the list address and the original sender — see MailProcessor::setOutgoingHeaders(). */
    case Both = 'both';
    /** Reply-To set to a translated "please do not reply" display name on "noreply@{list->domain}.invalid" — see MailProcessor::setOutgoingHeaders(). */
    case Nobody = 'nobody';
    /**
     * Like Sender, but Reply-To is a signed `{localPart}+r-{TOKEN}@{domain}` address instead of the
     * sender's own — replies are relayed by Listig, the address stays hidden. See ReplyTargetStore.
     */
    case MaskedSender = 'masked-sender';
    /** Like Both, but via the masked token address; the copy to the group is made server-side. */
    case MaskedBoth = 'masked-both';

    public function isMasked(): bool
    {
        return $this === self::MaskedSender || $this === self::MaskedBoth;
    }
}
