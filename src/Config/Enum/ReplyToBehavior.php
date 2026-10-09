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

    /**
     * The mode that governs a mail to a `+r-{TOKEN}` address (the reply relay), or null if
     * the list doesn't relay replies at all (`list`, `nobody`). `masked-both` also reaches
     * the group; every other relaying mode — including `sender`/`both`, where the relay is
     * only used by the archive's "reply to the author" button — is a private message to the
     * target (`masked-sender` behaviour). See docs/architecture/masked-replies.md.
     */
    public function relayMode(): ?self
    {
        return match ($this) {
            self::List, self::Nobody => null,
            self::Sender, self::Both, self::MaskedSender => self::MaskedSender,
            self::MaskedBoth => self::MaskedBoth,
        };
    }

    public function isMasked(): bool
    {
        return $this === self::MaskedSender || $this === self::MaskedBoth;
    }
}
