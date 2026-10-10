<?php

declare(strict_types=1);

namespace Hengeb\Listig\Config\Enum;

/** Which address a distributed mail carries in From — see MailProcessor::setOutgoingHeaders(). */
enum FromAddress: string
{
    /** The list address (display name from `smtp-from-name`). */
    case List = 'list';
    /** The sender's masked `{localPart}+r-{TOKEN}@{domain}` address: replying to the sender alone reaches them through the relay. */
    case Masked = 'masked';
}
