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
}
