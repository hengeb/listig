<?php

declare(strict_types=1);

namespace Hengeb\Listig\Config\Enum;

/** Whether the original sender's address is put into an X-Original-Sender-Address header — see MailProcessor::setOutgoingHeaders(). */
enum SenderAddressHeader: string
{
    case Never = 'never';
    /** Only when the sender is not a member of the list. */
    case External = 'external';
    case Always = 'always';
}
