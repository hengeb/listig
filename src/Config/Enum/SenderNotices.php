<?php

declare(strict_types=1);

namespace Hengeb\Listig\Config\Enum;

enum SenderNotices: string
{
    /** Notices only to senders whose mail is DMARC-aligned authenticated (default). See SenderNoticePolicy. */
    case Authenticated = 'authenticated';
    /** Notices to every sender (throttled), the original attached only if authenticated. Never for spam / SPF-DKIM fail. */
    case Always = 'always';
    case Never = 'never';
}
