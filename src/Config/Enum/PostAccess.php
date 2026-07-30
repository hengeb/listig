<?php

declare(strict_types=1);

namespace Hengeb\Listig\Config\Enum;

/**
 * Per-sender-class posting grant — used independently for `post-access-members`
 * and `post-access-public` (see ListConfig::$postAccessMembers/$postAccessPublic).
 * Owners have no config key of their own: they always post, never moderated —
 * see IncomingMailFilter::checkPostAccess()/requiresModeration().
 */
enum PostAccess: string
{
    case Allow = 'allow';
    case Deny = 'deny';
    case Moderate = 'moderate';
}
