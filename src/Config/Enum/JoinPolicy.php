<?php

declare(strict_types=1);

namespace Hengeb\Listig\Config\Enum;

enum JoinPolicy: string
{
    /** Any authenticated user who can see the list may join it themselves (web UI "Join" button). */
    case Open = 'open';
    /** Owners add members; nobody can join on their own (default). Only shown in the list info. */
    case Invite = 'invite';
    /** Users ask, owners decide. Not implemented yet — only shown in the list info. */
    case Request = 'request';
}
