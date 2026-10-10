<?php

declare(strict_types=1);

namespace Hengeb\Listig\Config\Enum;

enum ArchiveMode: string
{
    case Members = 'members';
    case Owners = 'owners';
    /** Every logged-in user (a member or owner of any list), whether or not of this list; guests excluded. */
    case Authenticated = 'authenticated';
    case Public = 'public';
    case Hidden = 'hidden';
    case Off = 'off';
}
