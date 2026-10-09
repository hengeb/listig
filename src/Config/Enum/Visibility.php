<?php

declare(strict_types=1);

namespace Hengeb\Listig\Config\Enum;

enum Visibility: string
{
    /** Listed for every authenticated user (dashboard "Other lists" and the list's info page). */
    case Public = 'public';
    /** Only members and owners see the list (default). */
    case Members = 'members';
    /** Only owners see the list. */
    case Hidden = 'hidden';
}
