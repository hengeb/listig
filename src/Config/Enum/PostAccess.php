<?php

declare(strict_types=1);

namespace Hengeb\Listig\Config\Enum;

enum PostAccess: string
{
    case Members = 'members';
    case Owners = 'owners';
    case All = 'all';
}
