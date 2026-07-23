<?php

declare(strict_types=1);

namespace Hengeb\Listig\Config\Enum;

enum ArchiveMode: string
{
    case Members = 'members';
    case Owners = 'owners';
    case Public = 'public';
    case Hidden = 'hidden';
    case Off = 'off';
}
