<?php

declare(strict_types=1);

namespace Hengeb\Listig\Config\Enum;

enum LeavePolicy: string
{
    case Direct = 'direct';
    case Moderated = 'moderated';
}
