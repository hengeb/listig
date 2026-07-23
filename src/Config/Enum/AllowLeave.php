<?php

declare(strict_types=1);

namespace Hengeb\Listig\Config\Enum;

enum AllowLeave: string
{
    case Direct = 'direct';
    case Moderated = 'moderated';
}
