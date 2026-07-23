<?php

declare(strict_types=1);

namespace Hengeb\Listig\Config\Enum;

enum ReplyToBehavior: string
{
    case List = 'list';
    case Sender = 'sender';
}
