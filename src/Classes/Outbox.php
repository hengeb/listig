<?php
declare(strict_types=1);

namespace Hengeb\Listig;

use PHPMailer\PHPMailer\PHPMailer;

class Outbox extends PHPMailer {
    public function addrAppend($type, $addr)
    {
        if ($type === 'To') {
            return '';
        } else {
            return parent::addrAppend($type, $addr);
        }
    }
}
