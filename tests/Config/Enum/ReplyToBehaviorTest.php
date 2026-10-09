<?php

declare(strict_types=1);

namespace Hengeb\Listig\Tests\Config\Enum;

use Hengeb\Listig\Config\Enum\ReplyToBehavior;
use PHPUnit\Framework\TestCase;

class ReplyToBehaviorTest extends TestCase
{
    public function testRelayModePerReplyTo(): void
    {
        $this->assertNull(ReplyToBehavior::List->relayMode());
        $this->assertNull(ReplyToBehavior::Nobody->relayMode());
        // sender/both only relay for the archive's "reply to the author" button: private, like masked-sender.
        $this->assertSame(ReplyToBehavior::MaskedSender, ReplyToBehavior::Sender->relayMode());
        $this->assertSame(ReplyToBehavior::MaskedSender, ReplyToBehavior::Both->relayMode());
        $this->assertSame(ReplyToBehavior::MaskedSender, ReplyToBehavior::MaskedSender->relayMode());
        $this->assertSame(ReplyToBehavior::MaskedBoth, ReplyToBehavior::MaskedBoth->relayMode());
    }
}
