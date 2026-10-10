<?php

declare(strict_types=1);

namespace Hengeb\Listig\Tests\Config\Enum;

use Hengeb\Listig\Config\Enum\ReplyToBehavior;
use PHPUnit\Framework\TestCase;

class ReplyToBehaviorTest extends TestCase
{
    public function testRelayModePerReplyTo(): void
    {
        // every mode relays; all but masked-both privately (list/nobody/sender/both: archive button, {sender-reply-address}).
        $this->assertSame(ReplyToBehavior::MaskedSender, ReplyToBehavior::List->relayMode());
        $this->assertSame(ReplyToBehavior::MaskedSender, ReplyToBehavior::Nobody->relayMode());
        $this->assertSame(ReplyToBehavior::MaskedSender, ReplyToBehavior::Sender->relayMode());
        $this->assertSame(ReplyToBehavior::MaskedSender, ReplyToBehavior::Both->relayMode());
        $this->assertSame(ReplyToBehavior::MaskedSender, ReplyToBehavior::MaskedSender->relayMode());
        $this->assertSame(ReplyToBehavior::MaskedBoth, ReplyToBehavior::MaskedBoth->relayMode());
    }
}
