<?php

declare(strict_types=1);

namespace Hengeb\Listig\Tests\Member;

use Hengeb\Listig\Config\ListConfig;
use Hengeb\Listig\Mail\NotificationMailer;
use Hengeb\Listig\Member\LeaveOutcome;
use Hengeb\Listig\Member\ListLeaver;
use Hengeb\Listig\Member\Member;
use Hengeb\Listig\Member\MemberResolver;
use PHPUnit\Framework\TestCase;
use Symfony\Contracts\Translation\TranslatorInterface;

class ListLeaverTest extends TestCase
{
    private function list(array $raw, MemberResolver $resolver): ListConfig
    {
        return new ListConfig('news', 'news@example.org', $raw, $resolver);
    }

    private function leaver(?NotificationMailer $mailer = null): ListLeaver
    {
        $translator = $this->createStub(TranslatorInterface::class);
        $translator->method('trans')->willReturnArgument(0);
        return new ListLeaver($mailer ?? $this->createStub(NotificationMailer::class), $translator);
    }

    public function testDirectLeaveRemovesTheMember(): void
    {
        $resolver = $this->createMock(MemberResolver::class);
        $resolver->method('supportsRemoval')->willReturn(true);
        $resolver->expects($this->once())->method('removeMember')->with('news', 'm@example.org');

        $this->assertSame(LeaveOutcome::Left, $this->leaver()->leave($this->list([], $resolver), new Member('m@example.org'), 'm@example.org'));
    }

    public function testAStoreThatCannotRemoveIsReportedAndNothingIsAttempted(): void
    {
        $resolver = $this->createMock(MemberResolver::class);
        $resolver->method('supportsRemoval')->willReturn(false);
        $resolver->expects($this->never())->method('removeMember');

        $this->assertSame(LeaveOutcome::NotSupported, $this->leaver()->leave($this->list([], $resolver), null, 'm@example.org'));
    }

    public function testAFailingStoreIsReportedAsNotSupportedNotAsSuccess(): void
    {
        $this->expectErrorLog();
        $resolver = $this->createStub(MemberResolver::class);
        $resolver->method('supportsRemoval')->willReturn(true);
        $resolver->method('removeMember')->willThrowException(new \RuntimeException('directory unreachable'));

        $this->assertSame(LeaveOutcome::NotSupported, $this->leaver()->leave($this->list([], $resolver), null, 'm@example.org'));
    }

    public function testModeratedLeaveOnlyNotifiesTheOwnersAndRemovesNobody(): void
    {
        $resolver = $this->createMock(MemberResolver::class);
        $resolver->expects($this->never())->method('removeMember');
        $mailer = $this->createMock(NotificationMailer::class);
        $mailer->expects($this->once())->method('sendToOwners');

        $outcome = $this->leaver($mailer)->leave($this->list(['allow-leave' => 'moderated'], $resolver), new Member('m@example.org', ['firstname' => 'Mia']), 'm@example.org');
        $this->assertSame(LeaveOutcome::Requested, $outcome);
    }
}
