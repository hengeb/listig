<?php

declare(strict_types=1);

namespace Hengeb\Listig\Tests\Archive;

use Hengeb\Listig\Archive\ArchiveThreader;
use PHPUnit\Framework\TestCase;

class ArchiveThreaderTest extends TestCase
{
    private ArchiveThreader $threader;

    protected function setUp(): void
    {
        $this->threader = new ArchiveThreader();
    }

    private function row(string $messageId, string $threadRoot, ?string $inReplyTo = null): array
    {
        return ['message_id' => $messageId, 'thread_root' => $threadRoot, 'in_reply_to' => $inReplyTo];
    }

    public function testSingleMessageThreadHasDepthZero(): void
    {
        $rows = $this->threader->annotate([$this->row('m1', 'm1')]);
        $this->assertSame(0, $rows[0]['depth']);
        $this->assertSame(1, $rows[0]['thread_size']);
        $this->assertTrue($rows[0]['is_thread_start']);
    }

    public function testReplyHasIncrementedDepth(): void
    {
        $rows = $this->threader->annotate([
            $this->row('m1', 'm1'),
            $this->row('m2', 'm1', 'm1'),
        ]);
        $this->assertSame(0, $rows[0]['depth']);
        $this->assertSame(1, $rows[1]['depth']);
    }

    public function testDeepReplyChainDepthIncreasesEachLevel(): void
    {
        $rows = $this->threader->annotate([
            $this->row('m1', 'm1'),
            $this->row('m2', 'm1', 'm1'),
            $this->row('m3', 'm1', 'm2'),
        ]);
        $this->assertSame([0, 1, 2], array_column($rows, 'depth'));
    }

    public function testThreadSizeCountsAllRowsSharingThreadRoot(): void
    {
        $rows = $this->threader->annotate([
            $this->row('m1', 'm1'),
            $this->row('m2', 'm1', 'm1'),
            $this->row('m3', 'm1', 'm2'),
        ]);
        $this->assertSame([3, 3, 3], array_column($rows, 'thread_size'));
    }

    public function testParentNotOnPageResultsInDepthZeroNotAnError(): void
    {
        // A reply whose parent isn't present on THIS page (pagination boundary)
        // is still grouped under the same thread_root, just not indented.
        $rows = $this->threader->annotate([
            $this->row('m2', 'm1', 'missing-parent'),
        ]);
        $this->assertSame(0, $rows[0]['depth']);
    }

    public function testIsThreadStartOnlyTrueOnceThreadRootChanges(): void
    {
        // Rows are already SQL-sorted so a thread's rows are contiguous — only the
        // first row of a new thread_root value should be flagged as thread-start.
        $rows = $this->threader->annotate([
            $this->row('m1', 'root-a'),
            $this->row('m2', 'root-a', 'm1'),
            $this->row('m3', 'root-b'),
        ]);
        $this->assertSame([true, false, true], array_column($rows, 'is_thread_start'));
    }

    public function testCyclicalInReplyToDoesNotLoopForever(): void
    {
        // A malformed/cyclical In-Reply-To chain must be bounded, not infinite.
        $rows = $this->threader->annotate([
            $this->row('m1', 'm1', 'm2'),
            $this->row('m2', 'm1', 'm1'),
        ]);
        $this->assertLessThan(50, $rows[0]['depth']);
        $this->assertLessThan(50, $rows[1]['depth']);
    }

    public function testEmptyInputReturnsEmptyArray(): void
    {
        $this->assertSame([], $this->threader->annotate([]));
    }
}
