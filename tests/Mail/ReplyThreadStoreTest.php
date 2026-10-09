<?php

declare(strict_types=1);

namespace Hengeb\Listig\Tests\Mail;

use Hengeb\Listig\Config\ListConfig;
use Hengeb\Listig\Mail\HeaderFilter;
use Hengeb\Listig\Mail\ReplyThreadStore;
use Hengeb\Listig\Token\TokenService;
use PDO;
use PDOStatement;
use PhpImap\IncomingMail;
use PHPUnit\Framework\TestCase;

class ReplyThreadStoreTest extends TestCase
{
    private function store(array|false $row = ['message_id' => 'a@x', 'thread_root' => 'r@x'], ?TokenService $tokens = null): ReplyThreadStore
    {
        $stmt = $this->createStub(PDOStatement::class);
        $stmt->method('fetch')->willReturn($row);
        $db = $this->createStub(PDO::class);
        $db->method('prepare')->willReturn($stmt);
        return new ReplyThreadStore($db, $tokens ?? new TokenService(str_repeat('k', 32)), new HeaderFilter());
    }

    private function list(string $name = 'news'): ListConfig
    {
        return new ListConfig($name, 'news@example.org', []);
    }

    private function mail(string $to): IncomingMail
    {
        $mail = new IncomingMail();
        $mail->headersRaw = "To: $to\r\n";
        return $mail;
    }

    public function testAddressRoundTrip(): void
    {
        $store = $this->store();
        $address = $store->addressFor($this->list(), 42);
        $this->assertMatchesRegularExpression('/^news\+re-[A-Za-z0-9_-]+@example\.org$/', $address);
        $this->assertLessThanOrEqual(64, strlen(explode('@', $address)[0]), 'RFC 5321 local-part limit');

        $mail = $this->mail($address);
        $token = $store->extractToken($mail, $this->list());
        $this->assertNotNull($token);
        $this->assertSame(['message_id' => 'a@x', 'thread_root' => 'r@x'], $store->resolve($this->list(), $token));
        $this->assertSame(['message_id' => 'a@x', 'thread_root' => 'r@x'], $store->resolveMail($mail, $this->list()));
    }

    public function testTokenOfAnotherListIsRejected(): void
    {
        $store = $this->store();
        $token = $store->extractToken($this->mail($store->addressFor($this->list('other'), 42)), $this->list('other'));
        $this->assertNull($store->resolve($this->list('news'), $token));
    }

    public function testTamperedOrGarbageTokenIsRejected(): void
    {
        $store = $this->store();
        $this->assertNull($store->resolve($this->list(), 'not-a-token'));
        $token = $store->extractToken($this->mail($store->addressFor($this->list(), 42)), $this->list());
        $this->assertNull($store->resolve($this->list(), substr($token, 0, -2) . 'AA'));
    }

    public function testResolveIsNullWhenTheArchivedMailIsGone(): void
    {
        $store = $this->store(false);
        $token = $store->extractToken($this->mail($store->addressFor($this->list(), 42)), $this->list());
        $this->assertNull($store->resolve($this->list(), $token));
    }

    public function testExtractTokenIgnoresOtherTagsAndMixedCaseDomain(): void
    {
        $store = $this->store();
        $this->assertNull($store->extractToken($this->mail('news+r-abc@example.org'), $this->list()), 'masked-reply tag is a different tag');
        $this->assertNull($store->extractToken($this->mail('news@example.org'), $this->list()));
        $this->assertSame('AbC_-1', $store->extractToken($this->mail('News+re-AbC_-1@Example.org'), $this->list()), 'token keeps its case');
    }

    public function testNoTokenOnSubaddressLists(): void
    {
        $list = new ListConfig('news', 'news@example.org', [], subaddressMemberTemplates: ['{subaddress}@example.org']);
        $this->assertNull($this->store()->extractToken($this->mail('news+re-abc@example.org'), $list));
    }
}
