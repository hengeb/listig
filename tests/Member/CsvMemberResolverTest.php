<?php

declare(strict_types=1);

namespace Hengeb\Listig\Tests\Member;

use Hengeb\Listig\Member\CsvMemberResolver;
use Hengeb\Listig\Member\Member;
use PHPUnit\Framework\TestCase;

class CsvMemberResolverTest extends TestCase
{
    private string $file;
    private CsvMemberResolver $resolver;

    protected function setUp(): void
    {
        $this->file = tempnam(sys_get_temp_dir(), 'listig_csv_test_') . '.csv';
        $this->resolver = new CsvMemberResolver($this->file);
    }

    protected function tearDown(): void
    {
        if (file_exists($this->file)) {
            unlink($this->file);
        }
    }

    private function writeCsv(string $content): void
    {
        file_put_contents($this->file, $content);
    }

    public function testMissingFileReturnsNoMembers(): void
    {
        $this->assertSame([], $this->resolver->getMembers('mylist'));
    }

    public function testGetMembersReadsScopedRows(): void
    {
        $this->writeCsv("name,mail,firstname,is_member,is_owner\n"
            . "mylist,alice@example.org,Alice,1,0\n"
            . "otherlist,bob@example.org,Bob,1,0\n");

        $members = $this->resolver->getMembers('mylist');
        $this->assertCount(1, $members);
        $this->assertSame('alice@example.org', $members[0]->email);
        $this->assertSame('Alice', $members[0]->attributes['firstname']);
    }

    public function testGetOwnersFiltersOnIsOwnerColumn(): void
    {
        $this->writeCsv("name,mail,is_member,is_owner\n"
            . "mylist,alice@example.org,1,0\n"
            . "mylist,carol@example.org,1,1\n");

        $owners = $this->resolver->getOwners('mylist');
        $this->assertCount(1, $owners);
        $this->assertSame('carol@example.org', $owners[0]->email);
    }

    public function testArbitraryColumnBecomesAttributeVerbatim(): void
    {
        $this->writeCsv("name,mail,pronoun,mail-aliases,is_member,is_owner\n"
            . "mylist,alice@example.org,she,\"alt@example.org,alt2@example.org\",1,0\n");

        $member = $this->resolver->getMembers('mylist')[0];
        $this->assertSame('she', $member->attributes['pronoun']);
        $this->assertSame('alt@example.org,alt2@example.org', $member->attributes['mail-aliases']);
    }

    public function testFindByEmailIsCaseInsensitive(): void
    {
        $this->writeCsv("name,mail,is_member,is_owner\nmylist,Alice@Example.org,1,0\n");
        $this->assertSame('Alice@Example.org', $this->resolver->findByEmail('alice@example.org')?->email);
    }

    public function testFindByEmailReturnsNullWhenAbsent(): void
    {
        $this->writeCsv("name,mail,is_member,is_owner\nmylist,alice@example.org,1,0\n");
        $this->assertNull($this->resolver->findByEmail('nobody@example.org'));
    }

    public function testAddMemberAppendsNewRow(): void
    {
        $this->writeCsv("name,mail,is_member,is_owner\n");
        $this->resolver->addMember('mylist', new Member('new@example.org', ['firstname' => 'New']));

        $members = $this->resolver->getMembers('mylist');
        $this->assertCount(1, $members);
        $this->assertSame('new@example.org', $members[0]->email);
        $this->assertSame('New', $members[0]->attributes['firstname']);
    }

    public function testAddMemberExtendsHeaderForNewAttributeAndBackfillsOtherRows(): void
    {
        $this->writeCsv("name,mail,is_member,is_owner\nmylist,existing@example.org,1,0\n");
        $this->resolver->addMember('mylist', new Member('new@example.org', ['pronoun' => 'she']));

        $header = explode(',', trim(explode("\n", file_get_contents($this->file))[0]));
        $this->assertContains('pronoun', $header);

        $existing = $this->resolver->findByEmail('existing@example.org');
        $this->assertSame('', $existing->attributes['pronoun'] ?? null, 'existing row backfilled with empty string for the new column');
    }

    public function testAddMemberOnExistingRowSetsIsMemberTrue(): void
    {
        $this->writeCsv("name,mail,is_member,is_owner\nmylist,alice@example.org,0,1\n");
        $this->resolver->addMember('mylist', new Member('alice@example.org'));

        $owners = $this->resolver->getOwners('mylist');
        $this->assertCount(1, $owners, 'is_owner preserved');
        $members = $this->resolver->getMembers('mylist');
        $this->assertCount(1, $members, 'is_member now true');
    }

    public function testRemoveMemberDropsRowEntirelyWhenNotAlsoOwner(): void
    {
        $this->writeCsv("name,mail,is_member,is_owner\nmylist,alice@example.org,1,0\n");
        $this->resolver->removeMember('mylist', 'alice@example.org');
        $this->assertSame([], $this->resolver->getMembers('mylist'));
    }

    public function testRemoveMemberKeepsRowIfStillAnOwner(): void
    {
        $this->writeCsv("name,mail,is_member,is_owner\nmylist,alice@example.org,1,1\n");
        $this->resolver->removeMember('mylist', 'alice@example.org');

        $this->assertSame([], $this->resolver->getMembers('mylist'), 'no longer a member');
        $this->assertCount(1, $this->resolver->getOwners('mylist'), 'still an owner');
    }

    public function testSupportsRemovalIsAlwaysTrue(): void
    {
        $this->assertTrue($this->resolver->supportsRemoval());
    }
}
