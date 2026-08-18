<?php

declare(strict_types=1);

namespace Hengeb\Listig\Tests\Config;

use Hengeb\Listig\Config\YamlIncludeResolver;
use PHPUnit\Framework\TestCase;

class YamlIncludeResolverTest extends TestCase
{
    private string $dir;
    private array $files = [];

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/listig_yaml_include_test_' . uniqid();
        mkdir($this->dir);
    }

    protected function tearDown(): void
    {
        foreach ($this->files as $file) {
            @unlink($file);
        }
        @rmdir($this->dir);
    }

    private function write(string $name, string $content): string
    {
        $path = $this->dir . '/' . $name;
        file_put_contents($path, $content);
        $this->files[] = $path;
        return $path;
    }

    public function testPlainYamlWithoutIncludesParsesNormally(): void
    {
        $path = $this->write('main.yml', "key: value\n");
        $result = YamlIncludeResolver::parseFile($path);
        $this->assertSame(['key' => 'value'], $result);
    }

    public function testIncludeSplicesReferencedFileContentInPlace(): void
    {
        $this->write('members.yml', "- alice@example.org\n- bob@example.org\n");
        $path = $this->write('main.yml', "members: !include members.yml\n");

        $result = YamlIncludeResolver::parseFile($path);
        $this->assertSame(['alice@example.org', 'bob@example.org'], $result['members']);
    }

    public function testIncludePathIsRelativeToIncludingFilesOwnDirectory(): void
    {
        mkdir($this->dir . '/sub');
        $this->files[] = $this->dir . '/sub'; // cleaned up separately below
        file_put_contents($this->dir . '/sub/nested.yml', "value: nested\n");
        $path = $this->write('main.yml', "included: !include sub/nested.yml\n");

        $result = YamlIncludeResolver::parseFile($path);
        $this->assertSame('nested', $result['included']['value']);
        @unlink($this->dir . '/sub/nested.yml');
        @rmdir($this->dir . '/sub');
    }

    public function testNestedIncludeIsRelativeToItsOwnFilesDirectory(): void
    {
        mkdir($this->dir . '/sub');
        file_put_contents($this->dir . '/sub/inner.yml', "value: deeply-nested\n");
        file_put_contents($this->dir . '/sub/middle.yml', "nested: !include inner.yml\n");
        $path = $this->write('main.yml', "outer: !include sub/middle.yml\n");

        $result = YamlIncludeResolver::parseFile($path);
        $this->assertSame('deeply-nested', $result['outer']['nested']['value']);

        @unlink($this->dir . '/sub/inner.yml');
        @unlink($this->dir . '/sub/middle.yml');
        @rmdir($this->dir . '/sub');
    }

    public function testCircularIncludeThrows(): void
    {
        $pathA = $this->dir . '/a.yml';
        $pathB = $this->dir . '/b.yml';
        file_put_contents($pathA, "b: !include b.yml\n");
        file_put_contents($pathB, "a: !include a.yml\n");
        $this->files[] = $pathA;
        $this->files[] = $pathB;

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessageMatches('/Circular/');
        YamlIncludeResolver::parseFile($pathA);
    }

    public function testMissingIncludedFileThrows(): void
    {
        $path = $this->write('main.yml', "key: !include does-not-exist.yml\n");
        $this->expectException(\RuntimeException::class);
        YamlIncludeResolver::parseFile($path);
    }

    public function testUnsupportedTagThrows(): void
    {
        $path = $this->write('main.yml', "key: !foo bar\n");
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessageMatches('/Unsupported YAML tag/');
        YamlIncludeResolver::parseFile($path);
    }

    public function testMissingRootFileThrows(): void
    {
        $this->expectException(\RuntimeException::class);
        YamlIncludeResolver::parseFile($this->dir . '/does-not-exist-at-all.yml');
    }

    public function testIncludeNestedInsideAList(): void
    {
        $this->write('extra.yml', "mail: extra@example.org\n");
        $path = $this->write('main.yml', "members:\n  - alice@example.org\n  - !include extra.yml\n");

        $result = YamlIncludeResolver::parseFile($path);
        $this->assertSame('alice@example.org', $result['members'][0]);
        $this->assertSame(['mail' => 'extra@example.org'], $result['members'][1]);
    }
}
