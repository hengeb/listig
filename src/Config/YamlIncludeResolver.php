<?php

declare(strict_types=1);

namespace Hengeb\Listig\Config;

use Symfony\Component\Yaml\Tag\TaggedValue;
use Symfony\Component\Yaml\Yaml;

/**
 * Resolves `!include path/to/file.yml` tags in YAML config files.
 *
 * The tagged node is replaced by the parsed content of the referenced file, spliced
 * into the tree as if it had been written inline. Resolution happens at parse time,
 * before any $VAR substitution or use:/priority merging.
 */
final class YamlIncludeResolver
{
    /**
     * Realpaths of every file read during the most recent *top-level*
     * parseFile() call — the top-level file itself plus every !include
     * target reached from it, in read order. Reset at the start of each
     * top-level call, detected via `$visited === []` — only a genuine
     * top-level call ever passes that; every recursive !include call
     * already has at least the calling file's own key in $visited (see
     * resolveIncludes()'s `[...$visited, $key]`), so this can't be
     * mistaken for a fresh top-level parse mid-recursion.
     *
     * Exists for bin/worker.php's own config-reload mtime watch (see
     * docs/architecture/worker-and-queue.md "Worker loop — config reload"): a change to config.yml
     * itself is one thing to watch for, but a file spliced in via !include
     * is just as much a part of "the configuration", and needs the same
     * restart-on-change treatment — this class is the only place that ever
     * knows which files those actually were. `ConfigResolver` captures this
     * list into its own instance state immediately after its own top-level
     * parseFile() call, specifically so a *later* parseFile() call for an
     * unrelated purpose (YamlListProvider's own list file, which also goes
     * through this same resolver) can never silently overwrite it from
     * underneath a caller that already read it.
     *
     * @var string[]
     */
    private static array $lastParsedFiles = [];

    /** @return string[] See $lastParsedFiles. */
    public static function getLastParsedFiles(): array
    {
        return self::$lastParsedFiles;
    }

    /**
     * @param string[] $visited Realpaths of files already in the include chain (cycle detection)
     */
    public static function parseFile(string $path, array $visited = []): mixed
    {
        if ($visited === []) {
            self::$lastParsedFiles = [];
        }

        $realPath = realpath($path);
        $key = $realPath !== false ? $realPath : $path;
        if (in_array($key, $visited, true)) {
            throw new \RuntimeException("Circular !include detected: $path");
        }
        self::$lastParsedFiles[] = $key;

        // @-suppressed: a missing/unreadable file is expected here (a typo'd
        // config.yml path, a dangling !include) and handled cleanly via the
        // false-return check below — same "check the return value, don't let
        // the native warning leak" convention as e.g. SpamFilter's @preg_match.
        $content = @file_get_contents($path);
        if ($content === false) {
            throw new \RuntimeException("Cannot read YAML file: $path");
        }

        $parsed = Yaml::parse($content, Yaml::PARSE_CUSTOM_TAGS);
        return self::resolveIncludes($parsed, dirname($path), [...$visited, $key]);
    }

    /**
     * @param string[] $visited
     */
    private static function resolveIncludes(mixed $value, string $baseDir, array $visited): mixed
    {
        if ($value instanceof TaggedValue) {
            if ($value->getTag() !== 'include') {
                throw new \RuntimeException("Unsupported YAML tag '!{$value->getTag()}'");
            }

            $includePath = $value->getValue();
            if (!is_string($includePath) || $includePath === '') {
                throw new \RuntimeException('!include requires a non-empty string path');
            }

            $resolvedPath = self::resolvePath($includePath, $baseDir);
            if (!is_file($resolvedPath)) {
                throw new \RuntimeException("Included YAML file not found: $resolvedPath");
            }

            return self::parseFile($resolvedPath, $visited);
        }

        if (is_array($value)) {
            return array_map(fn($v) => self::resolveIncludes($v, $baseDir, $visited), $value);
        }

        return $value;
    }

    private static function resolvePath(string $includePath, string $baseDir): string
    {
        if (self::isAbsolute($includePath)) {
            return $includePath;
        }
        return $baseDir . DIRECTORY_SEPARATOR . $includePath;
    }

    private static function isAbsolute(string $path): bool
    {
        return str_starts_with($path, '/') || preg_match('#^[A-Za-z]:[\\\\/]#', $path) === 1;
    }
}
