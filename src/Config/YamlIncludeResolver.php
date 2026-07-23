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
     * @param string[] $visited Realpaths of files already in the include chain (cycle detection)
     */
    public static function parseFile(string $path, array $visited = []): mixed
    {
        $realPath = realpath($path);
        $key = $realPath !== false ? $realPath : $path;
        if (in_array($key, $visited, true)) {
            throw new \RuntimeException("Circular !include detected: $path");
        }

        $content = file_get_contents($path);
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
