<?php

declare(strict_types=1);

namespace Hengeb\Listig\Logging;

/**
 * Mirrors the four levels documented in CLAUDE.md's "Logging" section
 * (config.yml's global 'log-level' default / per-list ListConfig::$logLevel
 * override) — ordered so a numeric comparison decides whether a given message
 * actually reaches error_log() (see Logger).
 */
enum LogLevel: int
{
    case Debug = 0;
    case Info = 1;
    case Warning = 2;
    case Error = 3;

    public static function fromString(string $level): self
    {
        return match ($level) {
            'debug' => self::Debug,
            'warning' => self::Warning,
            'error' => self::Error,
            default => self::Info,
        };
    }
}
