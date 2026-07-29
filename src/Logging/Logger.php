<?php

declare(strict_types=1);

namespace Hengeb\Listig\Logging;

/**
 * Thin, level-gated wrapper around error_log() — see CLAUDE.md "Debug logging".
 * Scoped specifically to the new debug-level tracing this class was introduced
 * for (login requests/logins, mail found on IMAP poll, per-recipient enqueue).
 * The pre-existing, unconditional error_log() calls throughout the codebase
 * (operational failures/warnings) are deliberately NOT routed through this
 * class — those represent problems an operator should always see regardless of
 * the configured level, and migrating all of them was out of scope for what was
 * actually asked (see CLAUDE.md).
 */
class Logger
{
    public function __construct(private readonly LogLevel $defaultLevel)
    {
    }

    /**
     * @param ?string $listLevel pass $list->logLevel when the message is scoped
     *        to a specific list — that list's own 'log-level' override then
     *        applies instead of the process-wide default. Needed because
     *        bin/worker.php builds one Logger for the whole process lifetime
     *        (see "Worker loop — config reload") but iterates many lists, each
     *        of which may set its own override.
     */
    public function debug(string $message, ?string $listLevel = null): void
    {
        $threshold = $listLevel !== null ? LogLevel::fromString($listLevel) : $this->defaultLevel;
        if (LogLevel::Debug->value >= $threshold->value) {
            error_log($message);
        }
    }
}
