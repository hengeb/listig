<?php

declare(strict_types=1);

namespace Hengeb\Listig\Variable;

/**
 * Tags a VariableResolver::resolve()/lookup() call with what the result will be
 * used for, threaded unchanged through recursive resolution. See
 * VariableResolver::BLOCKED_KEYS.
 */
enum ResolutionPurpose
{
    /** Full, unfiltered access — only for credential resolution (e.g. ListConfig::$imapPassword). */
    case Trusted;

    /** Default. A blocked key resolves to VariableResolver::CLASSIFIED_PLACEHOLDER instead of its real value, and the attempt is logged. */
    case Disclosed;
}
