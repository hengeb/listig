<?php

declare(strict_types=1);

namespace Hengeb\Listig\Config\Enum;

/**
 * The configurable consequence of a recognized, authenticated permanent bounce
 * (BounceCause::UserUnknown) or an escalated repeated temporary one
 * (BounceCause::MailboxFull, after `bounce-escalate-after` occurrences) — see
 * docs/architecture/bounces.md "Automatic bounce actions". Applied uniformly regardless of which
 * of the two causes triggered it.
 */
enum BounceAction: string
{
    /** Default — no automatic mutation of member data, ever, until an operator opts in explicitly. */
    case None = 'none';

    /** Append a `.BOUNCE_{cause}.{date}.invalid` suffix to the member's own address — see Member\InvalidatedEmail. */
    case MarkInvalid = 'mark-invalid';

    /** Add to bounce_suppressed_members — skipped at send time, membership otherwise untouched. */
    case Restrict = 'restrict';

    /** Remove from the list outright — reuses the existing ListConfig::removeMember(). */
    case Remove = 'remove';
}
