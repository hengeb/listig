<?php

declare(strict_types=1);

namespace Hengeb\Listig\Member;

enum LeaveOutcome
{
    /** Removed from the list (or already not on it — never revealed which). */
    case Left;
    /** `allow-leave: moderated`: the owners were told, they remove the member by hand. */
    case Requested;
    /** The list's member store cannot persist a removal — a list-wide fact, safe to tell. */
    case NotSupported;
}
