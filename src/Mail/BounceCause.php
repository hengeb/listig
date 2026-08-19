<?php

declare(strict_types=1);

namespace Hengeb\Listig\Mail;

/**
 * A bounce reason BounceCauseClassifier can recognize well enough to trigger an
 * automatic action in BounceHandler. Adding a new one is three small,
 * independent steps: a new case here, a new check in
 * BounceCauseClassifier::classify(), and a new match arm in
 * BounceHandler::applyAutomaticAction().
 *
 * A plain (non-string-backed) enum, like ResolutionPurpose — this is an
 * internal classification result, never a config.yml value, so there is
 * nothing to serialize.
 */
enum BounceCause
{
    /** Reported as spam by a reliable domain — aborts the rest of the batch (BounceHandler::abortBatchForBounce()). */
    case Spam;

    /** Permanent: mailbox/user/domain doesn't exist, or the relay refuses it — drives the list's configurable `bounce-action`. */
    case UserUnknown;

    /** Temporary: mailbox full — defers this recipient's future sends, escalating to `bounce-action` after repeated occurrences. */
    case MailboxFull;
}
