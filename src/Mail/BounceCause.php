<?php

declare(strict_types=1);

namespace Hengeb\Listig\Mail;

/**
 * A bounce reason BounceCauseClassifier can recognize well enough to trigger an
 * automatic action in BounceHandler — deliberately small today (only Spam),
 * but structured to grow: a future permanent-failure cause (e.g. "user
 * unknown", "mailbox does not exist") would drive a block-or-remove-member
 * action instead of Spam's abort-batch one. Adding one is three small,
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
    case Spam;
}
