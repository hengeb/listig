<?php

declare(strict_types=1);

namespace Hengeb\Listig\Member;

use Hengeb\Listig\Config\Enum\AllowLeave;
use Hengeb\Listig\Config\ListConfig;
use Hengeb\Listig\Mail\NotificationMailer;
use Symfony\Contracts\Translation\TranslatorInterface;

/**
 * Takes a member off a list, honouring `allow-leave`. Shared by the two ways to leave: the token link
 * of a mail footer (UnsubscribeController, POST only — see ADR-0022) and the logged-in "Unsubscribe"
 * button (MembershipController::leave()), so both behave identically and never differ in what they
 * reveal about an address.
 */
class ListLeaver
{
    public function __construct(
        private readonly NotificationMailer $notificationMailer,
        private readonly TranslatorInterface $translator,
    ) {
    }

    /** @param Member|null $member the member record if known (for the owners' notice), else only the address is used */
    public function leave(ListConfig $list, ?Member $member, string $memberEmail): LeaveOutcome
    {
        if ($list->allowLeave === AllowLeave::Moderated) {
            $this->notifyOwners($list, $member, $memberEmail);
            return LeaveOutcome::Requested;
        }

        // Direct: remove and report success regardless of whether $memberEmail was actually still a
        // member (prevents enumeration). But if the member store can't persist a removal at all
        // (static inline config.yml members, or no store), that's a list-wide, non-address-specific
        // fact — safe to reveal, and better than a false "success" that leaves the member subscribed.
        if (!$list->supportsUnsubscribe) {
            return LeaveOutcome::NotSupported;
        }

        try {
            $list->removeMember($memberEmail);
        } catch (\RuntimeException $e) {
            error_log("Listig: Unsubscribe failed for list {$list->name}: " . $e->getMessage());
            return LeaveOutcome::NotSupported;
        }

        return LeaveOutcome::Left;
    }

    private function notifyOwners(ListConfig $list, ?Member $member, string $memberEmail): void
    {
        $firstname = $member?->attributes['firstname'] ?? '';
        $lastname = $member?->attributes['lastname'] ?? '';
        $displayName = trim("$firstname $lastname") ?: $memberEmail;
        $locale = $list->language;

        $this->notificationMailer->sendToOwners(
            $list,
            $this->translator->trans('unsubscribe.owner_notice.subject', [
                '%list%' => $list->displayName,
                '%name%' => $displayName,
            ], null, $locale),
            $this->translator->trans('unsubscribe.owner_notice.body', [
                '%name%' => $displayName,
                '%mail%' => $memberEmail,
                '%list%' => $list->displayName,
            ], null, $locale),
        );
    }
}
