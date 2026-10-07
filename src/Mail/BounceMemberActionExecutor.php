<?php

declare(strict_types=1);

namespace Hengeb\Listig\Mail;

use Hengeb\Listig\Config\ListConfig;
use Symfony\Contracts\Translation\TranslatorInterface;

/**
 * Executes the three "mutate member data" automatic bounce actions
 * (mark-invalid/restrict/remove — see docs/architecture/bounces.md "Automatic bounce actions"),
 * extracted out of BounceHandler so that class stays focused on detection/
 * classification/notice-building. Each method is wrapped in its own
 * try/catch — a failure here (e.g. LDAP unreachable) must never prevent
 * BounceHandler from still forwarding the triggering bounce to the owners;
 * it's reported as part of the returned description instead.
 */
class BounceMemberActionExecutor
{
    public function __construct(
        private readonly BounceSuppressionList $suppressionList,
        private readonly TranslatorInterface $translator,
    ) {
    }

    public function markInvalid(ListConfig $list, string $envelopeTo, string $reasonCode): string
    {
        if (!$list->supportsInvalidation) {
            return $this->translator->trans('bounce.auto_action.mark_invalid_unsupported', [], null, $list->language);
        }

        try {
            $list->invalidateEmail($envelopeTo, $reasonCode);
        } catch (\Throwable $e) {
            error_log("Listig: Failed to mark $envelopeTo invalid for list {$list->name}: " . $e->getMessage());
            return $this->translator->trans('bounce.auto_action.mark_invalid_failed', [], null, $list->language);
        }

        return $this->translator->trans('bounce.auto_action.mark_invalid_done', [], null, $list->language);
    }

    public function restrict(ListConfig $list, string $envelopeTo, string $reasonCode): string
    {
        try {
            $this->suppressionList->suppress($list->name, $envelopeTo, $reasonCode);
        } catch (\Throwable $e) {
            error_log("Listig: Failed to suppress $envelopeTo for list {$list->name}: " . $e->getMessage());
            return $this->translator->trans('bounce.auto_action.restrict_failed', [], null, $list->language);
        }

        return $this->translator->trans('bounce.auto_action.restrict_done', [], null, $list->language);
    }

    public function remove(ListConfig $list, string $envelopeTo): string
    {
        if (!$list->supportsUnsubscribe) {
            return $this->translator->trans('bounce.auto_action.remove_unsupported', [], null, $list->language);
        }

        try {
            $list->removeMember($envelopeTo);
        } catch (\Throwable $e) {
            error_log("Listig: Failed to remove $envelopeTo from list {$list->name}: " . $e->getMessage());
            return $this->translator->trans('bounce.auto_action.remove_failed', [], null, $list->language);
        }

        return $this->translator->trans('bounce.auto_action.remove_done', [], null, $list->language);
    }
}
