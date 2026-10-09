<?php

declare(strict_types=1);

namespace Hengeb\Listig\Http;

/**
 * What ListActions::forViewer() decided for one list and one viewer: the buttons to show
 * (rendered by templates/list-actions.latte) and whether the viewer may write to the list,
 * which also makes the list address a clickable mailto: link.
 */
final class ListNavigation
{
    /**
     * @param list<array{key: string, href: string, label: string, title: ?string, active: bool}> $items
     *     `label`/`title` are translation keys
     */
    public function __construct(
        public readonly array $items,
        public readonly bool $canPost,
    ) {
    }
}
