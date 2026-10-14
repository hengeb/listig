<?php

declare(strict_types=1);

namespace Hengeb\Listig\Tests\Config\Enum;

use Hengeb\Listig\Config\Enum\ArchiveMode;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Yaml\Yaml;

class ArchiveModeTest extends TestCase
{
    /** The list info page renders `list.archive_mode.<value>`; a new mode without a sentence would show the raw key. */
    public function testEveryModeHasAnInfoPageSentenceInBothLanguages(): void
    {
        foreach (['de', 'en'] as $language) {
            $catalog = Yaml::parseFile(__DIR__ . "/../../../translations/messages.$language.yaml");
            foreach (ArchiveMode::cases() as $mode) {
                $this->assertArrayHasKey($mode->value, $catalog['list']['archive_mode'], "$language: {$mode->value}");
            }
        }
    }
}
