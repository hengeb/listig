<?php

declare(strict_types=1);

namespace Hengeb\Listig\Mail;

use Hengeb\Listig\Config\ListConfig;
use Hengeb\Listig\Variable\ResolutionPurpose;
use Hengeb\Listig\Variable\VariableResolver;
use Symfony\Component\Mime\Email;
use Symfony\Component\Mime\Header\ParameterizedHeader;
use Symfony\Component\Mime\Part\AbstractPart;
use Symfony\Component\Mime\Part\DataPart;
use Symfony\Component\Mime\Part\TextPart;
use Symfony\Component\Mime\Part\Multipart\AlternativePart;
use Symfony\Component\Mime\Part\Multipart\MixedPart;

class FooterAppender
{
    public function append(Email $email, ListConfig $list, array $contexts): void
    {
        $footerTemplate = $list->footer;

        // null = not configured, '' = explicitly disabled
        if ($footerTemplate === null || $footerTemplate === '') {
            return;
        }

        $footerHtml = VariableResolver::resolve($footerTemplate, $contexts, ResolutionPurpose::Disclosed);
        $footerText = $this->htmlToText($footerHtml);

        $body = $email->getBody();
        if ($body !== null) {
            $email->setBody($this->appendToPart($body, $footerHtml, $footerText));
        }
    }

    private function appendToPart(AbstractPart $part, string $footerHtml, string $footerText): AbstractPart
    {
        // DataPart extends TextPart but holds binary attachments — never append footer there
        if ($part instanceof TextPart && !($part instanceof DataPart)) {
            if ($part->getMediaSubtype() === 'html') {
                $newContent = $this->appendHtml($part->getBody(), $footerHtml);
            } else {
                $newContent = $part->getBody() . "\n\n" . $footerText;
            }
            // TextPart has no public getCharset(); read it back from the prepared Content-Type header.
            $ct = $part->getPreparedHeaders()->get('Content-Type');
            $charset = $ct instanceof ParameterizedHeader ? ($ct->getParameter('charset') ?: 'utf-8') : 'utf-8';
            return new TextPart($newContent, $charset, $part->getMediaSubtype());
        }

        if ($part instanceof AlternativePart) {
            return new AlternativePart(...array_map(
                fn(AbstractPart $p) => $this->appendToPart($p, $footerHtml, $footerText),
                $part->getParts(),
            ));
        }

        if ($part instanceof MixedPart) {
            return new MixedPart(...array_map(
                fn(AbstractPart $p) => $this->appendToPart($p, $footerHtml, $footerText),
                $part->getParts(),
            ));
        }

        return $part;
    }

    private function appendHtml(string $html, string $footerHtml): string
    {
        if (preg_match('/<\/body>/i', $html)) {
            return preg_replace('/<\/body>/i', "<div>{$footerHtml}</div></body>", $html);
        }
        return $html . "<div>{$footerHtml}</div>";
    }

    private function htmlToText(string $html): string
    {
        // Convert links: <a href="url">text</a> -> text (url)
        $text = preg_replace('/<a\s[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)<\/a>/is', '$2 ($1)', $html);

        // Block-level tags to newlines
        $text = preg_replace('/<\/(p|div|br|h[1-6]|li|tr)>/i', "\n", $text);
        $text = preg_replace('/<(br|hr)\s*\/?>/i', "\n", $text);

        // Strip remaining tags
        $text = strip_tags($text);

        // Decode HTML entities
        $text = html_entity_decode($text, ENT_QUOTES | ENT_HTML5, 'UTF-8');

        return trim($text);
    }
}
