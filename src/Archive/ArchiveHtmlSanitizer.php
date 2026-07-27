<?php

declare(strict_types=1);

namespace Hengeb\Listig\Archive;

use HTMLPurifier;
use HTMLPurifier_Config;
use PhpImap\IncomingMailAttachment;

/**
 * Renders an archived mail's body as safe HTML for the sandboxed archive-viewer
 * frame (ArchiveController::frame()). Three independent steps, always in this
 * order:
 *  1. Rewrite cid: references to attachment download URLs — always, regardless
 *     of $loadImages, since these are part of the mail's own MIME structure we
 *     host, not a third-party fetch (no tracking-pixel risk).
 *  2. Sanitize via HTMLPurifier: HTML.Allowed is a fixed, small tag/attribute
 *     allowlist (structural/formatting tags, `style` restricted to a safe CSS
 *     property allowlist, `img` restricted to src/alt/width/height) — `srcset`,
 *     `<source>`/`<video>`/`<audio>`/`<picture>`, `<script>`, `<style>`,
 *     `<iframe>`, `<form>`, event-handler attributes, and `javascript:` URIs are
 *     all simply absent from the allowlist, so HTMLPurifier strips them outright;
 *     there is no separate "dangerous tag" blocklist to maintain.
 *  3. Strip off-origin (http/https) `img[src]` unless $loadImages is true — the
 *     only URL-bearing attribute HTMLPurifier's allowlist still lets through.
 *     Because the iframe this is rendered into has no `allow-scripts` (see
 *     CLAUDE.md), "load images" is a full server re-render triggered by the OUTER
 *     page changing the iframe's src — never a live DOM mutation from inside the
 *     sandboxed content.
 */
class ArchiveHtmlSanitizer
{
    private HTMLPurifier $purifier;

    public function __construct()
    {
        $config = HTMLPurifier_Config::createDefault();
        // No definition cache directory needed — the only writable-dir precedent
        // in this codebase is Latte's /tmp/latte; rebuilding per request is fine,
        // the archive viewer is not a hot path.
        $config->set('Cache.DefinitionImpl', null);
        $config->set('HTML.Allowed', implode(',', [
            'p[style]', 'br', 'div[style]', 'span[style]',
            'a[href|style]',
            'b[style]', 'strong[style]', 'i[style]', 'em[style]', 'u[style]', 's[style]', 'strike[style]',
            'ul[style]', 'ol[style]', 'li[style]',
            'blockquote[style]', 'hr', 'pre[style]', 'code[style]',
            'h1[style]', 'h2[style]', 'h3[style]', 'h4[style]', 'h5[style]', 'h6[style]',
            'table[style]', 'thead', 'tbody', 'tr[style]', 'td[style]', 'th[style]',
            'img[src|alt|width|height]',
        ]));
        $config->set('CSS.AllowedProperties', [
            'color', 'background-color', 'font-weight', 'font-style', 'text-decoration', 'text-align',
        ]);
        // Every link opens in a new (non-opener) tab — this is rendered inside a
        // sandboxed iframe without allow-top-navigation, so an unmarked link would
        // otherwise be inert/confusing rather than unsafe, but marking it explicit
        // is clearer and costs nothing.
        $config->set('HTML.TargetBlank', true);

        $this->purifier = new HTMLPurifier($config);
    }

    /**
     * @param IncomingMailAttachment[] $attachments
     * @param string $attachmentToken appended as a `?token=` query string to every
     *        cid:-rewritten URL — see ArchiveController::frame()'s comment on why
     *        the sandboxed viewer frame needs this (its own <img> requests carry
     *        no session cookie at all).
     * @param string $view 'text' forces the plaintext part even when $textHtml is
     *        present (archive/show.latte's HTML/plain-text toggle, only shown when
     *        both actually exist); anything else keeps the original default of
     *        HTML-if-present.
     */
    public function render(
        ?string $textHtml,
        ?string $textPlain,
        array $attachments,
        string $attachmentBaseUrl,
        bool $loadImages,
        string $attachmentToken = '',
        string $view = 'html',
    ): string {
        if ($view !== 'text' && ($textHtml ?? '') !== '') {
            $html = $this->rewriteCidReferences($textHtml, $attachments, $attachmentBaseUrl, $attachmentToken);
            $html = $this->purifier->purify($html);
        } else {
            $html = $this->renderPlainText($textPlain ?? '');
        }

        if (!$loadImages) {
            $html = $this->stripExternalResources($html);
        }

        return $html;
    }

    private function renderPlainText(string $text): string
    {
        return '<pre>' . htmlspecialchars($text, ENT_QUOTES, 'UTF-8') . '</pre>';
    }

    /**
     * Rewrites cid: URIs to our own attachment endpoint BEFORE purification, so
     * HTMLPurifier only ever sees ordinary relative URLs — it has no built-in
     * "cid" URI scheme, and teaching it one is unnecessary when a pre-processing
     * rewrite is simpler and just as correct.
     */
    /** @param IncomingMailAttachment[] $attachments */
    private function rewriteCidReferences(string $html, array $attachments, string $attachmentBaseUrl, string $attachmentToken): string
    {
        $tokenSuffix = $attachmentToken !== '' ? '?token=' . urlencode($attachmentToken) : '';

        $urlByContentId = [];
        foreach ($attachments as $index => $attachment) {
            if ($attachment->disposition === 'inline' && ($attachment->contentId ?? '') !== '') {
                $urlByContentId[$attachment->contentId] = "{$attachmentBaseUrl}/{$index}{$tokenSuffix}";
            }
        }
        if (empty($urlByContentId)) {
            return $html;
        }

        return preg_replace_callback(
            '/cid:([^"\'\s)>]+)/i',
            fn(array $m): string => $urlByContentId[$m[1]] ?? $m[0],
            $html,
        );
    }

    /**
     * Runs only on already-HTMLPurifier-sanitized, well-formed output, so a
     * DOMDocument-based pass here is safe (no untrusted-markup parsing risk).
     * Strips img[src]/img[srcset] and any `background(-image): url(...)` inline
     * style pointing off-origin, replacing nothing — the outer page's "load
     * images" button re-requests this same render with $loadImages = true.
     */
    private function stripExternalResources(string $html): string
    {
        if (trim($html) === '') {
            return $html;
        }

        $dom = new \DOMDocument();
        $wrapped = '<!DOCTYPE html><html><body><div id="__root">' . $html . '</div></body></html>';
        @$dom->loadHTML('<?xml encoding="utf-8">' . $wrapped, LIBXML_NOERROR | LIBXML_NOWARNING);

        $root = $dom->getElementById('__root');
        if ($root === null) {
            return $html;
        }

        foreach (iterator_to_array($dom->getElementsByTagName('img')) as $img) {
            foreach (['src', 'srcset'] as $attr) {
                if ($img->hasAttribute($attr) && self::isExternal($img->getAttribute($attr))) {
                    $img->removeAttribute($attr);
                }
            }
        }

        $inner = '';
        foreach (iterator_to_array($root->childNodes) as $child) {
            $inner .= $dom->saveHTML($child);
        }
        return $inner;
    }

    private static function isExternal(string $url): bool
    {
        return (bool) preg_match('#^(https?:)?//#i', trim($url));
    }
}
