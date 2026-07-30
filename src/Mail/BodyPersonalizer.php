<?php

declare(strict_types=1);

namespace Hengeb\Listig\Mail;

use Hengeb\Listig\Variable\ResolutionPurpose;
use Hengeb\Listig\Variable\VariableResolver;
use Symfony\Component\Mime\Email;
use Symfony\Component\Mime\Header\ParameterizedHeader;
use Symfony\Component\Mime\Part\AbstractPart;
use Symfony\Component\Mime\Part\DataPart;
use Symfony\Component\Mime\Part\TextPart;
use Symfony\Component\Mime\Part\Multipart\AlternativePart;
use Symfony\Component\Mime\Part\Multipart\MixedPart;

class BodyPersonalizer
{
    /**
     * Substitutes {key} placeholders in the mail body and subject.
     *
     * Top-level gate: only keys listed in $personalizeKeys are substituted.
     * Recursive resolution of those values goes through the full $contexts stack
     * (so vorname: "{firstname}" works if firstname is resolvable in $contexts).
     * Resolved with ResolutionPurpose::Disclosed, so VariableResolver itself
     * blocks any BLOCKED_KEYS value (passwords, hostnames, ...) even during
     * recursive resolution — see VariableResolver class docblock.
     */
    public function personalize(Email $email, array $contexts, array $personalizeKeys): void
    {
        $subject = $email->getSubject() ?? '';
        if ($subject !== '') {
            $decoded     = $this->decodeRfc2047($subject);
            $personalized = $this->substituteWhitelisted($decoded, $contexts, $personalizeKeys);
            $email->subject($this->encodeRfc2047($personalized));
        }

        $body = $email->getBody();
        if ($body !== null) {
            $email->setBody($this->personalizePart($body, $contexts, $personalizeKeys));
        }
    }

    private function personalizePart(AbstractPart $part, array $contexts, array $personalizeKeys): AbstractPart
    {
        if ($part instanceof TextPart && !($part instanceof DataPart)) {
            $personalized = $this->substituteWhitelisted($part->getBody(), $contexts, $personalizeKeys);
            $ct      = $part->getPreparedHeaders()->get('Content-Type');
            $charset = $ct instanceof ParameterizedHeader ? ($ct->getParameter('charset') ?: 'utf-8') : 'utf-8';
            return new TextPart($personalized, $charset, $part->getMediaSubtype());
        }

        if ($part instanceof AlternativePart) {
            return new AlternativePart(...array_map(
                fn(AbstractPart $p) => $this->personalizePart($p, $contexts, $personalizeKeys),
                $part->getParts(),
            ));
        }

        if ($part instanceof MixedPart) {
            return new MixedPart(...array_map(
                fn(AbstractPart $p) => $this->personalizePart($p, $contexts, $personalizeKeys),
                $part->getParts(),
            ));
        }

        return $part;
    }

    private function substituteWhitelisted(string $text, array $contexts, array $personalizeKeys): string
    {
        // Brace-depth aware (VariableResolver::walkPlaceholders), so a
        // whitelisted key's filter args may themselves contain {} placeholders
        // without being cut off at the first '}'.
        return VariableResolver::walkPlaceholders($text, function (string $inner) use ($contexts, $personalizeKeys): string {
            // Whitelist check is on the bare variable name — a |filter:... pipeline
            // (see VariableResolver) does not grant access to a non-whitelisted key.
            if (!in_array(VariableResolver::baseKey($inner), $personalizeKeys, true)) {
                return '{' . $inner . '}'; // not whitelisted at top level — leave literal
            }
            // Whitelisted: resolve including recursive {variable} substitution through full contexts
            return VariableResolver::resolve('{' . $inner . '}', $contexts, ResolutionPurpose::Disclosed);
        });
    }

    private function decodeRfc2047(string $value): string
    {
        return iconv_mime_decode($value, ICONV_MIME_DECODE_CONTINUE_ON_ERROR, 'UTF-8') ?: $value;
    }

    private function encodeRfc2047(string $value): string
    {
        if (mb_check_encoding($value, 'ASCII')) {
            return $value;
        }
        return '=?UTF-8?B?' . base64_encode($value) . '?=';
    }
}
