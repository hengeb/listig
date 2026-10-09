<?php

declare(strict_types=1);

namespace Hengeb\Listig\Mail;

use Hengeb\Listig\Config\ListConfig;
use Hengeb\Listig\Token\ListFingerprint;
use Hengeb\Listig\Token\TokenService;
use PDO;
use PhpImap\IncomingMail;

/**
 * The archive viewer's "reply to this mail" button: a `mailto:` cannot set In-Reply-To
 * (mail clients ignore that parameter), so the address itself names the mail being
 * answered — `{localPart}+re-{TOKEN}@{domain}`, TOKEN a signed token over the list
 * fingerprint and `archived_mail.id`, no table of its own (ADR-0020). Receiving, Listig
 * turns the tag back into In-Reply-To/References (MailProcessor) and into the right
 * thread in its own archive (ArchiveIndexer). DB-gated collaborator, since neither may
 * run SQL itself.
 */
class ReplyThreadStore
{
    /** Token purpose code — see docs/architecture/security-and-tokens.md "Short purpose codes". */
    public const string PURPOSE = 't';

    /** Token max age; a mailto: is built per page view, so this only bounds a saved address/draft. */
    public const int MAX_AGE_DAYS = 180;

    /** The tag, after the `+` — deliberately not a prefix of `r-` (the masked-reply tag). */
    public const string TAG = 're-';

    public function __construct(
        private readonly PDO $db,
        private readonly TokenService $tokenService,
        private readonly HeaderFilter $headerFilter,
    ) {
    }

    /** The address to reply to archived mail `$archivedMailId` of `$list`. */
    public function addressFor(ListConfig $list, int $archivedMailId): string
    {
        $token = $this->tokenService->sign(self::PURPOSE, ListFingerprint::of($list->name), $archivedMailId);
        return "{$list->localPart}+" . self::TAG . "{$token}@{$list->domain}";
    }

    /**
     * The raw token of a `{localPart}+re-{TOKEN}@…` address in To (or, for a Bcc'd copy,
     * Delivered-To/X-Original-To), or null. Read from the raw headers, not $mail->to:
     * PhpImap lowercases parsed recipient addresses, which corrupts the case-sensitive
     * base64 token. Never for type: subaddress lists, where the tag has its own meaning.
     */
    public function extractToken(IncomingMail $mail, ListConfig $list): ?string
    {
        if ($list->subaddressMemberTemplates !== null) {
            return null;
        }
        $pattern = '/' . preg_quote($list->localPart, '/') . '\+' . preg_quote(self::TAG, '/') . '([A-Za-z0-9_-]+)@/i';
        foreach (['To', 'Delivered-To', 'X-Original-To'] as $header) {
            $value = $this->headerFilter->readHeader($mail->headersRaw ?? '', $header) ?? '';
            if (preg_match($pattern, $value, $m)) {
                return $m[1];
            }
        }
        return null;
    }

    /**
     * The archived mail a token points to, or null for an invalid/expired token, one of
     * another list, or a mail that is no longer in the index (deleted, pruned).
     *
     * @return array{message_id: string, thread_root: string}|null
     */
    public function resolve(ListConfig $list, string $token): ?array
    {
        try {
            [$fingerprint, $id] = $this->tokenService->verify($token, self::PURPOSE, self::MAX_AGE_DAYS * 86400);
        } catch (\InvalidArgumentException) {
            return null;
        }
        if ($fingerprint !== ListFingerprint::of($list->name)) {
            return null;
        }

        $stmt = $this->db->prepare('SELECT message_id, thread_root FROM archived_mail WHERE id = :id AND list_cn = :list');
        $stmt->execute(['id' => $id, 'list' => $list->name]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        return $row === false ? null : ['message_id' => $row['message_id'], 'thread_root' => $row['thread_root']];
    }

    /** extractToken() + resolve() for an incoming mail; null if it carries no (valid) tag. */
    public function resolveMail(IncomingMail $mail, ListConfig $list): ?array
    {
        $token = $this->extractToken($mail, $list);
        return $token === null ? null : $this->resolve($list, $token);
    }
}
