<?php

declare(strict_types=1);

namespace Hengeb\Listig\Mail;

use Hengeb\Listig\Config\ListConfig;
use Hengeb\Listig\Token\ListFingerprint;
use Hengeb\Listig\Token\TokenService;
use Hengeb\Listig\Member\Member;
use PDO;
use PhpImap\IncomingMail;

/**
 * Backs the masked-sender / masked-both reply-to modes (see docs/architecture/masked-replies.md "Masked reply
 * addresses"): creates and resolves the per-list, signed `+r-{TOKEN}` addresses that
 * stand in for a sender's real address. DB-gated collaborator, since MailProcessor
 * may not run SQL itself.
 *
 * A token is list-specific twice over: the payload carries ListFingerprint (signed),
 * and find() always looks the row up by (id, list_cn) of the list the mail actually
 * arrived on — the database check is the real boundary.
 */
class ReplyTargetStore
{
    /** Token purpose code — see docs/architecture/security-and-tokens.md "Short purpose codes". */
    public const string PURPOSE = 'p';

    /** Also the retention of unused rows, see purgeUnused(). */
    public const int MAX_AGE_DAYS = 180;

    public function __construct(
        private readonly PDO $db,
        private readonly TokenService $tokenService,
        private readonly HeaderFilter $headerFilter,
    ) {
    }

    /**
     * Returns the token for the given address on the given list, creating the row on
     * first use. A current member (or owner) is stored by `username` if they have one
     * (see kind 'member' in migration 007), everyone else by address.
     */
    public function tokenFor(ListConfig $list, string $email): string
    {
        $member = $list->findMemberByEmail($email) ?? $list->findOwnerInList($email);
        if ($member !== null) {
            $kind = 'member';
            $key  = $member->attributes['username'] ?? $member->email;
        } else {
            $kind = 'external';
            $key  = $email;
        }

        $stmt = $this->db->prepare(
            'INSERT INTO reply_targets (list_cn, kind, target_key, created_at, last_used_at)
             VALUES (:list, :kind, :key, NOW(), NOW())
             ON DUPLICATE KEY UPDATE id = LAST_INSERT_ID(id), last_used_at = NOW()'
        );
        $stmt->execute(['list' => $list->name, 'kind' => $kind, 'key' => $key]);
        $id = (int) $this->db->lastInsertId();

        return $this->tokenService->sign(self::PURPOSE, ListFingerprint::of($list->name), $id);
    }

    /**
     * @return array{kind: string, target_key: string}|null null for an invalid/expired
     * token, one of another list, or a row that has been purged.
     */
    public function find(ListConfig $list, string $token): ?array
    {
        try {
            [$fingerprint, $id] = $this->tokenService->verify($token, self::PURPOSE, self::MAX_AGE_DAYS * 86400);
        } catch (\InvalidArgumentException) {
            return null;
        }
        if ($fingerprint !== ListFingerprint::of($list->name)) {
            return null;
        }

        $stmt = $this->db->prepare('SELECT kind, target_key FROM reply_targets WHERE id = :id AND list_cn = :list');
        $stmt->execute(['id' => $id, 'list' => $list->name]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        return $row === false ? null : $row;
    }

    /**
     * The raw token of a `{localPart}+r-{TOKEN}@…` address in To (or, for a Bcc'd copy,
     * Delivered-To/X-Original-To), or null. Read from the raw headers, not $mail->to:
     * PhpImap lowercases parsed recipient addresses, which corrupts the case-sensitive
     * base64 token (same reason as ModerationResponseHandler::detectAction()).
     */
    public function extractToken(IncomingMail $mail, ListConfig $list): ?string
    {
        $pattern = '/' . preg_quote($list->localPart, '/') . '\+r-([A-Za-z0-9_-]+)@/i';
        foreach (['To', 'Delivered-To', 'X-Original-To'] as $header) {
            $value = $this->headerFilter->readHeader($mail->headersRaw ?? '', $header) ?? '';
            if (preg_match($pattern, $value, $m)) {
                return $m[1];
            }
        }
        return null;
    }

    /**
     * Resolves a token to its recipient, or null if the token is invalid/expired/of another
     * list, or the target is gone (a member who left, or whose address changed and who has
     * no username to follow it by).
     */
    public function resolve(ListConfig $list, string $token): ?ReplyTarget
    {
        $row = $this->find($list, $token);
        if ($row === null) {
            return null;
        }
        if ($row['kind'] === 'external') {
            return new ReplyTarget(new Member($row['target_key']), true);
        }

        foreach ([...$list->getMembers(), ...$list->getOwners()] as $member) {
            if (($member->attributes['username'] ?? $member->email) === $row['target_key']) {
                return new ReplyTarget($member, false);
            }
        }
        return null;
    }

    /** Whether the mail is addressed to a `+r-` reply address at all (never true for type: subaddress lists). */
    public function isReplyMail(IncomingMail $mail, ListConfig $list): bool
    {
        return $list->subaddressMemberTemplates === null && $this->extractToken($mail, $list) !== null;
    }

    /**
     * A masked-sender reply is a private message between two people — the worker must not
     * index it into the (possibly member- or publicly-visible) archive.
     */
    public function isPrivateReply(IncomingMail $mail, ListConfig $list): bool
    {
        return $list->replyTo === \Hengeb\Listig\Config\Enum\ReplyToBehavior::MaskedSender
            && $this->isReplyMail($mail, $list);
    }

    /** Touches last_used_at so an address still being replied to isn't purged. */
    public function markUsed(ListConfig $list, string $token): void
    {
        $row = $this->find($list, $token);
        if ($row === null) {
            return;
        }
        $stmt = $this->db->prepare('UPDATE reply_targets SET last_used_at = NOW() WHERE list_cn = :list AND kind = :kind AND target_key = :key');
        $stmt->execute(['list' => $list->name, 'kind' => $row['kind'], 'key' => $row['target_key']]);
    }

    public function purgeUnused(): void
    {
        $this->db->exec('DELETE FROM reply_targets WHERE last_used_at < NOW() - INTERVAL ' . self::MAX_AGE_DAYS . ' DAY');
    }
}
