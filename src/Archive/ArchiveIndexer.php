<?php

declare(strict_types=1);

namespace Hengeb\Listig\Archive;

use Hengeb\Listig\Config\Enum\ArchiveMode;
use Hengeb\Listig\Config\ListConfig;
use Hengeb\Listig\Mail\HeaderFilter;
use PDO;
use PhpImap\IncomingMail;

/**
 * Indexes a successfully distributed mail into archived_mail for the web archive
 * viewer (Http/Controller/ArchiveController.php; see CLAUDE.md "Archive access
 * levels"). Deliberately NOT called from ImapArchiver::archiveOrDelete(), which
 * also runs for bounce/reject outcomes that were never sent to the list — callers
 * only invoke index() at the three call sites representing a successful distribute
 * (bin/worker.php, ModerationController::accept, ModerationResponseHandler) once
 * archiveOrDelete() has already moved the raw mail into the list's IMAP archive
 * folder ($list->archiveFolder).
 */
class ArchiveIndexer
{
    public function __construct(
        private readonly PDO $db,
        private readonly HeaderFilter $headerFilter,
    ) {
    }

    public function index(ListConfig $list, IncomingMail $mail): void
    {
        if ($list->archive === ArchiveMode::Off) {
            return;
        }

        $headersRaw = $mail->headersRaw ?? '';
        $messageId  = self::normalize($this->headerFilter->readHeader($headersRaw, 'Message-ID'));

        // No stable key to re-locate this mail by later — can't index it usefully.
        // Rare in practice (a conformant MTA always sets Message-ID); the mail is
        // still safely archived on IMAP, just invisible to the list/thread view.
        if ($messageId === null) {
            return;
        }

        $inReplyTo = self::normalize($this->headerFilter->readHeader($headersRaw, 'In-Reply-To'));
        $threadRoot = self::firstReference($this->headerFilter->readHeader($headersRaw, 'References'))
            ?? $inReplyTo
            ?? $messageId;

        $timestamp = strtotime($mail->date ?? '') ?: time();

        $stmt = $this->db->prepare(
            'INSERT INTO archived_mail
                (list_cn, message_id, in_reply_to, thread_root, subject, sender_name, mail_date, has_attachments, archived_at)
             VALUES
                (:list, :message_id, :in_reply_to, :thread_root, :subject, :sender_name, :mail_date, :has_attachments, NOW())
             ON DUPLICATE KEY UPDATE id = id'
        );
        $stmt->execute([
            'list'            => $list->name,
            'message_id'      => $messageId,
            'in_reply_to'     => $inReplyTo,
            'thread_root'     => $threadRoot,
            'subject'         => $mail->subject ?? null,
            // Display name only — never the address. Empty means the template falls
            // back to a translated placeholder at render time (like reject.* keys,
            // translation happens at render, not at write, see CLAUDE.md).
            'sender_name'     => ($mail->fromName ?? '') !== '' ? $mail->fromName : null,
            'mail_date'       => date('Y-m-d H:i:s', $timestamp),
            'has_attachments' => $mail->hasAttachments() ? 1 : 0,
        ]);
    }

    /**
     * Removes an archived_mail row once ArchiveMailLocator has confirmed (via a
     * full, successful IMAP search — see ArchiveMailNotFoundException) that the
     * underlying mail no longer exists in the list's archive folder. Called
     * lazily from ArchiveController::locateMail() when a viewer actually opens
     * that mail, not proactively/periodically — a mail nobody re-opens simply
     * keeps its stale index row until someone does.
     */
    public function remove(string $listCn, string $messageId): void
    {
        $stmt = $this->db->prepare('DELETE FROM archived_mail WHERE list_cn = :list AND message_id = :message_id');
        $stmt->execute(['list' => $listCn, 'message_id' => $messageId]);
    }

    private static function normalize(?string $value): ?string
    {
        if ($value === null) {
            return null;
        }
        $value = trim($value);
        return $value === '' ? null : trim($value, '<>');
    }

    /** First Message-ID token in a References header — the thread-initiating message. */
    private static function firstReference(?string $references): ?string
    {
        if ($references === null) {
            return null;
        }
        if (preg_match('/<[^<>]+>/', $references, $m)) {
            return trim($m[0], '<>');
        }
        return null;
    }
}
