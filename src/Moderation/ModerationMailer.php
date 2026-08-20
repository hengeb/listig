<?php

declare(strict_types=1);

namespace Hengeb\Listig\Moderation;

use Hengeb\Listig\Config\ListConfig;
use Hengeb\Listig\Mail\NotificationMailer;
use Hengeb\Listig\Smtp\SmtpConnectionFactory;
use Hengeb\Listig\Token\ListFingerprint;
use Hengeb\Listig\Token\TokenService;
use PDO;
use PhpImap\IncomingMail;
use Symfony\Component\Mailer\Mailer;
use Symfony\Component\Mime\Address;
use Symfony\Component\Mime\Email;
use Symfony\Component\Mime\Part\DataPart;
use Symfony\Component\Mime\Part\Multipart\MixedPart;
use Symfony\Component\Mime\Part\TextPart;
use Symfony\Contracts\Translation\TranslatorInterface;

class ModerationMailer
{
    public function __construct(
        private readonly PDO $db,
        private readonly SmtpConnectionFactory $smtpFactory,
        private readonly TokenService $tokenService,
        private readonly TranslatorInterface $translator,
        private readonly NotificationMailer $notificationMailer,
    ) {
    }

    public function send(ListConfig $list, IncomingMail $mail, int $imapUid, int $uidValidity, string $rawMime): void
    {
        $owners = $list->getOwners();
        if (empty($owners)) {
            error_log("Listig: No owners for list {$list->name}, cannot send moderation mail");
            return;
        }

        $subject = $mail->subject ?? '';
        $senderName = $mail->fromName ?? '';
        $senderMail = $mail->fromAddress ?? '';
        // Same fallback as ArchiveIndexer::index() for the same field — an
        // unparseable/absent Date header must not block queuing the item.
        $mailDate = date('Y-m-d H:i:s', strtotime($mail->date ?? '') ?: time());

        // moderation_queue only tracks that an item is pending and when it was created/
        // reminded/from whom — it holds no secret, so a plain dedup no-op (not updating
        // the mail metadata on a repeat call) is enough here; the metadata was already
        // correct from the first INSERT and never changes for a given UID. Runs *before*
        // signing the accept/reject tokens below — those now embed this row's own id
        // (see there for why), so the row (and its id) must exist first.
        // "ON DUPLICATE KEY UPDATE id = LAST_INSERT_ID(id)" (not a bare "id = id") is
        // required to get the item's own id back via PDO::lastInsertId() reliably on
        // *both* paths — confirmed live against MariaDB: a genuine new INSERT sets
        // LAST_INSERT_ID() to the new row's id as usual, and — unlike the previous
        // "id = id" form, which never touches LAST_INSERT_ID() at all on the
        // duplicate-key path — this form also sets LAST_INSERT_ID() to the *existing*
        // row's own id when the UNIQUE KEY is hit, while leaving ROW_COUNT() (and
        // therefore $isNewItem below) exactly as before: 1 for a real insert, 0 for a
        // reminder resend hitting the same row.
        $insertStmt = $this->db->prepare(
            'INSERT INTO moderation_queue (list_cn, imap_uid, imap_uidvalidity, subject, sender_name, sender_mail, mail_date, created_at)
             VALUES (:list, :uid, :validity, :subject, :sender_name, :sender_mail, :mail_date, NOW())
             ON DUPLICATE KEY UPDATE id = LAST_INSERT_ID(id)'
        );
        $insertStmt->execute([
            'list' => $list->name,
            'uid' => $imapUid,
            'validity' => $uidValidity,
            'subject' => $subject,
            'sender_name' => $senderName,
            'sender_mail' => $senderMail,
            'mail_date' => $mailDate,
        ]);
        // MariaDB's own INSERT ... ON DUPLICATE KEY UPDATE semantics: 1 row affected
        // means this was a genuine INSERT; 0 means the row already existed and the
        // update clause changed nothing — i.e. this call is a reminder resend
        // (ModerationChecker::checkOverdue()), not the item's first queueing.
        $isNewItem = $insertStmt->rowCount() === 1;
        $itemId = (int) $this->db->lastInsertId();

        // The token embeds a short list fingerprint — not the unboundedly long raw
        // list name, since these tokens are embedded in an email address local-part
        // (RFC 5321's 64-byte limit); see ListFingerprint's own docblock — plus the
        // moderation_queue row's own id, and is HMAC-signed. Verifying an accept/
        // reject reply still needs one DB lookup (by id, see
        // ModerationResponseHandler), same as it always needed one for the
        // idempotency/still-pending check regardless. One shared pair per message
        // (not per owner): the token doesn't identify which owner approved, that is
        // checked separately via $list->isOwnedBy() on arrival.
        $listFingerprint = ListFingerprint::of($list->name);
        $acceptToken = $this->tokenService->sign('accept', $listFingerprint, $itemId);
        $rejectToken = $this->tokenService->sign('reject', $listFingerprint, $itemId);

        // localPart, not $list->name/{list-cn} — those commonly differ (e.g. a list
        // named "it-team" with mail "it@example.org"), same reasoning as the bounce
        // address (see MailProcessor::setOutgoingHeaders()).
        $acceptAddress = "{$list->localPart}+accept-{$acceptToken}@{$list->domain}";
        $rejectAddress = "{$list->localPart}+reject-{$rejectToken}@{$list->domain}";

        $locale = $list->language;
        // "Name <mail>", or just "<mail>" when the sender set no display name —
        // one formatted string is simpler for translators than two separate
        // %sender_name%/%sender_mail% placeholders that would need their own
        // punctuation/spacing baked into every translation.
        $senderDisplay = $senderName !== '' ? "{$senderName} <{$senderMail}>" : $senderMail;
        $translatedSubject = $this->translator->trans('moderation.mail.subject', ['%list%' => $list->displayName], null, $locale);
        $body = $this->translator->trans('moderation.mail.body', [
            '%list%' => $list->displayName,
            '%mail%' => $list->mail,
            '%subject%' => $subject,
            '%sender%' => $senderDisplay,
            '%date%' => $mailDate,
            // ?subject=... only in the mailto: link shown to the owner — never on
            // $acceptAddress/$rejectAddress themselves, which also feed
            // Email::replyTo() below and must stay bare addresses there. A blank
            // Subject (the moderated mail's own subject/body are deliberately
            // never quoted back into this reply — see the multipart/mixed comment
            // below) otherwise made some mail clients warn about sending an
            // empty-subject mail, which the pre-filled subject avoids.
            '%accept%' => "{$acceptAddress}?subject=accept",
            '%reject%' => "{$rejectAddress}?subject=reject",
        ], null, $locale);

        foreach ($owners as $owner) {
            $email = new Email();
            $email->from(new Address($list->mail, $list->displayName));
            $email->to(new Address($owner->email));
            // Lets an owner just hit "Reply" in their mail client to accept — without
            // this, a reply went to $list->mail (the From address) instead, silently
            // distributing nothing and never reaching ModerationResponseHandler at all.
            $email->replyTo(new Address($acceptAddress));
            $email->subject($translatedSubject);

            // multipart/mixed: text/plain (no HTML to prevent token leakage) + message/rfc822
            $textPart = new TextPart($body, 'utf-8', 'plain');
            // message/rfc822 per RFC 2046 only allows 7bit/8bit/binary transfer
            // encoding, never quoted-printable/base64 — DataPart defaults to base64
            // for a null charset, which made Thunderbird (and others) refuse to
            // display the attached original mail at all.
            $originalPart = new DataPart($rawMime, null, 'message/rfc822', '8bit');
            $email->setBody(new MixedPart($textPart, $originalPart));

            try {
                $transport = $this->smtpFactory->getTransport($list);
                $mailer = new Mailer($transport);
                $mailer->send($email);
            } catch (\Throwable $e) {
                error_log("Listig: Failed to send moderation mail to {$owner->email}: " . $e->getMessage());
            }
        }

        // Owners aren't the only ones left waiting — without this, a sender whose
        // mail is pending moderation gets no feedback at all until (if ever) an
        // owner acts on it, indistinguishable from the mail having silently
        // vanished. Sent once per incoming mail (only on first queueing, not
        // again on every 7-day reminder resend — see $isNewItem above), not once
        // per owner above.
        if ($isNewItem && $senderMail !== '') {
            $this->notificationMailer->send(
                $list,
                $senderMail,
                $this->translator->trans('moderation.pending_notice.subject', ['%list%' => $list->displayName], null, $locale),
                $this->translator->trans('moderation.pending_notice.body', [
                    '%list%' => $list->displayName,
                    '%mail%' => $list->mail,
                    '%subject%' => $subject,
                    '%date%' => $mailDate,
                ], null, $locale),
                // Same attachment as the owners' own copy above — lets the sender
                // tell which of their mails this notice is about, same reasoning
                // as RejectionNotifier::notify().
                $rawMime,
                'original.eml',
                'message/rfc822',
            );
        }
    }
}
