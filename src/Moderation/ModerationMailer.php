<?php

declare(strict_types=1);

namespace Hengeb\Listig\Moderation;

use Hengeb\Listig\Config\ListConfig;
use Hengeb\Listig\Smtp\SmtpConnectionFactory;
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
    ) {
    }

    public function send(ListConfig $list, IncomingMail $mail, int $imapUid, int $uidValidity, string $rawMime): void
    {
        $owners = $list->getOwners();
        if (empty($owners)) {
            error_log("Listig: No owners for list {$list->name}, cannot send moderation mail");
            return;
        }

        // The token embeds list, uid and uidvalidity and is HMAC-signed, so it is fully
        // self-describing — verifying an accept/reject reply never needs a DB lookup.
        // One shared pair per message (not per owner): the token doesn't identify which
        // owner approved, that is checked separately via $list->isOwnedBy() on arrival.
        $acceptToken = $this->tokenService->sign('accept', $list->name, $imapUid, $uidValidity);
        $rejectToken = $this->tokenService->sign('reject', $list->name, $imapUid, $uidValidity);

        $acceptAddress = "{$list->name}+accept-{$acceptToken}@{$list->domain}";
        $rejectAddress = "{$list->name}+reject-{$rejectToken}@{$list->domain}";

        $subject = $mail->subject ?? '';
        $senderName = $mail->fromName ?? '';
        $senderMail = $mail->fromAddress ?? '';
        // Same fallback as ArchiveIndexer::index() for the same field — an
        // unparseable/absent Date header must not block queuing the item.
        $mailDate = date('Y-m-d H:i:s', strtotime($mail->date ?? '') ?: time());

        // moderation_queue only tracks that an item is pending and when it was created/
        // reminded/from whom — it holds no secret, so a plain dedup no-op (not updating
        // the mail metadata on a repeat call) is enough here; the metadata was already
        // correct from the first INSERT and never changes for a given UID.
        $this->db->prepare(
            'INSERT INTO moderation_queue (list_cn, imap_uid, imap_uidvalidity, subject, sender_name, sender_mail, mail_date, created_at)
             VALUES (:list, :uid, :validity, :subject, :sender_name, :sender_mail, :mail_date, NOW())
             ON DUPLICATE KEY UPDATE id = id'
        )->execute([
            'list' => $list->name,
            'uid' => $imapUid,
            'validity' => $uidValidity,
            'subject' => $subject,
            'sender_name' => $senderName,
            'sender_mail' => $senderMail,
            'mail_date' => $mailDate,
        ]);

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
            '%accept%' => $acceptAddress,
            '%reject%' => $rejectAddress,
        ], null, $locale);

        foreach ($owners as $owner) {
            $email = new Email();
            $email->from(new Address($list->mail, $list->displayName));
            $email->to(new Address($owner->email));
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
    }
}
