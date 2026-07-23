<?php

declare(strict_types=1);

namespace Hengeb\Listig\Mail;

use Hengeb\Listig\Config\ListConfig;
use Hengeb\Listig\Smtp\SmtpConnectionFactory;
use Symfony\Component\Mailer\Mailer;
use Symfony\Component\Mime\Address;
use Symfony\Component\Mime\Email;

/**
 * Sends short plain-text operational notifications (delivery failures, bounces,
 * moderation/unsubscribe notices) from a list's address. Centralizes the
 * "build Email, get transport, send, log on failure" boilerplate previously
 * duplicated across QueueSender, UnsubscribeController, ModerationResponseHandler,
 * and bin/worker.php.
 */
class NotificationMailer
{
    public function __construct(
        private readonly SmtpConnectionFactory $smtpFactory,
    ) {
    }

    /** @param Address[]|string[] $to */
    public function send(
        ListConfig $list,
        array|string $to,
        string $subject,
        string $text,
        ?string $attachmentContent = null,
        ?string $attachmentName = null,
        ?string $attachmentMimeType = null,
    ): void {
        $recipients = is_array($to) ? $to : [$to];
        if (empty($recipients)) {
            return;
        }

        try {
            $transport = $this->smtpFactory->getTransport($list);
            $mailer = new Mailer($transport);

            $email = new Email();
            $email->from(new Address($list->mail, $list->displayName));
            $email->to(...array_map(
                fn($recipient) => $recipient instanceof Address ? $recipient : new Address($recipient),
                $recipients,
            ));
            $email->subject($subject);
            $email->text($text);

            if ($attachmentContent !== null) {
                $email->attach($attachmentContent, $attachmentName, $attachmentMimeType);
            }

            $mailer->send($email);
        } catch (\Throwable $e) {
            error_log("Listig: Failed to send notification '{$subject}' for list {$list->name}: " . $e->getMessage());
        }
    }

    public function sendToOwners(
        ListConfig $list,
        string $subject,
        string $text,
        ?string $attachmentContent = null,
        ?string $attachmentName = null,
        ?string $attachmentMimeType = null,
    ): void {
        $owners = $list->getOwners();
        if (empty($owners)) {
            return;
        }

        $this->send(
            $list,
            array_map(fn($owner) => new Address($owner->email), $owners),
            $subject,
            $text,
            $attachmentContent,
            $attachmentName,
            $attachmentMimeType,
        );
    }
}
