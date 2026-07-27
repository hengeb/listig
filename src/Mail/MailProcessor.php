<?php

declare(strict_types=1);

namespace Hengeb\Listig\Mail;

use Hengeb\Listig\Config\Enum\PostAccess;
use Hengeb\Listig\Config\Enum\ReplyToBehavior;
use Hengeb\Listig\Config\ListConfig;
use Hengeb\Listig\Member\Member;
use Hengeb\Listig\Queue\QueueWriter;
use Hengeb\Listig\Token\TokenService;
use Hengeb\Listig\Variable\Literal;
use Hengeb\Listig\Variable\ResolutionPurpose;
use Hengeb\Listig\Variable\VariableResolver;
use PhpImap\IncomingMail;
use Symfony\Component\Mime\Address;
use Symfony\Component\Mime\Email;
use Symfony\Component\Mime\Part\DataPart;

class MailProcessor
{
    public function __construct(
        private readonly HeaderFilter $headerFilter,
        private readonly BodyPersonalizer $bodyPersonalizer,
        private readonly FooterAppender $footerAppender,
        private readonly QueueWriter $queueWriter,
        private readonly TokenService $tokenService,
        private readonly string $hostname,
    ) {
    }

    public function process(IncomingMail $incomingMail, string $rawMime, ListConfig $list): void
    {
        $headersRaw  = $incomingMail->headersRaw ?? '';
        $authResults = $this->headerFilter->readAuthResults($headersRaw);

        $senderEmail    = $incomingMail->fromAddress ?? '';
        $rawFromHeader  = $this->extractFromHeader($headersRaw);
        $senderMember   = $list->findMemberByEmail($senderEmail) ?? new Member($senderEmail);

        // Build the outgoing Email from the parsed incoming mail
        $email = $this->buildOutgoingEmail($incomingMail);

        $subaddress = SubaddressExtractor::extract($incomingMail, $list);

        $listContext  = $list->createContext();
        $mailContext  = $this->buildMailContext($senderMember, $rawFromHeader, $subaddress);
        $mailContexts = [$listContext, $mailContext];

        $this->setOutgoingHeaders($email, $list, $senderEmail, $mailContexts);
        $this->applySubjectLabel($email, $list, $mailContexts);

        $recipients = $this->resolveRecipients($incomingMail, $list, $mailContexts);

        $personalizeKeys = $list->personalizeKeys;

        // Identifies all recipients' copies of this one incoming mail across the queue,
        // even though personalization gives each of them different outgoing MIME (and
        // therefore a different mail_queue.id, which is a hash of that MIME) — see
        // mail_queue.batch_id. Derived from the original incoming MIME, not the outgoing
        // one, so it stays constant regardless of per-recipient personalization.
        $batchId = hash('sha256', $list->name . ':' . $rawMime);

        foreach ($recipients as $recipient) {
            // Full recipient context — not pre-filtered. BodyPersonalizer gates by personalizeKeys
            // at the top level; FooterAppender is operator content with no restriction.
            $recipientContext  = $this->buildRecipientContext($recipient);
            $recipientContexts = [...$mailContexts, $recipientContext];

            $recipientEmail = clone $email;

            $this->bodyPersonalizer->personalize($recipientEmail, $recipientContexts, $personalizeKeys);
            $this->footerAppender->append($recipientEmail, $list, $recipientContexts);

            $token          = $this->tokenService->sign('unsubscribe', $list->name, $recipient->attributes['username'] ?? $recipient->email);
            $unsubscribeUrl = "https://{$this->hostname}/{$list->name}/unsubscribe?token={$token}";
            $recipientEmail->getHeaders()->remove('list-unsubscribe');
            $recipientEmail->getHeaders()->addTextHeader('List-Unsubscribe', "<{$unsubscribeUrl}>");
            $recipientEmail->getHeaders()->addTextHeader('List-Unsubscribe-Post', 'List-Unsubscribe=One-Click');

            $this->queueWriter->enqueue($list->name, $recipientEmail, $recipient->email, $batchId);
        }
    }

    private function buildOutgoingEmail(IncomingMail $mail): Email
    {
        $email = new Email();
        $email->subject($mail->subject ?? '');

        // Body
        if ($mail->textHtml !== null && $mail->textHtml !== '') {
            $email->html($mail->textHtml);
            if ($mail->textPlain !== null && $mail->textPlain !== '') {
                $email->text($mail->textPlain);
            }
        } elseif ($mail->textPlain !== null && $mail->textPlain !== '') {
            $email->text($mail->textPlain);
        }

        // Attachments. $mail->textHtml is copied into the outgoing body verbatim
        // above — any cid: references it contains are never rewritten — so an
        // attachment that's actually an embedded image (Content-Disposition:
        // inline with a Content-ID, matching such a cid: reference) must keep
        // both on the outgoing copy, or the reference resolves to nothing once
        // the recipient's mail client looks for it. Email::attach() always
        // creates a plain Content-Disposition: attachment part with no Content-ID
        // at all, silently breaking every embedded image on every distributed
        // mail; DataPart::asInline()/setContentId() (the same two primitives
        // Email::embed() itself calls, just without a way to pin a *specific*
        // pre-existing id) preserve the original inline part faithfully.
        foreach ($mail->getAttachments() as $attachment) {
            $contentType = $attachment->mimeType ?? 'application/octet-stream';
            if ($attachment->disposition === 'inline' && ($attachment->contentId ?? '') !== '') {
                $part = new DataPart($attachment->getContents(), $attachment->name, $contentType);
                $part->asInline()->setContentId($attachment->contentId);
                $email->addPart($part);
            } else {
                $email->attach($attachment->getContents(), $attachment->name, $contentType);
            }
        }

        // Threading and identification headers worth preserving. symfony/mime enforces
        // a specific header value class for some names (Headers::HEADER_CLASS_MAP) —
        // Message-ID must be an IdentificationHeader and Date a DateHeader, both
        // rejecting the UnstructuredHeader addTextHeader() always creates; In-Reply-To/
        // References are deliberately lenient (UnstructuredHeader is allowed there too,
        // to accept a Message-ID-shaped value that isn't strictly RFC-compliant), so
        // those two keep using addTextHeader() as before.
        $headersRaw = $mail->headersRaw ?? '';
        foreach (['Message-ID', 'In-Reply-To', 'References', 'Date'] as $header) {
            $value = $this->headerFilter->readHeader($headersRaw, $header);
            if ($value === null) {
                continue;
            }
            try {
                match ($header) {
                    // IdentificationHeader expects the bare id — Message-ID's raw value
                    // ("<abc123@domain>") still has the angle brackets HeaderFilter
                    // doesn't strip; getBodyAsString() re-adds them when serializing.
                    'Message-ID' => $email->getHeaders()->addIdHeader($header, trim($value, '<> ')),
                    'Date' => $email->getHeaders()->addDateHeader($header, new \DateTimeImmutable($value)),
                    default => $email->getHeaders()->addTextHeader($header, $value),
                };
            } catch (\Throwable $e) {
                // A malformed value from the sending MTA must not block distribution
                // of an otherwise-fine mail — skip preserving just this one header.
                error_log("Listig: Failed to preserve $header header on outgoing mail: " . $e->getMessage());
            }
        }

        // Original recipient context
        $email->getHeaders()->addTextHeader('X-Original-To', implode(', ', array_keys($mail->to)));
        $email->getHeaders()->addTextHeader('X-Forwarded-From', $mail->fromAddress ?? '');

        return $email;
    }

    private function extractFromHeader(string $headersRaw): string
    {
        return $this->headerFilter->readHeader($headersRaw, 'From') ?? '';
    }

    /**
     * $senderMember->attributes (whatever the resolver knows — firstname,
     * lastname, an LDAP employeeNumber, ...) is exposed under 'sender-' + its
     * own key name, e.g. {sender-firstname}, {sender-employeeNumber}. Nothing
     * beyond 'sender-mail' is hardcoded — a list wanting {sender-firstname} for
     * an LDAP sender configures its own `sender-firstname: "{sender-givenName}"`
     * alias, same pattern as `pronoun: "{businessCategory}"`.
     *
     * Every value here is Literal-wrapped (see VariableResolver) — it ultimately
     * comes from the incoming mail's sender (a directory/database/CSV row keyed
     * by their address, or the subaddress they addressed the list with), so a
     * self-chosen attribute value containing '{' must never be treated as a
     * template to recurse into — see "Untrusted input in {} templates" in CLAUDE.md.
     */
    private function buildMailContext(Member $senderMember, string $rawFromHeader, ?string $subaddress): array
    {
        $context = [];
        foreach ($senderMember->attributes as $key => $value) {
            $context["sender-$key"] = new Literal($value);
        }
        $context['sender-mail'] = new Literal($senderMember->email);
        $context['subaddress'] = new Literal($subaddress ?? '');
        $context['sender-name'] = function (array $contexts, ResolutionPurpose $purpose) use ($rawFromHeader): string {
            // Try display name from From header
            if ($rawFromHeader !== '' && preg_match('/^(.+?)\s*</', $rawFromHeader, $m)) {
                $name = trim(trim($m[1]), '"\'');
                if ($name !== '') {
                    return $name;
                }
            }
            $first = VariableResolver::lookup('sender-firstname', $contexts, $purpose) ?? '';
            $last  = VariableResolver::lookup('sender-lastname', $contexts, $purpose) ?? '';
            $full  = trim("$first $last");
            if ($full !== '') {
                return $full;
            }
            $email = VariableResolver::lookup('sender-mail', $contexts, $purpose) ?? '';
            $at    = strpos($email, '@');
            return $at !== false ? substr($email, 0, $at) : $email;
        };
        return $context;
    }

    /**
     * $recipient->attributes (whatever the resolver knows) is exposed directly
     * under each key's own name — {firstname}, {pronoun}, {employeeNumber},
     * whatever exists. 'mail' is set last so it always wins over a same-named
     * attribute (e.g. a raw LDAP 'mail' entry never shadows the canonical
     * recipient email — LdapMemberResolver already excludes it, but this stays
     * correct even if a resolver didn't).
     *
     * Every value is Literal-wrapped (see VariableResolver) — a recipient's own
     * data (e.g. self-set via the public subscribe API), not list config, so a
     * value containing '{' must never be recursed into as if it were a trusted
     * template — see "Untrusted input in {} templates" in CLAUDE.md.
     */
    private function buildRecipientContext(Member $recipient): array
    {
        $context = array_map(fn(string $v) => new Literal($v), $recipient->attributes);
        $context['mail'] = new Literal($recipient->email);
        return $context;
    }

    private function setOutgoingHeaders(Email $email, ListConfig $list, string $senderEmail, array $contexts): void
    {
        $headers = $email->getHeaders();

        $fromName = $list->smtpFromName !== null
            ? VariableResolver::resolve($list->smtpFromName, $contexts, ResolutionPurpose::Disclosed)
            : $list->displayName;
        $email->from(new Address($list->mail, $fromName));

        $senderHeader = "{$list->name}+bounce@{$list->domain}";
        $headers->remove('sender');
        $headers->addMailboxHeader('Sender', new Address($senderHeader));

        $headers->remove('reply-to');
        if ($list->replyTo === ReplyToBehavior::List) {
            $email->replyTo(new Address($list->mail));
        } else {
            $email->replyTo(new Address($senderEmail));
            $senderMember = $list->findMemberByEmail($senderEmail);
            $senderUsername = $senderMember?->attributes['username'] ?? null;
            if ($senderUsername !== null) {
                $headers->addTextHeader('X-Original-Sender', $senderUsername);
            }
        }

        $headers->remove('list-id');
        $headers->addTextHeader('List-Id', "<{$list->name}.{$list->domain}>");

        $headers->remove('list-post');
        if ($list->postAccess === PostAccess::Owners) {
            $headers->addTextHeader('List-Post', 'NO');
        } else {
            $headers->addTextHeader('List-Post', "<mailto:{$list->mail}>");
        }

        $headers->remove('list-help');
        $owners = $list->getOwners();
        if (!empty($owners)) {
            $headers->addTextHeader('List-Help', "<mailto:{$owners[0]->email}>");
        }

        $headers->remove('precedence');
        $headers->addTextHeader('Precedence', 'list');

        $headers->remove('x-loop');
        $headers->addTextHeader('X-Loop', $list->mail);
    }

    private function applySubjectLabel(Email $email, ListConfig $list, array $contexts): void
    {
        $label = $list->listLabel;
        if ($label === null || $label === '') {
            return;
        }

        $resolvedLabel = VariableResolver::resolve($label, $contexts, ResolutionPurpose::Disclosed);
        $subject       = $email->getSubject() ?? '';

        if (stripos($subject, $resolvedLabel) === false) {
            $email->subject("{$resolvedLabel} {$subject}");
        }
    }

    /** @return Member[] */
    private function resolveRecipients(IncomingMail $incomingMail, ListConfig $list, array $mailContexts): array
    {
        $excluded = array_map('strtolower', array_merge(
            array_keys($incomingMail->to),
            array_keys($incomingMail->cc)
        ));

        $members = $list->subaddressMemberTemplates !== null
            ? $this->resolveTemplateMembers($list->subaddressMemberTemplates, $mailContexts)
            : $list->getMembers();

        return array_values(array_filter(
            $members,
            fn(Member $m) => !in_array(strtolower($m->email), $excluded, true)
        ));
    }

    /**
     * Resolves type: subaddress member templates (mail, plus any other keys like
     * firstname/pronoun — all become Member::$attributes, same as
     * InlineMemberResolver) through VariableResolver — e.g. {subaddress}@intranet.com
     * — once per incoming mail, since the target depends on the specific recipient
     * address this mail was sent to.
     *
     * @param array<int, string|array{mail:string}> $templates
     * @return Member[]
     */
    private function resolveTemplateMembers(array $templates, array $contexts): array
    {
        $members = [];
        foreach ($templates as $entry) {
            if (is_string($entry)) {
                $members[] = new Member(VariableResolver::resolve($entry, $contexts, ResolutionPurpose::Disclosed));
                continue;
            }
            $mail = VariableResolver::resolve($entry['mail'], $contexts, ResolutionPurpose::Disclosed);
            $attributes = [];
            foreach ($entry as $key => $template) {
                if ($key === 'mail') {
                    continue;
                }
                $attributes[$key] = VariableResolver::resolve($template, $contexts, ResolutionPurpose::Disclosed);
            }
            $members[] = new Member($mail, $attributes);
        }
        return $members;
    }
}
