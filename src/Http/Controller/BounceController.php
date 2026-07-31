<?php

declare(strict_types=1);

namespace Hengeb\Listig\Http\Controller;

use Hengeb\Listig\Archive\ArchiveHtmlSanitizer;
use Hengeb\Listig\Archive\ArchiveMailNotFoundException;
use Hengeb\Listig\Archive\ArchiveMailResolver;
use Hengeb\Listig\Archive\AttachmentSafety;
use Hengeb\Listig\Archive\ByteFormatter;
use Hengeb\Listig\Archive\CachedArchivedMail;
use Hengeb\Listig\Archive\CachedAttachment;
use Hengeb\Listig\Config\ListConfig;
use Hengeb\Listig\Provider\ListProvider;
use Hengeb\Listig\Token\TokenService;
use Latte\Engine;
use PDO;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Response;
use Symfony\Contracts\Translation\TranslatorInterface;

/**
 * Owner-only preview of a bounce mail from the manage page's bounce table —
 * same rendering as the archive viewer and the moderation preview
 * (ModerationController), reusing archive/show.latte + archive/frame.latte.
 * Unlike a pending moderation mail (still on IMAP's INBOX, fetched by UID), a
 * bounce mail has *already* been archived (or deleted, if the list's archive
 * mode is Off) by ImapArchiver::archiveOrDelete() by the time anyone could
 * open this preview — so it's located the same way the archive viewer locates
 * any other archived mail: by Message-ID via ArchiveMailResolver, not by UID.
 * See CLAUDE.md "Bounce preview".
 */
class BounceController
{
    public function __construct(
        private readonly PDO $db,
        private readonly ListProvider $listProvider,
        private readonly Engine $latte,
        private readonly ArchiveMailResolver $resolver,
        private readonly ArchiveHtmlSanitizer $sanitizer,
        private readonly TranslatorInterface $translator,
        private readonly TokenService $tokenService,
        private readonly string $appName,
    ) {
    }

    public function show(ServerRequestInterface $request, ResponseInterface $response, array $args): ResponseInterface
    {
        $user = $request->getAttribute('user');
        [$item, $list, $denied] = $this->loadOwnedItem($request, (int) $args['id']);
        if ($denied !== null) {
            return $denied;
        }

        $mail = $item['message_id'] !== null ? $this->locateMail($list, $item['message_id']) : null;

        $attachments = $mail !== null
            ? array_filter($mail->attachments, fn(CachedAttachment $a) => !self::isEmbeddedInline($a))
            : [];
        $imageAttachments = array_filter($attachments, fn(CachedAttachment $a) => str_starts_with($a->mimeType ?? '', 'image/'));
        $totalAttachmentSize = array_sum(array_map(fn(CachedAttachment $a) => $a->sizeInBytes ?? 0, $attachments));

        $hasExternalContent = $mail !== null && $this->sanitizer->hasExternalResources(
            $mail->textHtml,
            $mail->textPlain,
            $mail->attachments,
        );

        $this->translator->setLocale($list->language);

        $html = $this->latte->renderToString(__DIR__ . '/../../../templates/archive/show.latte', [
            'user'                => $user,
            'allowDelete'         => false,
            'baseUrl'             => "/{$list->name}/bounce/{$item['id']}",
            'backUrl'             => "/{$list->name}",
            'backLabel'           => $this->translator->trans('list.manage.bounces'),
            'list'                => $list,
            // The bounce table (manage.latte) already shows this same raw sender
            // address in its own "Sender" column — unlike the archive/moderation
            // views, which only ever show a display name (see CLAUDE.md
            // "Privacy"), a bounce's own sender is the remote MTA
            // (MAILER-DAEMON@...), not a list member, so there is nothing extra
            // to redact here that isn't already on the same page.
            'row'                 => [
                'id'          => $item['id'],
                'subject'     => $item['subject'],
                'sender_name' => $item['sender'],
                'mail_date'   => $item['bounced_at'],
            ],
            'mailMissing'         => $mail === null,
            'attachments'         => $attachments,
            'imageAttachments'    => $imageAttachments,
            'totalAttachmentSize' => ByteFormatter::format($totalAttachmentSize),
            'hasExternalContent'  => $hasExternalContent,
            'hasPlainAlternative' => $mail !== null && ($mail->textHtml ?? '') !== '' && ($mail->textPlain ?? '') !== '',
            'language'            => $list->language,
            'translator'          => $this->translator,
            'appName'             => $this->appName,
        ]);
        $response->getBody()->write($html);
        return $response;
    }

    public function frame(ServerRequestInterface $request, ResponseInterface $response, array $args): ResponseInterface
    {
        [$item, $list, $denied] = $this->loadOwnedItem($request, (int) $args['id']);
        if ($denied !== null) {
            return $denied;
        }

        $mail       = $item['message_id'] !== null ? $this->locateMail($list, $item['message_id']) : null;
        $loadImages = ($request->getQueryParams()['loadImages'] ?? '') === '1';
        $view       = ($request->getQueryParams()['view'] ?? '') === 'text' ? 'text' : 'html';
        $baseUrl    = "/{$list->name}/bounce/{$item['id']}/attachment";

        // Same sandboxed-iframe-has-no-session-cookie problem as the archive
        // viewer's/moderation preview's own frame() — see their comments. Its
        // own token purpose ('bounce-attachment') keeps this grant from being
        // replayable against the other two.
        $attachmentToken = $this->tokenService->sign('bounce-attachment', $list->name, (string) $item['id']);

        $bodyHtml = null;
        if ($mail !== null) {
            try {
                $bodyHtml = $this->sanitizer->render($mail->textHtml, $mail->textPlain, $mail->attachments, $baseUrl, $loadImages, $attachmentToken, $view);
            } catch (\Throwable $e) {
                error_log("Listig: failed to render bounce mail {$item['id']} for list {$list->name}: " . $e->getMessage());
            }
        }

        $this->translator->setLocale($list->language);

        $html = $this->latte->renderToString(__DIR__ . '/../../../templates/archive/frame.latte', [
            'bodyHtml'   => $bodyHtml,
            'translator' => $this->translator,
        ]);
        $response->getBody()->write($html);

        $imgSrc = $loadImages ? "img-src 'self' https: http:" : "img-src 'self'";
        return $response
            ->withHeader('Content-Type', 'text/html; charset=utf-8')
            ->withHeader('Content-Security-Policy', "default-src 'none'; {$imgSrc}; style-src 'unsafe-inline'; frame-ancestors 'self'")
            ->withHeader('X-Frame-Options', 'SAMEORIGIN');
    }

    public function attachment(ServerRequestInterface $request, ResponseInterface $response, array $args): ResponseInterface
    {
        $item = $this->fetchItem((int) $args['id']);
        if ($item === null || $item['message_id'] === null) {
            return $response->withStatus(404);
        }
        $list = $this->listProvider->getList($item['list_cn']);
        if ($list === null) {
            return $response->withStatus(404);
        }

        $user = $request->getAttribute('user');
        if ($user === null || !$list->isOwnedBy($user['email'])) {
            // Same fallback grant as ArchiveController::attachment() — the <img>
            // tags frame()'s sandboxed iframe fetches carry no session cookie.
            $token = $request->getQueryParams()['token'] ?? '';
            if (!$this->isValidAttachmentToken($token, $list->name, (string) $item['id'])) {
                return $response->withStatus(403);
            }
        }

        $mail = $this->locateMail($list, $item['message_id']);
        if ($mail === null || !isset($mail->attachments[(int) $args['index']])) {
            return $response->withStatus(404);
        }
        $attachment = $mail->attachments[(int) $args['index']];
        $contents = $attachment->contents;
        if ($contents === null) {
            error_log("Listig: attachment {$args['index']} unavailable for bounce mail {$item['id']} on list {$list->name}");
            return $response->withStatus(502);
        }
        $mimeType = $attachment->mimeType ?: 'application/octet-stream';

        $response = $response->withHeader('X-Content-Type-Options', 'nosniff');
        if (AttachmentSafety::isSafeInlineContent($contents, $mimeType)) {
            $response = $response
                ->withHeader('Content-Type', $mimeType)
                ->withHeader('Content-Disposition', 'inline');
        } else {
            $filename = AttachmentSafety::sanitizeFilename($attachment->name ?: 'attachment');
            $response = $response
                ->withHeader('Content-Type', $mimeType)
                ->withHeader('Content-Disposition', "attachment; filename=\"{$filename}\"");
        }

        $response->getBody()->write($contents);
        return $response;
    }

    /**
     * Shared by show()/frame() — fetches the bounce_log row and its list,
     * checking ownership. Returns [item, list, null] on success, or
     * [null, null, $errorResponse] to short-circuit with.
     *
     * @return array{0: ?array, 1: ?ListConfig, 2: ?ResponseInterface}
     */
    private function loadOwnedItem(ServerRequestInterface $request, int $id): array
    {
        $item = $this->fetchItem($id);
        if ($item === null) {
            return [null, null, (new Response())->withStatus(404)];
        }

        $list = $this->listProvider->getList($item['list_cn']);
        if ($list === null) {
            return [null, null, (new Response())->withStatus(404)];
        }

        $user = $request->getAttribute('user');
        if ($user === null || !$list->isOwnedBy($user['email'])) {
            return [null, null, (new Response())->withStatus(403)];
        }

        return [$item, $list, null];
    }

    private function fetchItem(int $id): ?array
    {
        $stmt = $this->db->prepare('SELECT * FROM bounce_log WHERE id = :id');
        $stmt->execute(['id' => $id]);
        $item = $stmt->fetch(PDO::FETCH_ASSOC);
        return $item ?: null;
    }

    /**
     * No archived_mail-equivalent index to clean up on a confirmed-gone mail
     * (unlike ArchiveController::locateMail()) — a bounce_log row has nothing
     * else keyed off its message_id, so a stale one is simply left as-is; the
     * next open of the same row will just try (and fail) to locate it again.
     */
    private function locateMail(ListConfig $list, string $messageId): ?CachedArchivedMail
    {
        try {
            return $this->resolver->resolve($list, $messageId);
        } catch (ArchiveMailNotFoundException) {
            return null;
        }
    }

    /** @see frame()'s $attachmentToken comment for why this fallback exists. */
    private function isValidAttachmentToken(string $token, string $listCn, string $bounceId): bool
    {
        if ($token === '') {
            return false;
        }
        try {
            [$tokenListCn, $tokenId] = $this->tokenService->verify($token, 'bounce-attachment', 10 * 60);
        } catch (\InvalidArgumentException) {
            return false;
        }
        return $tokenListCn === $listCn && $tokenId === $bounceId;
    }

    private static function isEmbeddedInline(CachedAttachment $attachment): bool
    {
        return ($attachment->disposition ?? '') === 'inline' && ($attachment->contentId ?? '') !== '';
    }
}
