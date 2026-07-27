<?php

declare(strict_types=1);

namespace Hengeb\Listig\Http\Controller;

use Hengeb\Listig\Archive\ArchiveHtmlSanitizer;
use Hengeb\Listig\Archive\ArchiveMailLocator;
use Hengeb\Listig\Archive\ArchiveThreader;
use Hengeb\Listig\Config\Enum\ArchiveMode;
use Hengeb\Listig\Config\ListConfig;
use Hengeb\Listig\Provider\ListProvider;
use Hengeb\Listig\Token\TokenService;
use Latte\Engine;
use PDO;
use PhpImap\IncomingMailAttachment;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Response;
use Symfony\Contracts\Translation\TranslatorInterface;

class ArchiveController
{
    private const PER_PAGE = 1000;

    /** MIME types ever eligible for inline (non-download) delivery — never svg, it can carry scripts. */
    private const INLINE_SAFE_MIME_TYPES = ['image/png', 'image/jpeg', 'image/gif', 'image/webp'];

    /**
     * Deliberately short — this token only needs to survive one page load's worth
     * of <img> requests from inside the sandboxed frame (see attachment() /
     * ARCHIVE_ATTACHMENT_TOKEN purpose below), not act as a lasting credential.
     */
    private const ARCHIVE_ATTACHMENT_TOKEN_MAX_AGE = 10 * 60;

    public function __construct(
        private readonly Engine $latte,
        private readonly PDO $db,
        private readonly ListProvider $listProvider,
        private readonly ArchiveThreader $threader,
        private readonly ArchiveMailLocator $mailLocator,
        private readonly ArchiveHtmlSanitizer $sanitizer,
        private readonly TranslatorInterface $translator,
        private readonly string $appName,
        private readonly TokenService $tokenService,
    ) {
    }

    public function index(ServerRequestInterface $request, ResponseInterface $response, array $args): ResponseInterface
    {
        $list = $this->listProvider->getList($args['listname']);
        if ($list === null) {
            return $response->withStatus(404);
        }
        $denied = $this->checkAccess($request, $list);
        if ($denied !== null) {
            return $denied;
        }

        $page   = max(1, (int) ($request->getQueryParams()['page'] ?? 1));
        $offset = ($page - 1) * self::PER_PAGE;

        $rows  = $this->threader->annotate($this->fetchRows($list->name, self::PER_PAGE, $offset));
        $total = $this->countRows($list->name);

        $this->translator->setLocale($list->language);

        $html = $this->latte->renderToString(__DIR__ . '/../../../templates/archive/index.latte', [
            'user'       => $request->getAttribute('user'),
            'list'       => $list,
            'rows'       => $rows,
            'page'       => $page,
            'totalPages' => (int) ceil($total / self::PER_PAGE),
            'total'      => $total,
            'language'   => $list->language,
            'translator' => $this->translator,
            'appName'    => $this->appName,
        ]);
        $response->getBody()->write($html);
        return $response;
    }

    public function show(ServerRequestInterface $request, ResponseInterface $response, array $args): ResponseInterface
    {
        $list = $this->listProvider->getList($args['listname']);
        if ($list === null) {
            return $response->withStatus(404);
        }
        $denied = $this->checkAccess($request, $list);
        if ($denied !== null) {
            return $denied;
        }

        $row = $this->fetchRow($list->name, (int) $args['id']);
        if ($row === null) {
            return $response->withStatus(404);
        }

        $mail = $this->mailLocator->find($list, $row['message_id']);

        // Attachments actually referenced inline in the body (rewritten to cid: URLs
        // by ArchiveHtmlSanitizer) are not listed again as separate downloads —
        // array_filter preserves the positional keys assigned by
        // indexAttachmentsByPosition(), which is exactly the {index} the
        // attachment/frame routes expect (see that method's docblock for why).
        $attachments = $mail !== null
            ? array_filter(self::indexAttachmentsByPosition($mail->getAttachments()), fn(IncomingMailAttachment $a) => !self::isEmbeddedInline($a))
            : [];

        $this->translator->setLocale($list->language);

        $html = $this->latte->renderToString(__DIR__ . '/../../../templates/archive/show.latte', [
            'user'        => $request->getAttribute('user'),
            'list'        => $list,
            'row'         => $row,
            'mailMissing' => $mail === null,
            'attachments' => $attachments,
            'language'    => $list->language,
            'translator'  => $this->translator,
            'appName'     => $this->appName,
        ]);
        $response->getBody()->write($html);
        return $response;
    }

    public function frame(ServerRequestInterface $request, ResponseInterface $response, array $args): ResponseInterface
    {
        $list = $this->listProvider->getList($args['listname']);
        if ($list === null) {
            return $response->withStatus(404);
        }
        $denied = $this->checkAccess($request, $list);
        if ($denied !== null) {
            return $denied;
        }

        $row = $this->fetchRow($list->name, (int) $args['id']);
        if ($row === null) {
            return $response->withStatus(404);
        }

        $mail        = $this->mailLocator->find($list, $row['message_id']);
        $loadImages  = ($request->getQueryParams()['loadImages'] ?? '') === '1';
        $baseUrl     = "/{$list->name}/archive/{$args['id']}/attachment";

        // The <img> tags this produces (cid: rewrites) are fetched by the browser
        // from *inside* the sandboxed iframe below — sandbox with no
        // allow-same-origin gives that content a unique opaque origin, so those
        // requests carry no session cookie at all, regardless of the viewer's own
        // login. attachment() accepts this signed, mail-scoped token as a fallback
        // grant for exactly that case (see attachment()) — checkAccess() above
        // already confirmed access once for this same request.
        $attachmentToken = $this->tokenService->sign('archive-attachment', $list->name, (string) $row['id']);

        $bodyHtml = null;
        if ($mail !== null) {
            try {
                $bodyHtml = $this->sanitizer->render($mail->textHtml, $mail->textPlain, self::indexAttachmentsByPosition($mail->getAttachments()), $baseUrl, $loadImages, $attachmentToken);
            } catch (\Throwable $e) {
                error_log("Listig: failed to render archived mail {$row['id']} for list {$list->name}: " . $e->getMessage());
            }
        }

        $this->translator->setLocale($list->language);

        $html = $this->latte->renderToString(__DIR__ . '/../../../templates/archive/frame.latte', [
            'bodyHtml'   => $bodyHtml,
            'translator' => $this->translator,
        ]);
        $response->getBody()->write($html);

        // Own strict CSP, independent of the outer page — the sandboxed iframe (see
        // templates/archive/show.latte) already blocks scripts via the `sandbox`
        // attribute; this is defense-in-depth for the response itself. img-src only
        // widens beyond 'self' (our own cid:-rewritten attachment URLs) when the
        // viewer has explicitly opted into loading external images for this mail —
        // ArchiveHtmlSanitizer::stripExternalResources() is what actually removes
        // off-origin img[src]/srcset otherwise, but a same-origin-only CSP was
        // blocking them outright even when that step correctly left them in place.
        $imgSrc = $loadImages ? "img-src 'self' https: http:" : "img-src 'self'";
        return $response
            ->withHeader('Content-Type', 'text/html; charset=utf-8')
            ->withHeader('Content-Security-Policy', "default-src 'none'; {$imgSrc}; style-src 'unsafe-inline'; frame-ancestors 'self'")
            ->withHeader('X-Frame-Options', 'SAMEORIGIN');
    }

    public function attachment(ServerRequestInterface $request, ResponseInterface $response, array $args): ResponseInterface
    {
        $list = $this->listProvider->getList($args['listname']);
        if ($list === null) {
            return $response->withStatus(404);
        }
        $denied = $this->checkAccess($request, $list);
        if ($denied !== null) {
            // Session-based access failed — this is also the endpoint <img> tags
            // inside the sandboxed archive/frame.latte iframe fetch for cid:
            // attachments, and those requests never carry a session cookie (see
            // frame()'s $attachmentToken comment). Accept a valid token for this
            // exact list+mail as an alternative grant before giving up.
            $token = $request->getQueryParams()['token'] ?? '';
            if (!$this->isValidAttachmentToken($token, $list->name, $args['id'] ?? '')) {
                return $denied;
            }
        }

        $row = $this->fetchRow($list->name, (int) $args['id']);
        if ($row === null) {
            return $response->withStatus(404);
        }

        $mail = $this->mailLocator->find($list, $row['message_id']);
        if ($mail === null) {
            return $response->withStatus(404);
        }

        $attachments = self::indexAttachmentsByPosition($mail->getAttachments());
        $index = (int) $args['index'];
        if (!isset($attachments[$index])) {
            return $response->withStatus(404);
        }
        $attachment = $attachments[$index];
        try {
            $contents = $attachment->getContents();
        } catch (\Throwable $e) {
            error_log("Listig: failed to fetch attachment $index for archived mail {$row['id']} on list {$list->name}: " . $e->getMessage());
            return $response->withStatus(502);
        }
        $mimeType = $attachment->mimeType ?: 'application/octet-stream';

        $response = $response->withHeader('X-Content-Type-Options', 'nosniff');

        if (self::isEmbeddedInline($attachment) && self::isSafeInlineImage($contents, $mimeType)) {
            $response = $response
                ->withHeader('Content-Type', $mimeType)
                ->withHeader('Content-Disposition', 'inline');
        } else {
            $filename = self::sanitizeFilename($attachment->name ?: 'attachment');
            $response = $response
                ->withHeader('Content-Type', $mimeType)
                ->withHeader('Content-Disposition', "attachment; filename=\"{$filename}\"");
        }

        $response->getBody()->write($contents);
        return $response;
    }

    /** @see frame()'s $attachmentToken comment for why this fallback exists. */
    private function isValidAttachmentToken(string $token, string $listCn, string $archivedMailId): bool
    {
        if ($token === '') {
            return false;
        }
        try {
            [$tokenListCn, $tokenMailId] = $this->tokenService->verify(
                $token,
                'archive-attachment',
                self::ARCHIVE_ATTACHMENT_TOKEN_MAX_AGE,
            );
        } catch (\InvalidArgumentException) {
            return false;
        }
        return $tokenListCn === $listCn && $tokenMailId === $archivedMailId;
    }

    /**
     * Returns null if access is granted, otherwise the response to short-circuit
     * with. Off/Hidden always 404 — indistinguishable from a nonexistent list or
     * route, even for the list's own owner (Hidden means archived but exposed to
     * no one via the UI, by design — see CLAUDE.md "Archive access levels").
     */
    private function checkAccess(ServerRequestInterface $request, ListConfig $list): ?ResponseInterface
    {
        if ($list->archive === ArchiveMode::Off || $list->archive === ArchiveMode::Hidden) {
            return (new Response())->withStatus(404);
        }
        if ($list->archive === ArchiveMode::Public) {
            return null;
        }

        $user  = $request->getAttribute('user');
        $email = $user['email'] ?? null;
        if ($email === null) {
            return $this->loginRequiredResponse($list);
        }

        $allowed = match ($list->archive) {
            ArchiveMode::Members => $list->isMember($email) || $list->isOwnedBy($email),
            ArchiveMode::Owners  => $list->isOwnedBy($email),
            default              => false,
        };

        return $allowed ? null : (new Response())->withStatus(403);
    }

    private function loginRequiredResponse(ListConfig $list): ResponseInterface
    {
        $this->translator->setLocale($list->language);
        $html = $this->latte->renderToString(__DIR__ . '/../../../templates/archive/login_required.latte', [
            'list'       => $list,
            'language'   => $list->language,
            'translator' => $this->translator,
            'appName'    => $this->appName,
        ]);
        $response = (new Response())->withStatus(401);
        $response->getBody()->write($html);
        return $response;
    }

    private function fetchRows(string $listName, int $limit, int $offset): array
    {
        $stmt = $this->db->prepare(
            'SELECT m.* FROM archived_mail m
             JOIN (SELECT thread_root, MAX(mail_date) AS thread_activity
                   FROM archived_mail WHERE list_cn = :list GROUP BY thread_root) t
               ON m.thread_root = t.thread_root
             WHERE m.list_cn = :list
             ORDER BY t.thread_activity DESC, m.mail_date ASC
             LIMIT :limit OFFSET :offset'
        );
        $stmt->bindValue('list', $listName, PDO::PARAM_STR);
        $stmt->bindValue('limit', $limit, PDO::PARAM_INT);
        $stmt->bindValue('offset', $offset, PDO::PARAM_INT);
        $stmt->execute();
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    private function countRows(string $listName): int
    {
        $stmt = $this->db->prepare('SELECT COUNT(*) FROM archived_mail WHERE list_cn = :list');
        $stmt->execute(['list' => $listName]);
        return (int) $stmt->fetchColumn();
    }

    private function fetchRow(string $listName, int $id): ?array
    {
        $stmt = $this->db->prepare('SELECT * FROM archived_mail WHERE id = :id AND list_cn = :list');
        $stmt->execute(['id' => $id, 'list' => $listName]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        return $row ?: null;
    }

    /**
     * IncomingMail::getAttachments() is keyed by IncomingMailAttachment::$id —
     * PhpImap\Mailbox generates this fresh with bin2hex(random_bytes(20)) on
     * *every* parse, so it is never the same twice for the same message, let alone
     * stable across the separate HTTP requests this app's routes are split across
     * (show()'s attachment links and frame()'s cid: rewrites are rendered from one
     * getMail() call; clicking them or loading the resulting <img> triggers a
     * second, independent getMail() call in attachment(), via ArchiveMailLocator —
     * see its own docblock on why nothing here is cached across requests). Using
     * that random id as the {index} in a URL therefore can never work: by the time
     * attachment() looks it up, the id it's holding no longer exists anywhere.
     *
     * The MIME part order php-imap parses attachments in, by contrast, is fully
     * determined by the message's own (unchanging) byte structure — parsing the
     * same raw mail twice always encounters its attachments in the same order.
     * Re-keying by that position instead of the random id gives every caller
     * (show(), frame(), attachment()) a stable identifier that actually survives
     * from one request to the next.
     *
     * @param IncomingMailAttachment[] $attachments
     * @return array<int, IncomingMailAttachment>
     */
    private static function indexAttachmentsByPosition(array $attachments): array
    {
        return array_values($attachments);
    }

    /** An attachment rewritten to a cid: reference in the body by ArchiveHtmlSanitizer — not listed as a separate download. */
    private static function isEmbeddedInline(IncomingMailAttachment $attachment): bool
    {
        return ($attachment->disposition ?? '') === 'inline' && ($attachment->contentId ?? '') !== '';
    }

    /**
     * Trusting a mail's own Content-Disposition/MIME claim to decide "safe to serve
     * inline" would let a mislabeled attachment ride along; verify the actual bytes
     * decode as one of the whitelisted image types before honoring the claim.
     */
    private static function isSafeInlineImage(string $contents, string $claimedMimeType): bool
    {
        if (!in_array(strtolower($claimedMimeType), self::INLINE_SAFE_MIME_TYPES, true)) {
            return false;
        }
        $info = @getimagesizefromstring($contents);
        return $info !== false
            && isset($info['mime'])
            && in_array(strtolower($info['mime']), self::INLINE_SAFE_MIME_TYPES, true);
    }

    private static function sanitizeFilename(string $filename): string
    {
        return str_replace(["\r", "\n", '"'], '', $filename);
    }
}
