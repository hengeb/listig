<?php

declare(strict_types=1);

namespace Hengeb\Listig\Http\Controller;

use Hengeb\Listig\Archive\ArchiveHtmlSanitizer;
use Hengeb\Listig\Archive\ArchiveMailLocator;
use Hengeb\Listig\Archive\ArchiveThreader;
use Hengeb\Listig\Config\Enum\ArchiveMode;
use Hengeb\Listig\Config\ListConfig;
use Hengeb\Listig\Provider\ListProvider;
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

    public function __construct(
        private readonly Engine $latte,
        private readonly PDO $db,
        private readonly ListProvider $listProvider,
        private readonly ArchiveThreader $threader,
        private readonly ArchiveMailLocator $mailLocator,
        private readonly ArchiveHtmlSanitizer $sanitizer,
        private readonly TranslatorInterface $translator,
        private readonly string $appName,
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
        // array_filter preserves the original numeric keys, which is exactly the
        // {index} the attachment/frame routes expect.
        $attachments = $mail !== null
            ? array_filter($mail->getAttachments(), fn(IncomingMailAttachment $a) => !self::isEmbeddedInline($a))
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

        $bodyHtml = null;
        if ($mail !== null) {
            try {
                $bodyHtml = $this->sanitizer->render($mail->textHtml, $mail->textPlain, $mail->getAttachments(), $baseUrl, $loadImages);
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
        // attribute; this is defense-in-depth for the response itself.
        return $response
            ->withHeader('Content-Type', 'text/html; charset=utf-8')
            ->withHeader('Content-Security-Policy', "default-src 'none'; img-src 'self'; style-src 'unsafe-inline'; frame-ancestors 'self'")
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
            return $denied;
        }

        $row = $this->fetchRow($list->name, (int) $args['id']);
        if ($row === null) {
            return $response->withStatus(404);
        }

        $mail = $this->mailLocator->find($list, $row['message_id']);
        if ($mail === null) {
            return $response->withStatus(404);
        }

        $attachments = $mail->getAttachments();
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
        $mimeType = $attachment->getMimeType() ?: 'application/octet-stream';

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
