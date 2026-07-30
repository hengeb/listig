<?php

declare(strict_types=1);

namespace Hengeb\Listig\Http\Controller;

use Hengeb\Listig\Archive\ArchiveHtmlSanitizer;
use Hengeb\Listig\Archive\ArchiveIndexer;
use Hengeb\Listig\Archive\ArchiveMailCache;
use Hengeb\Listig\Archive\ArchiveMailLocator;
use Hengeb\Listig\Archive\ArchiveMailNotFoundException;
use Hengeb\Listig\Archive\ArchiveSynchronizer;
use Hengeb\Listig\Archive\ArchiveThreader;
use Hengeb\Listig\Archive\ByteFormatter;
use Hengeb\Listig\Archive\CachedArchivedMail;
use Hengeb\Listig\Archive\CachedAttachment;
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

    /**
     * MIME types ever eligible for inline (browser-rendered, open-in-new-tab)
     * delivery instead of a forced download — never svg, it can carry scripts.
     * Every one of these the browser can display natively; anything else falls
     * back to a download regardless of what the mail itself claims.
     */
    private const INLINE_SAFE_MIME_TYPES = ['image/png', 'image/jpeg', 'image/gif', 'image/webp', 'application/pdf'];

    /**
     * Deliberately short — this token only needs to survive one page load's worth
     * of <img> requests from inside the sandboxed frame (see attachment() /
     * ARCHIVE_ATTACHMENT_TOKEN purpose below), not act as a lasting credential.
     */
    private const ARCHIVE_ATTACHMENT_TOKEN_MAX_AGE = 10 * 60;

    /**
     * How often index() re-checks the archive folder against archived_mail per
     * list, per session — see ArchiveSynchronizer's docblock for the cost this
     * throttles (a SEARCH ALL + FETCH OVERVIEW scan of the whole folder, which
     * grows with folder size, unlike the rest of index() which is a plain
     * indexed DB read).
     */
    private const SYNC_INTERVAL_SECONDS = 5 * 60;

    public function __construct(
        private readonly Engine $latte,
        private readonly PDO $db,
        private readonly ListProvider $listProvider,
        private readonly ArchiveThreader $threader,
        private readonly ArchiveMailLocator $mailLocator,
        private readonly ArchiveMailCache $mailCache,
        private readonly ArchiveIndexer $archiveIndexer,
        private readonly ArchiveHtmlSanitizer $sanitizer,
        private readonly TranslatorInterface $translator,
        private readonly string $appName,
        private readonly TokenService $tokenService,
        private readonly ArchiveSynchronizer $synchronizer,
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

        $this->syncIfDue($list);

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

    /**
     * Throttles ArchiveSynchronizer::sync() to once per SYNC_INTERVAL_SECONDS,
     * per list, per session. A cheap count-only check can't replace this — it
     * can't detect "one mail deleted, a different one added" (same total
     * count) — but the full scan's cost grows with the archive folder's size,
     * so it also can't run on every single page load; see ArchiveSynchronizer's
     * own docblock for the exact cost shape this throttle is based on.
     *
     * Session-scoped rather than global/DB-tracked: this is purely a "don't
     * hammer IMAP on every reload" throttle, not a correctness guarantee — a
     * fresh session (or simply waiting out the interval) always re-syncs.
     * Recorded even when sync() finds nothing to do or fails (transient IMAP
     * error) — retrying on every single request while IMAP is down would
     * defeat the point of throttling at all.
     */
    private function syncIfDue(ListConfig $list): void
    {
        $lastSync = $_SESSION['archive_synced'][$list->name] ?? null;
        if ($lastSync !== null && time() - $lastSync < self::SYNC_INTERVAL_SECONDS) {
            return;
        }

        $this->synchronizer->sync($list);
        $_SESSION['archive_synced'][$list->name] = time();
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

        $mail = $this->locateMail($list, $row['message_id']);

        // Attachments actually referenced inline in the body (rewritten to cid: URLs
        // by ArchiveHtmlSanitizer) are not listed again as separate downloads —
        // array_filter preserves CachedArchivedMail::$attachments' positional
        // keys, which is exactly the {index} the attachment/frame routes expect
        // (see ArchiveController::indexAttachmentsByPosition()'s docblock for why).
        $attachments = $mail !== null
            ? array_filter($mail->attachments, fn(CachedAttachment $a) => !self::isEmbeddedInline($a))
            : [];

        // Shown a second time below the mail body as a thumbnail gallery — the
        // claimed MIME type is fine for this (a UI hint, not a security decision;
        // attachment() independently verifies actual bytes before ever serving one
        // inline — see isSafeInlineContent()).
        $imageAttachments = array_filter($attachments, fn(CachedAttachment $a) => str_starts_with($a->mimeType ?? '', 'image/'));

        $totalAttachmentSize = array_sum(array_map(fn(CachedAttachment $a) => $a->sizeInBytes ?? 0, $attachments));

        // The "external content blocked" notice (show.latte) should only appear
        // when there's actually something blocked — previously shown unconditionally
        // under every mail, even a plain-text-only one or an HTML one with no
        // off-origin images at all.
        $hasExternalContent = $mail !== null && $this->sanitizer->hasExternalResources(
            $mail->textHtml,
            $mail->textPlain,
            $mail->attachments,
        );

        $this->translator->setLocale($list->language);

        $user = $request->getAttribute('user');

        $html = $this->latte->renderToString(__DIR__ . '/../../../templates/archive/show.latte', [
            'user'                 => $user,
            // Gates the delete button (show.latte) — deleting is an owner-only
            // action regardless of the list's archive mode, unlike viewing itself
            // (checkAccess() above already allowed Public/Members access without
            // requiring ownership).
            'isOwner'              => $user !== null && $list->isOwnedBy($user['email']),
            'list'                 => $list,
            'row'                  => $row,
            'mailMissing'          => $mail === null,
            'attachments'          => $attachments,
            'imageAttachments'     => $imageAttachments,
            'totalAttachmentSize'  => ByteFormatter::format($totalAttachmentSize),
            'hasExternalContent'   => $hasExternalContent,
            // Only meaningful when both exist — a mail with only one part has
            // nothing to switch between, so the toggle button stays hidden for it.
            'hasPlainAlternative'  => $mail !== null && ($mail->textHtml ?? '') !== '' && ($mail->textPlain ?? '') !== '',
            'language'             => $list->language,
            'translator'           => $this->translator,
            'appName'              => $this->appName,
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

        $mail        = $this->locateMail($list, $row['message_id']);
        $loadImages  = ($request->getQueryParams()['loadImages'] ?? '') === '1';
        // 'text' forces the plaintext part even when textHtml exists — the
        // show.latte toggle button (only shown when both parts exist, see show())
        // reloads the iframe with this param. Anything else (including absent)
        // keeps the existing default: HTML if present, plaintext otherwise.
        $view        = ($request->getQueryParams()['view'] ?? '') === 'text' ? 'text' : 'html';
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
                $bodyHtml = $this->sanitizer->render($mail->textHtml, $mail->textPlain, $mail->attachments, $baseUrl, $loadImages, $attachmentToken, $view);
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

        $mail = $this->locateMail($list, $row['message_id']);
        if ($mail === null) {
            return $response->withStatus(404);
        }

        $index = (int) $args['index'];
        if (!isset($mail->attachments[$index])) {
            return $response->withStatus(404);
        }
        $attachment = $mail->attachments[$index];
        $contents = $attachment->contents;
        if ($contents === null) {
            // Eager fetch failed while building the cached/located snapshot
            // (see CachedAttachment::$contents' docblock) — same client-visible
            // outcome as a live getContents() failure used to be.
            error_log("Listig: attachment $index unavailable for archived mail {$row['id']} on list {$list->name}");
            return $response->withStatus(502);
        }
        $mimeType = $attachment->mimeType ?: 'application/octet-stream';

        $response = $response->withHeader('X-Content-Type-Options', 'nosniff');

        // Inline (browser-rendered) whenever the content is a verified, safe type
        // — deliberately regardless of the mail's own claimed disposition: a
        // regular (non-cid) image or PDF attachment gets the same "open in a new
        // tab" treatment as an embedded one, since the browser can display either
        // just as safely either way (see show.latte's attachment links, which all
        // carry target="_blank" for exactly this).
        if (self::isSafeInlineContent($contents, $mimeType)) {
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
     * Owner-only, permanent delete of a single archived mail — from both the
     * IMAP archive folder (ArchiveMailLocator::delete()) and the archived_mail
     * index row (ArchiveIndexer::remove()), plus any cached snapshot
     * (ArchiveMailCache::delete()) so a viewer who had the mail open moments
     * ago doesn't keep seeing it for the rest of the cache's TTL. Registered
     * under /_/api (AuthMiddleware + CsrfMiddleware — see public/index.php),
     * not the OptionalAuthMiddleware group the read-only archive routes use:
     * unlike viewing, deleting must never be reachable without a real session,
     * even for an `archive: public` list.
     */
    public function delete(ServerRequestInterface $request, ResponseInterface $response, array $args): ResponseInterface
    {
        $user = $request->getAttribute('user');
        $list = $this->listProvider->getList($args['listname']);
        if ($list === null || !$list->isOwnedBy($user['email'])) {
            return $this->jsonError($response, 403, 'Forbidden');
        }

        $row = $this->fetchRow($list->name, (int) $args['id']);
        if ($row === null) {
            return $this->jsonError($response, 404, 'Not found');
        }

        // Order matters: delete the IMAP message first, while message_id is
        // still known from $row — ArchiveIndexer::remove() below is what makes
        // that row (and therefore message_id) unreachable via fetchRow() again.
        $this->mailLocator->delete($list, $row['message_id']);
        $this->mailCache->delete($list->name, $row['message_id']);
        $this->archiveIndexer->remove($list->name, $row['message_id']);

        return $this->json($response, ['status' => 'deleted']);
    }

    private function json(ResponseInterface $response, array $data, int $status = 200): ResponseInterface
    {
        $response->getBody()->write(json_encode($data));
        return $response->withStatus($status)->withHeader('Content-Type', 'application/json');
    }

    private function jsonError(ResponseInterface $response, int $status, string $error): ResponseInterface
    {
        return $this->json($response, ['error' => $error], $status);
    }

    /**
     * Wraps ArchiveMailLocator::find() with ArchiveMailCache — a single "view
     * this archived mail" page load fires several separate HTTP requests
     * (show(), frame(), one attachment() request per embedded image), each of
     * which would otherwise independently pay for ArchiveMailLocator's full
     * IMAP connect + SEARCH ALL + FETCH OVERVIEW scan of the *entire* archive
     * folder just to re-locate the same one message (measured live: ~550ms per
     * call against a 20-message archive folder — see ArchiveMailCache's own
     * docblock for the full reasoning, including why this returns a
     * CachedArchivedMail snapshot rather than the IncomingMail object itself).
     *
     * On a cache miss, every attachment's contents is fetched eagerly right
     * here — while the IMAP connection ArchiveMailLocator just opened is still
     * live — rather than lazily on demand later (impossible for a cached
     * snapshot anyway, see CachedAttachment). A single attachment failing to
     * fetch doesn't discard the whole mail: it's cached with a null $contents,
     * and attachment() surfaces that as the same 502 a live fetch failure
     * would have produced.
     */
    private function locateMail(ListConfig $list, string $messageId): ?CachedArchivedMail
    {
        $cached = $this->mailCache->get($list->name, $messageId);
        if ($cached !== null) {
            return $cached;
        }

        try {
            $mail = $this->mailLocator->find($list, $messageId);
        } catch (ArchiveMailNotFoundException) {
            // Confirmed gone from the IMAP archive folder (not a transient
            // failure — see the exception's own docblock): the list archive
            // must not keep listing a mail nobody can ever open again. Removed
            // lazily, right here, rather than via a periodic sync job.
            $this->archiveIndexer->remove($list->name, $messageId);
            return null;
        }
        if ($mail === null) {
            return null;
        }

        $attachments = [];
        foreach (self::indexAttachmentsByPosition($mail->getAttachments()) as $index => $attachment) {
            try {
                $contents = $attachment->getContents();
            } catch (\Throwable $e) {
                error_log("Listig: failed to eagerly fetch attachment $index for Message-ID $messageId on list {$list->name}: " . $e->getMessage());
                $contents = null;
            }
            $attachments[$index] = new CachedAttachment(
                $attachment->name,
                $attachment->mimeType,
                $attachment->sizeInBytes,
                $attachment->disposition,
                $attachment->contentId,
                $contents,
            );
        }

        $cached = new CachedArchivedMail($mail->textHtml, $mail->textPlain, $attachments);
        $this->mailCache->set($list->name, $messageId, $cached);

        return $cached;
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
    private static function isEmbeddedInline(CachedAttachment $attachment): bool
    {
        return ($attachment->disposition ?? '') === 'inline' && ($attachment->contentId ?? '') !== '';
    }

    /**
     * Trusting a mail's own Content-Disposition/MIME claim to decide "safe to serve
     * inline" would let a mislabeled attachment ride along; verify the actual bytes
     * decode as one of the whitelisted types before honoring the claim. Images are
     * verified via getimagesizefromstring() (decodes and reports the real format);
     * PDF has no equivalent lightweight PHP decoder, so its magic-bytes header is
     * checked instead — a lighter guarantee, but %PDF- is specific enough that a
     * mislabeled non-PDF attachment couldn't plausibly start with it by accident.
     */
    private static function isSafeInlineContent(string $contents, string $claimedMimeType): bool
    {
        $claimedMimeType = strtolower($claimedMimeType);
        if (!in_array($claimedMimeType, self::INLINE_SAFE_MIME_TYPES, true)) {
            return false;
        }

        if ($claimedMimeType === 'application/pdf') {
            return str_starts_with($contents, '%PDF-');
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
