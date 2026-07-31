<?php

declare(strict_types=1);

namespace Hengeb\Listig\Http\Controller;

use Hengeb\Listig\Archive\ArchiveHtmlSanitizer;
use Hengeb\Listig\Archive\ArchiveIndexer;
use Hengeb\Listig\Archive\AttachmentSafety;
use Hengeb\Listig\Archive\ByteFormatter;
use Hengeb\Listig\Config\ListConfig;
use Hengeb\Listig\Imap\ImapArchiver;
use Hengeb\Listig\Imap\ImapPoller;
use Hengeb\Listig\Mail\IncomingMailFilter;
use Hengeb\Listig\Mail\MailProcessor;
use Hengeb\Listig\Mail\RejectionNotifier;
use Hengeb\Listig\Provider\ListProvider;
use Hengeb\Listig\Token\TokenService;
use Latte\Engine;
use PDO;
use PhpImap\IncomingMailAttachment;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Response;
use Symfony\Contracts\Translation\TranslatorInterface;

class ModerationController
{
    public function __construct(
        private readonly PDO $db,
        private readonly ListProvider $listProvider,
        private readonly MailProcessor $mailProcessor,
        private readonly ImapPoller $imapPoller,
        private readonly ImapArchiver $imapArchiver,
        private readonly ArchiveIndexer $archiveIndexer,
        private readonly RejectionNotifier $rejectionNotifier,
        private readonly Engine $latte,
        private readonly ArchiveHtmlSanitizer $sanitizer,
        private readonly TranslatorInterface $translator,
        private readonly TokenService $tokenService,
        private readonly string $appName,
    ) {
    }

    public function accept(ServerRequestInterface $request, ResponseInterface $response, array $args): ResponseInterface
    {
        return $this->handle($request, $response, (int) $args['id'], 'accept');
    }

    public function reject(ServerRequestInterface $request, ResponseInterface $response, array $args): ResponseInterface
    {
        return $this->handle($request, $response, (int) $args['id'], 'reject');
    }

    /**
     * Owner-only preview of a still-pending mail — same rendering as the archive
     * viewer (ArchiveController::show()/frame()/attachment()), reused via the
     * shared archive/show.latte + archive/frame.latte templates rather than
     * duplicated, since the two are otherwise near-identical (metadata table,
     * attachment list/gallery, sandboxed HTML frame). The mail itself comes
     * straight from IMAP by UID (ImapPoller::fetchMailByUid(), same as accept()
     * above) — not archived_mail/ArchiveMailLocator, since a pending item was
     * never archived and still lives in the inbox, not the archive folder.
     */
    public function show(ServerRequestInterface $request, ResponseInterface $response, array $args): ResponseInterface
    {
        $user = $request->getAttribute('user');
        [$item, $list, $denied] = $this->loadOwnedItem($request, (int) $args['id']);
        if ($denied !== null) {
            return $denied;
        }

        $mail = $this->imapPoller->fetchMailByUid($list, (int) $item['imap_uid']);
        $attachments = $mail !== null
            ? array_filter(self::indexAttachmentsByPosition($mail->getAttachments()), fn(IncomingMailAttachment $a) => !self::isEmbeddedInline($a))
            : [];
        $imageAttachments = array_filter($attachments, fn(IncomingMailAttachment $a) => str_starts_with($a->mimeType ?? '', 'image/'));
        $totalAttachmentSize = array_sum(array_map(fn(IncomingMailAttachment $a) => $a->sizeInBytes ?? 0, $attachments));

        $hasExternalContent = $mail !== null && $this->sanitizer->hasExternalResources(
            $mail->textHtml,
            $mail->textPlain,
            $mail->getAttachments(),
        );

        $this->translator->setLocale($list->language);

        $html = $this->latte->renderToString(__DIR__ . '/../../../templates/archive/show.latte', [
            'user'                => $user,
            // A pending mail isn't an archived_mail row — there's nothing here
            // for the delete button (archive-only) to act on.
            'allowDelete'         => false,
            'baseUrl'             => "/{$list->name}/moderation/{$item['id']}",
            'backUrl'             => "/{$list->name}",
            'backLabel'           => $this->translator->trans('list.manage.moderation_queue'),
            'list'                => $list,
            'row'                 => $item,
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

        $mail       = $this->imapPoller->fetchMailByUid($list, (int) $item['imap_uid']);
        $loadImages = ($request->getQueryParams()['loadImages'] ?? '') === '1';
        $view       = ($request->getQueryParams()['view'] ?? '') === 'text' ? 'text' : 'html';
        $baseUrl    = "/{$list->name}/moderation/{$item['id']}/attachment";

        // Same sandboxed-iframe-has-no-session-cookie problem as the archive
        // viewer's frame() — see its own comment. A distinct token purpose
        // ('moderation-attachment', not 'archive-attachment') keeps the two
        // grants from being replayable against each other.
        $attachmentToken = $this->tokenService->sign('moderation-attachment', $list->name, (string) $item['id']);

        $bodyHtml = null;
        if ($mail !== null) {
            try {
                $bodyHtml = $this->sanitizer->render($mail->textHtml, $mail->textPlain, $mail->getAttachments(), $baseUrl, $loadImages, $attachmentToken, $view);
            } catch (\Throwable $e) {
                error_log("Listig: failed to render pending moderation mail {$item['id']} for list {$list->name}: " . $e->getMessage());
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
        if ($item === null) {
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

        $mail = $this->imapPoller->fetchMailByUid($list, (int) $item['imap_uid']);
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
            error_log("Listig: attachment $index unavailable for pending moderation mail {$item['id']} on list {$list->name}: " . $e->getMessage());
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
     * Shared by show()/frame() — fetches the moderation_queue row and its list,
     * checking ownership. Returns [item, list, null] on success, or
     * [null, null, $errorResponse] to short-circuit with (attachment() has its
     * own variant, since it also accepts a token as an alternative to a session
     * — see its own comment).
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

    /** @see frame()'s $attachmentToken comment for why this fallback exists. */
    private function isValidAttachmentToken(string $token, string $listCn, string $moderationId): bool
    {
        if ($token === '') {
            return false;
        }
        try {
            [$tokenListCn, $tokenId] = $this->tokenService->verify($token, 'moderation-attachment', 10 * 60);
        } catch (\InvalidArgumentException) {
            return false;
        }
        return $tokenListCn === $listCn && $tokenId === $moderationId;
    }

    /** @see \Hengeb\Listig\Http\Controller\ArchiveController::indexAttachmentsByPosition() — same reasoning. */
    private static function indexAttachmentsByPosition(array $attachments): array
    {
        return array_values($attachments);
    }

    private static function isEmbeddedInline(IncomingMailAttachment $attachment): bool
    {
        return ($attachment->disposition ?? '') === 'inline' && ($attachment->contentId ?? '') !== '';
    }

    private function fetchItem(int $id): ?array
    {
        $stmt = $this->db->prepare('SELECT * FROM moderation_queue WHERE id = :id');
        $stmt->execute(['id' => $id]);
        $item = $stmt->fetch(PDO::FETCH_ASSOC);
        return $item ?: null;
    }

    private function handle(ServerRequestInterface $request, ResponseInterface $response, int $id, string $action): ResponseInterface
    {
        $user = $request->getAttribute('user');

        $item = $this->fetchItem($id);

        if (!$item) {
            return $this->json($response, ['error' => 'Not found'], 404);
        }

        $list = $this->listProvider->getList($item['list_cn']);
        if ($list === null) {
            return $this->json($response, ['error' => 'List not found'], 404);
        }

        // Check owner
        if (!$list->isOwnedBy($user['email'])) {
            return $this->json($response, ['error' => 'Forbidden'], 403);
        }

        $uid         = (int) $item['imap_uid'];
        $uidValidity = (int) $item['imap_uidvalidity'];

        if ($action === 'accept') {
            $incomingMail = $this->imapPoller->fetchMailByUid($list, $uid);
            $rawMime      = $this->imapPoller->fetchByUid($list, $uid);

            if ($incomingMail === null || $rawMime === null) {
                $this->db->prepare('DELETE FROM moderation_queue WHERE id = :id')->execute(['id' => $id]);
                return $this->json($response, ['error' => 'Original mail not found in IMAP'], 410);
            }

            $this->mailProcessor->process($incomingMail, $rawMime, $list);
            $this->imapPoller->markSeen($list, $uid, $uidValidity);
            $this->imapArchiver->archiveOrDelete($list, $uid);
            $this->archiveIndexer->index($list, $incomingMail);
        } else {
            // Mirrors ModerationResponseHandler::processReject() (the mail-reply
            // path) — a reject via the manage-page button must notify the sender
            // and clear the mail out of the inbox the same way, not just drop the
            // moderation_queue row.
            $incomingMail = $this->imapPoller->fetchMailByUid($list, $uid);
            if ($incomingMail !== null) {
                // Best-effort attachment — see RejectionNotifier::notify()'s own
                // $rawMime docblock.
                $rawMime = $this->imapPoller->fetchByUid($list, $uid);
                $this->rejectionNotifier->notify($list, $incomingMail, $rawMime, 'reject.moderation_declined');
                $this->imapPoller->markSeen($list, $uid, $uidValidity);
                $this->imapArchiver->archiveOrDelete($list, $uid);
            }
        }

        $this->db->prepare('DELETE FROM moderation_queue WHERE id = :id')->execute(['id' => $id]);

        return $this->json($response, ['status' => 'ok']);
    }

    private function json(ResponseInterface $response, array $data, int $status = 200): ResponseInterface
    {
        $response->getBody()->write(json_encode($data));
        return $response->withStatus($status)->withHeader('Content-Type', 'application/json');
    }
}
