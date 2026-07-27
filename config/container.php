<?php

declare(strict_types=1);

use DI\ContainerBuilder;
use Hengeb\Listig\Archive\ArchiveHtmlSanitizer;
use Hengeb\Listig\Archive\ArchiveIndexer;
use Hengeb\Listig\Archive\ArchiveMailLocator;
use Hengeb\Listig\Archive\ArchiveThreader;
use Hengeb\Listig\Config\ConfigResolver;
use Hengeb\Listig\Config\ListConfig;
use Hengeb\Listig\Crypto\KeyDerivation;
use Hengeb\Listig\Crypto\PasswordCrypto;
use Hengeb\Listig\Http\Controller\ArchiveController;
use Hengeb\Listig\Http\Controller\AuthController;
use Hengeb\Listig\Http\Controller\DashboardController;
use Hengeb\Listig\Http\Controller\ListApiController;
use Hengeb\Listig\Http\Controller\ListController;
use Hengeb\Listig\Http\Controller\ModerationController;
use Hengeb\Listig\Http\Controller\QueueController;
use Hengeb\Listig\Http\Controller\UnsubscribeController;
use Hengeb\Listig\Http\Middleware\ApiTokenMiddleware;
use Hengeb\Listig\Imap\ImapArchiver;
use Hengeb\Listig\Imap\ImapMailboxFactory;
use Hengeb\Listig\Imap\ImapPoller;
use Hengeb\Listig\Mail\BodyPersonalizer;
use Hengeb\Listig\Mail\BounceHandler;
use Hengeb\Listig\Mail\FooterAppender;
use Hengeb\Listig\Mail\HeaderFilter;
use Hengeb\Listig\Mail\IncomingMailFilter;
use Hengeb\Listig\Mail\MailProcessor;
use Hengeb\Listig\Mail\NotificationMailer;
use Hengeb\Listig\Mail\RejectionNotifier;
use Hengeb\Listig\Mail\SpamFilter;
use Hengeb\Listig\Database\DatabaseConnectionFactory;
use Hengeb\Listig\Database\MigrationRunner;
use Hengeb\Listig\Member\AggregateMemberResolver;
use Hengeb\Listig\Moderation\ModerationChecker;
use Hengeb\Listig\Moderation\ModerationMailer;
use Hengeb\Listig\Moderation\ModerationResponseHandler;
use Hengeb\Listig\OpenIdConnect\OpenIdConnectService;
use Hengeb\Listig\Provider\ListProvider;
use Hengeb\Listig\Queue\QueueSender;
use Hengeb\Listig\Queue\QueueWriter;
use Hengeb\Listig\Queue\SpamRejectionDetector;
use Hengeb\Listig\RateLimit\RateLimiter;
use Hengeb\Listig\Smtp\SmtpConnectionFactory;
use Hengeb\Listig\Token\TokenService;
use Hengeb\Listig\Variable\ResolutionPurpose;
use Hengeb\Listig\Variable\VariableResolver;
use Latte\Engine;
use Psr\Container\ContainerInterface;
use Symfony\Component\Translation\Loader\YamlFileLoader;
use Symfony\Component\Translation\Translator;
use Symfony\Contracts\Translation\TranslatorInterface;

$builder = new ContainerBuilder();

$builder->addDefinitions([
    // Connection factory — shared singleton; caches PDO instances by db-* fingerprint
    DatabaseConnectionFactory::class => fn() => new DatabaseConnectionFactory(),

    // Global PDO — resolved from the 'database' block in config.yml via the factory
    PDO::class => function (ContainerInterface $c): PDO {
        $cfg = $c->get(ConfigResolver::class)->getResolvedDefault();
        return $c->get(DatabaseConnectionFactory::class)->getConnection($cfg);
    },

    // Applies pending migrations/*.sql on startup — see bin/migrate.php, run via
    // docker/entrypoint.sh before supervisord starts nginx/php-fpm/worker.
    MigrationRunner::class => function (ContainerInterface $c): MigrationRunner {
        return new MigrationRunner($c->get(PDO::class));
    },

    // Path to config.yml — also used by bin/worker.php to watch the file for
    // on-disk changes (see "Worker loop — config reload" in CLAUDE.md).
    'config.path' => function (): string {
        return $_ENV['CONFIG_PATH'] ?? getenv('CONFIG_PATH') ?: __DIR__ . '/config.yml';
    },

    // Configuration
    ConfigResolver::class => function (ContainerInterface $c): ConfigResolver {
        return new ConfigResolver($c->get('config.path'));
    },

    // App secret
    'app.secret' => function (): string {
        $secret = $_ENV['APP_SECRET'] ?? getenv('APP_SECRET');
        if (!$secret) {
            throw new \RuntimeException('APP_SECRET environment variable is required');
        }
        return $secret;
    },

    // Root-level config values are lazily {}-resolved, same as any per-list value
    // (see VariableResolver) — the merged default array is used as its own lookup
    // context, exactly like a provider's list-mail bootstrap resolution. Every
    // getResolvedDefault()-backed entry below goes through this so a root key like
    // 'hostname: "lists.{domain}"' referencing a sibling key ('domain') actually
    // resolves instead of leaking the literal template into every generated URL.
    // db-* (PDO::class, below) is the deliberate exception — those are
    // VariableResolver::BLOCKED_KEYS, meant to stay pure $VAR-substituted literals,
    // never {}-templated.
    'app.hostname.resolved' => function (ContainerInterface $c): string {
        $cfg = $c->get(ConfigResolver::class)->getResolvedDefault();
        if (!array_key_exists('hostname', $cfg) || $cfg['hostname'] === null) {
            return '';
        }
        return VariableResolver::resolve((string) $cfg['hostname'], [$cfg]);
    },

    // Hostname the app uses to build its own links (login, dashboard, manage page,
    // API) — the same 'hostname' key ListConfig::createContext() reads for
    // {hostname}/{list-url}, so both stay in sync instead of being two disconnected
    // settings. No env var of its own: set `hostname: $APP_HOST` in config.yml if
    // the value should come from the environment. Falls back to gethostname() only
    // once the resolved value (above) is empty — see bin/worker.php's startup
    // warning for the same check, pre-fallback.
    'app.hostname' => function (ContainerInterface $c): string {
        $resolved = $c->get('app.hostname.resolved');
        return $resolved !== '' ? $resolved : (gethostname() ?: 'localhost');
    },

    // Global default locale — just another config key; individual lists may
    // override it via ListConfig::$language.
    'app.language' => function (ContainerInterface $c): string {
        $cfg = $c->get(ConfigResolver::class)->getResolvedDefault();
        $raw = $cfg['language'] ?? null;
        return $raw !== null ? VariableResolver::resolve((string) $raw, [$cfg]) : 'en';
    },

    // QueueSender batch size (bin/worker.php's sendBatch() call) — config.yml's
    // 'batch-size' root key, like any other setting here.
    'worker.batch-size' => function (ContainerInterface $c): int {
        $cfg = $c->get(ConfigResolver::class)->getResolvedDefault();
        $raw = $cfg['batch-size'] ?? null;
        return $raw !== null ? (int) VariableResolver::resolve((string) $raw, [$cfg]) : 50;
    },

    // Worker cycle sleep in seconds — config.yml's 'sleep-seconds' root key.
    'worker.sleep-seconds' => function (ContainerInterface $c): int {
        $cfg = $c->get(ConfigResolver::class)->getResolvedDefault();
        $raw = $cfg['sleep-seconds'] ?? null;
        return $raw !== null ? (int) VariableResolver::resolve((string) $raw, [$cfg]) : 60;
    },

    // Display name for the app itself — config.yml's 'app-name' root key, default
    // 'Listig'. Passed as 'appName' to every rendered template (page titles, header)
    // and as '%app_name%' to every translated string that names the app (login mail
    // subject, queue failure notice, ...) — see CLAUDE.md "app-name".
    'app.name' => function (ContainerInterface $c): string {
        $cfg = $c->get(ConfigResolver::class)->getResolvedDefault();
        $raw = $cfg['app-name'] ?? null;
        return $raw !== null ? VariableResolver::resolve((string) $raw, [$cfg]) : 'Listig';
    },

    // Synthetic ListConfig built purely from the config.yml root defaults (levels
    // 1-2 of the priority chain, via getResolvedDefault() — no list-provider/list
    // override involved). Used only to give AuthController a list-agnostic SMTP
    // identity for login mail (see "Authentication (Magic Link)") — name/mail are
    // never displayed or routed, just carriers for ListConfig's existing
    // smtp-*/mail-* fallback and Trusted-resolution logic, so smtpHost/smtpUser/
    // smtpPassword/smtpPort/smtpSecure resolve exactly as they would for any list
    // that set no smtp-* overrides of its own.
    'app.default-smtp-config' => function (ContainerInterface $c): ListConfig {
        $cfg = $c->get(ConfigResolver::class)->getResolvedDefault();
        return new ListConfig('_default-smtp', '', $cfg);
    },

    // Translator — resolves keys from translations/messages.{locale}.yaml, falling
    // back to English for anything missing in the current locale.
    TranslatorInterface::class => function (ContainerInterface $c): TranslatorInterface {
        $translator = new Translator($c->get('app.language'));
        $translator->addLoader('yaml', new YamlFileLoader());
        $translator->addResource('yaml', __DIR__ . '/../translations/messages.de.yaml', 'de');
        $translator->addResource('yaml', __DIR__ . '/../translations/messages.en.yaml', 'en');
        $translator->setFallbackLocales(['en']);
        return $translator;
    },

    // Latte templating
    Engine::class => function (): Engine {
        $latte = new Engine();
        $latte->setTempDirectory(sys_get_temp_dir() . '/latte');
        // Latte does not expose arbitrary PHP functions as filters by default
        // (unlike e.g. Twig) — used for URL query parameters, e.g. dashboard.latte's
        // unsubscribe link.
        $latte->addFilter('rawurlencode', rawurlencode(...));
        // archive/show.latte's per-attachment sizes — same formatting rule
        // ArchiveController uses for the collapsed-summary "%size%" param, see
        // Archive\ByteFormatter's docblock.
        $latte->addFilter('formatBytes', \Hengeb\Listig\Archive\ByteFormatter::format(...));
        return $latte;
    },

    // Token service — HMAC key is a subkey derived from APP_SECRET (KeyDerivation),
    // never the raw secret, so it stays independent from other uses of APP_SECRET
    // (e.g. IMAP/SMTP password encryption).
    TokenService::class => function (ContainerInterface $c): TokenService {
        $hmacKey = KeyDerivation::derive($c->get('app.secret'), 'listig-token-hmac');
        return new TokenService($hmacKey);
    },

    // Password crypto — independent subkey from APP_SECRET (KeyDerivation), used to
    // decrypt LDAP-stored IMAP/SMTP passwords in ImapMailboxFactory/SmtpConnectionFactory,
    // and by bin/encrypt-password.php to encrypt new ones.
    PasswordCrypto::class => function (ContainerInterface $c): PasswordCrypto {
        $key = KeyDerivation::derive($c->get('app.secret'), 'listig-password-encryption');
        return new PasswordCrypto($key);
    },

    // Rate limiter
    RateLimiter::class => function (ContainerInterface $c): RateLimiter {
        return new RateLimiter($c->get(PDO::class));
    },

    // Queue
    QueueWriter::class => function (ContainerInterface $c): QueueWriter {
        return new QueueWriter($c->get(PDO::class));
    },

    // SMTP
    SmtpConnectionFactory::class => function (ContainerInterface $c): SmtpConnectionFactory {
        return new SmtpConnectionFactory($c->get(PasswordCrypto::class));
    },

    // List provider (build from config)
    ListProvider::class => function (ContainerInterface $c): ListProvider {
        $configResolver = $c->get(ConfigResolver::class);
        $providerConfigs = $configResolver->getListProviderConfigs();
        $dbFactory = $c->get(DatabaseConnectionFactory::class);

        $providers = [];
        foreach ($providerConfigs as $name => $config) {
            // 'type' goes through the normal priority chain (root use:/direct, then this
            // provider's own use:/direct — see ConfigResolver::resolveListConfig()) before
            // falling back to the provider's own name — see CLAUDE.md "list-providers".
            $type = $configResolver->resolveListConfig($config)['type'] ?? '';
            $type = $type !== '' ? $type : $name;
            $provider = match ($type) {
                'ldap' => new \Hengeb\Listig\Provider\LdapListProvider($name, $configResolver, $config),
                'inline' => new \Hengeb\Listig\Provider\InlineListProvider($name, $configResolver, $config, $dbFactory),
                'database' => new \Hengeb\Listig\Provider\DatabaseListProvider($name, $configResolver, $config, $dbFactory),
                'yaml' => new \Hengeb\Listig\Provider\YamlListProvider($name, $configResolver, $config, $dbFactory),
                'subaddress' => new \Hengeb\Listig\Provider\SubaddressListProvider($name, $configResolver, $config),
                default => throw new \RuntimeException("Unknown list provider type \"$type\" for provider \"$name\""),
            };
            $providers[] = $provider;
        }

        // Composite provider that searches all
        return new class($providers) implements ListProvider {
            public function __construct(private readonly array $providers) {}

            public function getLists(): array {
                return array_merge(...array_map(fn($p) => $p->getLists(), $this->providers));
            }

            public function getList(string $name): ?\Hengeb\Listig\Config\ListConfig {
                foreach ($this->providers as $p) {
                    $list = $p->getList($name);
                    if ($list !== null) return $list;
                }
                return null;
            }

            public function setListConfigValue(string $listName, string $key, string $value): void {
                foreach ($this->providers as $p) {
                    if ($p->getList($listName) !== null) {
                        $p->setListConfigValue($listName, $key, $value);
                        return;
                    }
                }
                throw new \RuntimeException("List '$listName' not found");
            }
        };
    },

    // Mail processing
    HeaderFilter::class => fn() => new HeaderFilter(),
    BodyPersonalizer::class => fn() => new BodyPersonalizer(),
    FooterAppender::class => fn() => new FooterAppender(),

    // Global, list-independent spam filter — rules from the top-level filters: section
    SpamFilter::class => function (ContainerInterface $c): SpamFilter {
        return new SpamFilter($c->get(ConfigResolver::class)->getFilters());
    },

    IncomingMailFilter::class => function (ContainerInterface $c): IncomingMailFilter {
        return new IncomingMailFilter($c->get(RateLimiter::class), $c->get(HeaderFilter::class), $c->get(SpamFilter::class));
    },

    MailProcessor::class => function (ContainerInterface $c): MailProcessor {
        return new MailProcessor(
            $c->get(HeaderFilter::class),
            $c->get(BodyPersonalizer::class),
            $c->get(FooterAppender::class),
            $c->get(QueueWriter::class),
            $c->get(TokenService::class),
            $c->get('app.hostname'),
        );
    },

    // Notifications — shared "build Email, send via list's SMTP, log on failure" helper
    NotificationMailer::class => function (ContainerInterface $c): NotificationMailer {
        return new NotificationMailer($c->get(SmtpConnectionFactory::class));
    },
    BounceHandler::class => function (ContainerInterface $c): BounceHandler {
        return new BounceHandler(
            $c->get(PDO::class),
            $c->get(NotificationMailer::class),
            $c->get(TranslatorInterface::class),
            $c->get(HeaderFilter::class),
        );
    },
    RejectionNotifier::class => function (ContainerInterface $c): RejectionNotifier {
        return new RejectionNotifier($c->get(NotificationMailer::class), $c->get(TranslatorInterface::class));
    },

    // IMAP — ImapMailboxFactory caches Mailbox connections per list for one worker
    // cycle (see bin/worker.php, which calls reset() before each sleep)
    ImapMailboxFactory::class => function (ContainerInterface $c): ImapMailboxFactory {
        return new ImapMailboxFactory($c->get(PasswordCrypto::class));
    },
    ImapPoller::class => function (ContainerInterface $c): ImapPoller {
        return new ImapPoller($c->get(PDO::class), $c->get(ImapMailboxFactory::class));
    },
    ImapArchiver::class => function (ContainerInterface $c): ImapArchiver {
        return new ImapArchiver($c->get(ImapMailboxFactory::class));
    },

    // Archive viewer — see CLAUDE.md "Archive access levels". ArchiveIndexer is
    // called alongside (not from within) ImapArchiver::archiveOrDelete(), only at
    // the 3 call sites that represent a successful distribute (bin/worker.php,
    // ModerationController::accept, ModerationResponseHandler) — bounce/reject
    // outcomes also call archiveOrDelete() but must never be indexed.
    ArchiveIndexer::class => function (ContainerInterface $c): ArchiveIndexer {
        return new ArchiveIndexer($c->get(PDO::class), $c->get(HeaderFilter::class));
    },
    ArchiveThreader::class => fn() => new ArchiveThreader(),
    ArchiveMailLocator::class => function (ContainerInterface $c): ArchiveMailLocator {
        return new ArchiveMailLocator($c->get(ImapMailboxFactory::class));
    },
    ArchiveHtmlSanitizer::class => fn() => new ArchiveHtmlSanitizer(),

    // Moderation
    ModerationMailer::class => function (ContainerInterface $c): ModerationMailer {
        return new ModerationMailer(
            $c->get(PDO::class),
            $c->get(SmtpConnectionFactory::class),
            $c->get(TokenService::class),
            $c->get(TranslatorInterface::class),
        );
    },

    ModerationChecker::class => function (ContainerInterface $c): ModerationChecker {
        return new ModerationChecker(
            $c->get(PDO::class),
            $c->get(ListProvider::class),
            $c->get(ModerationMailer::class),
            $c->get(ImapPoller::class),
        );
    },

    ModerationResponseHandler::class => function (ContainerInterface $c): ModerationResponseHandler {
        return new ModerationResponseHandler(
            $c->get(PDO::class),
            $c->get(TokenService::class),
            $c->get(MailProcessor::class),
            $c->get(ImapPoller::class),
            $c->get(ImapArchiver::class),
            $c->get(RejectionNotifier::class),
            $c->get(ArchiveIndexer::class),
        );
    },

    // Detects a trusted large provider's SMTP-level "rejected as spam" response —
    // see SpamRejectionDetector for why the trust list is hardcoded, not config.yml.
    SpamRejectionDetector::class => fn() => new SpamRejectionDetector(),

    QueueSender::class => function (ContainerInterface $c): QueueSender {
        return new QueueSender(
            $c->get(PDO::class),
            $c->get(SmtpConnectionFactory::class),
            $c->get(ListProvider::class),
            $c->get(NotificationMailer::class),
            $c->get(TranslatorInterface::class),
            $c->get(SpamRejectionDetector::class),
            $c->get('app.name'),
        );
    },

    // OIDC login (see "Authentication (OIDC)" in CLAUDE.md) is entirely optional —
    // enabled only if all three keys are configured. Root-level config.yml keys
    // (like hostname/language/db-*, see the block above), not per-list: the login
    // flow itself has no list in scope until after a member is found (same reason
    // AggregateMemberResolver exists for the magic-link flow).
    'oidc.enabled' => function (ContainerInterface $c): bool {
        $cfg = $c->get(ConfigResolver::class)->getResolvedDefault();
        return !empty($cfg['oidc-provider-url']) && !empty($cfg['oidc-client-id']) && !empty($cfg['oidc-client-secret']);
    },

    // Null when OIDC isn't configured — public/index.php only registers the
    // GET /_/login/oidc route (and login.latte only shows the button) when
    // 'oidc.enabled' is true, so this is never actually called in that case.
    OpenIdConnectService::class => function (ContainerInterface $c): ?OpenIdConnectService {
        if (!$c->get('oidc.enabled')) {
            return null;
        }
        $cfg = $c->get(ConfigResolver::class)->getResolvedDefault();

        // Only needed when the IdP is reached over a different address than its
        // own public identity — e.g. an internal Docker Compose service name/URL
        // — and derives its issuer strictly from the request's Host header (see
        // OpenIdConnectService's docblock for why). Absent otherwise.
        $publicProviderUrl = $cfg['oidc-public-provider-url'] ?? null;
        $publicProviderHost = $publicProviderUrl
            ? parse_url(VariableResolver::resolve((string) $publicProviderUrl, [$cfg], ResolutionPurpose::Trusted), PHP_URL_HOST)
            : null;

        // Only needed for providers without a standard, spec-compliant
        // end_session_endpoint (discovered automatically otherwise) — see
        // OpenIdConnectService::getLogoutUrl().
        $logoutUrlOverride = isset($cfg['oidc-logout-url'])
            ? VariableResolver::resolve((string) $cfg['oidc-logout-url'], [$cfg], ResolutionPurpose::Trusted)
            : null;

        return new OpenIdConnectService(
            VariableResolver::resolve((string) $cfg['oidc-provider-url'], [$cfg], ResolutionPurpose::Trusted),
            VariableResolver::resolve((string) $cfg['oidc-client-id'], [$cfg], ResolutionPurpose::Trusted),
            VariableResolver::resolve((string) $cfg['oidc-client-secret'], [$cfg], ResolutionPurpose::Trusted),
            'https://' . $c->get('app.hostname') . '/_/login/oidc',
            $publicProviderHost,
            $logoutUrlOverride,
        );
    },

    // HTTP Controllers
    AuthController::class => function (ContainerInterface $c): AuthController {
        return new AuthController(
            $c->get(Engine::class),
            $c->get(TokenService::class),
            $c->get(RateLimiter::class),
            new AggregateMemberResolver($c->get(ListProvider::class)),
            $c->get(TranslatorInterface::class),
            $c->get('app.hostname'),
            $c->get(SmtpConnectionFactory::class),
            $c->get('app.name'),
            $c->get('app.default-smtp-config'),
            $c->get('oidc.enabled'),
            $c->get(OpenIdConnectService::class),
        );
    },

    DashboardController::class => function (ContainerInterface $c): DashboardController {
        return new DashboardController(
            $c->get(Engine::class),
            $c->get(ListProvider::class),
            $c->get(TranslatorInterface::class),
            $c->get(TokenService::class),
            $c->get('app.hostname'),
            $c->get('app.name'),
        );
    },

    ListController::class => function (ContainerInterface $c): ListController {
        return new ListController(
            $c->get(Engine::class),
            $c->get(ListProvider::class),
            $c->get(PDO::class),
            $c->get(TranslatorInterface::class),
            $c->get('app.name'),
        );
    },

    ArchiveController::class => function (ContainerInterface $c): ArchiveController {
        return new ArchiveController(
            $c->get(Engine::class),
            $c->get(PDO::class),
            $c->get(ListProvider::class),
            $c->get(ArchiveThreader::class),
            $c->get(ArchiveMailLocator::class),
            $c->get(ArchiveHtmlSanitizer::class),
            $c->get(TranslatorInterface::class),
            $c->get('app.name'),
            $c->get(TokenService::class),
        );
    },

    ModerationController::class => function (ContainerInterface $c): ModerationController {
        return new ModerationController(
            $c->get(PDO::class),
            $c->get(ListProvider::class),
            $c->get(MailProcessor::class),
            $c->get(ImapPoller::class),
            $c->get(ImapArchiver::class),
            $c->get(ArchiveIndexer::class),
        );
    },

    QueueController::class => function (ContainerInterface $c): QueueController {
        return new QueueController($c->get(PDO::class), $c->get(ListProvider::class));
    },

    UnsubscribeController::class => function (ContainerInterface $c): UnsubscribeController {
        return new UnsubscribeController(
            $c->get(Engine::class),
            $c->get(TokenService::class),
            $c->get(ListProvider::class),
            $c->get(NotificationMailer::class),
            $c->get(TranslatorInterface::class),
            $c->get('app.name'),
        );
    },

    ListApiController::class => function (ContainerInterface $c): ListApiController {
        return new ListApiController(
            $c->get(Engine::class),
            $c->get(TokenService::class),
            $c->get(ListProvider::class),
            $c->get(NotificationMailer::class),
            $c->get(RateLimiter::class),
            $c->get(PasswordCrypto::class),
            $c->get(TranslatorInterface::class),
            $c->get('app.hostname'),
            $c->get('app.name'),
        );
    },

    // Guards PUT/DELETE/{listname}/{mail} and encrypt-password — see ApiTokenMiddleware.
    ApiTokenMiddleware::class => function (ContainerInterface $c): ApiTokenMiddleware {
        return new ApiTokenMiddleware($c->get(ListProvider::class), $c->get(RateLimiter::class));
    },
]);

return $builder->build();
