<?php

declare(strict_types=1);

use DI\ContainerBuilder;
use Hengeb\Listig\Archive\ArchiveHtmlSanitizer;
use Hengeb\Listig\Archive\ArchiveIndexer;
use Hengeb\Listig\Archive\ArchiveMailLocator;
use Hengeb\Listig\Archive\ArchiveThreader;
use Hengeb\Listig\Config\ConfigResolver;
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
use Hengeb\Listig\Provider\ListProvider;
use Hengeb\Listig\Queue\QueueSender;
use Hengeb\Listig\Queue\QueueWriter;
use Hengeb\Listig\Queue\SpamRejectionDetector;
use Hengeb\Listig\RateLimit\RateLimiter;
use Hengeb\Listig\Smtp\SmtpConnectionFactory;
use Hengeb\Listig\Token\TokenService;
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

    // Configuration
    ConfigResolver::class => function (): ConfigResolver {
        $configPath = $_ENV['CONFIG_PATH'] ?? getenv('CONFIG_PATH') ?: __DIR__ . '/config.yml';
        return new ConfigResolver($configPath);
    },

    // App secret
    'app.secret' => function (): string {
        $secret = $_ENV['APP_SECRET'] ?? getenv('APP_SECRET');
        if (!$secret) {
            throw new \RuntimeException('APP_SECRET environment variable is required');
        }
        return $secret;
    },

    'app.host' => function (): string {
        return $_ENV['APP_HOST'] ?? getenv('APP_HOST') ?: gethostname() ?: 'localhost';
    },

    'mailer.dsn' => function (): string {
        return $_ENV['MAILER_DSN'] ?? getenv('MAILER_DSN') ?: 'smtp://localhost:25';
    },

    // Global default locale — just another config key, read via getResolvedDefault()
    // like db-*; individual lists may override it via ListConfig::$language.
    'app.language' => function (ContainerInterface $c): string {
        return $c->get(ConfigResolver::class)->getResolvedDefault()['language'] ?? 'en';
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
            $c->get('app.host'),
        );
    },

    // Notifications — shared "build Email, send via list's SMTP, log on failure" helper
    NotificationMailer::class => function (ContainerInterface $c): NotificationMailer {
        return new NotificationMailer($c->get(SmtpConnectionFactory::class));
    },
    BounceHandler::class => function (ContainerInterface $c): BounceHandler {
        return new BounceHandler($c->get(PDO::class), $c->get(NotificationMailer::class), $c->get(TranslatorInterface::class));
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
        );
    },

    // HTTP Controllers
    AuthController::class => function (ContainerInterface $c): AuthController {
        $listProvider = $c->get(ListProvider::class);
        $lists = $listProvider->getLists();
        $firstList = $lists[0] ?? null;

        return new AuthController(
            $c->get(Engine::class),
            $c->get(TokenService::class),
            $c->get(RateLimiter::class),
            new AggregateMemberResolver($listProvider),
            $c->get(TranslatorInterface::class),
            $c->get('app.host'),
            $c->get('mailer.dsn'),
            $firstList?->mail ?? 'noreply@localhost',
            $firstList?->name ?? 'listig',
        );
    },

    DashboardController::class => function (ContainerInterface $c): DashboardController {
        return new DashboardController(
            $c->get(Engine::class),
            $c->get(ListProvider::class),
            $c->get(TranslatorInterface::class),
            $c->get(TokenService::class),
            $c->get('app.host'),
        );
    },

    ListController::class => function (ContainerInterface $c): ListController {
        return new ListController($c->get(Engine::class), $c->get(ListProvider::class), $c->get(PDO::class), $c->get(TranslatorInterface::class));
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
            $c->get('app.host'),
        );
    },

    // Guards PUT/DELETE/{listname}/{mail} and encrypt-password — see ApiTokenMiddleware.
    ApiTokenMiddleware::class => function (ContainerInterface $c): ApiTokenMiddleware {
        return new ApiTokenMiddleware($c->get(ListProvider::class), $c->get(RateLimiter::class));
    },
]);

return $builder->build();
