<?php
declare(strict_types=1);

namespace Hengeb\Listig;

include 'vendor/autoload.php';

$app = new App('config.yml');

if ($argc !== 3) {
    echo <<<EOT
    usage: php set-password.php mail password
    example: php set-password.php user@example.com my-very-secret-password\n
    EOT;
    exit(1);
}
$app->setPassword(strtolower($argv[1]), $argv[2]);
