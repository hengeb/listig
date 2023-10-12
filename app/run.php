<?php
declare(strict_types=1);

namespace Hengeb\Listig;

include 'vendor/autoload.php';

$app = new App('config.yml');
$app->run();
