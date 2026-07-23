#!/usr/bin/env php
<?php

declare(strict_types=1);

use Hengeb\Listig\Crypto\PasswordCrypto;

require_once __DIR__ . '/../vendor/autoload.php';

// Load .env
$envFile = __DIR__ . '/../.env';
if (file_exists($envFile)) {
    foreach (file($envFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        if (str_starts_with($line, '#') || !str_contains($line, '=')) {
            continue;
        }
        [$key, $value] = explode('=', $line, 2);
        $_ENV[trim($key)] = trim($value);
        putenv(trim($key) . '=' . trim($value));
    }
}

$container = require __DIR__ . '/../config/container.php';
$passwordCrypto = $container->get(PasswordCrypto::class);

$options = getopt('h', ['decrypt:', 'stdin', 'help']);

if (isset($options['h']) || isset($options['help'])) {
    fwrite(STDOUT, <<<TXT
    Usage:
      bin/encrypt-password.php                Prompt for a password (hidden input), print its encrypted form
      bin/encrypt-password.php --stdin        Read the password from stdin (e.g. piped), print its encrypted form
      bin/encrypt-password.php --decrypt=VAL  Decrypt an existing base64(iv):base64(ciphertext) value

    The password itself is never accepted as a plain command-line argument, since
    that would leak it into the shell history and process list.

    Output of the default/--stdin modes is ready to use as a mail-password,
    imap-password, or smtp-password value: as an LDAP description[] entry
    ("mail-password:<output>") or directly in config.yml.

    TXT);
    exit(0);
}

if (isset($options['decrypt'])) {
    $value = (string) $options['decrypt'];
    try {
        fwrite(STDOUT, $passwordCrypto->decrypt($value) . "\n");
    } catch (\InvalidArgumentException $e) {
        fwrite(STDERR, "Error: {$e->getMessage()}\n");
        exit(1);
    }
    exit(0);
}

if (isset($options['stdin'])) {
    $password = trim((string) stream_get_contents(STDIN));
} else {
    $password = readHiddenPassword('Password to encrypt: ');
}

if ($password === '') {
    fwrite(STDERR, "Error: empty password\n");
    exit(1);
}

fwrite(STDOUT, $passwordCrypto->encrypt($password) . "\n");

function readHiddenPassword(string $prompt): string
{
    fwrite(STDOUT, $prompt);

    if (stripos(PHP_OS, 'WIN') === 0) {
        // No stty on Windows; input falls back to visible.
        return trim((string) fgets(STDIN));
    }

    $sttyOriginal = shell_exec('stty -g');
    shell_exec('stty -echo');
    $password = trim((string) fgets(STDIN));
    shell_exec('stty ' . trim((string) $sttyOriginal));
    fwrite(STDOUT, "\n");

    return $password;
}
