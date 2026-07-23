<?php

declare(strict_types=1);

namespace Hengeb\Listig\Crypto;

/**
 * Encrypts/decrypts IMAP/SMTP passwords stored in LDAP description[] values
 * (mail-password, imap-password, smtp-password, legacy password) using
 * AES-256-CBC with a subkey derived from APP_SECRET via KeyDerivation — never
 * APP_SECRET itself (see CLAUDE.md "Key Derivation").
 *
 * Wire format: base64(iv) . ':' . base64(ciphertext).
 *
 * Passwords supplied via config.yml (typically $VAR substitution from .env, or a
 * literal value) are already plaintext from a trusted source and are never
 * encrypted with this class — decryptIfEncrypted() tells the two apart by shape,
 * since ListConfig merges both sources into the same flat key space.
 */
final class PasswordCrypto
{
    private const CIPHER = 'aes-256-cbc';

    public function __construct(
        private readonly string $key,
    ) {
    }

    public function encrypt(string $plaintext): string
    {
        $iv = random_bytes(openssl_cipher_iv_length(self::CIPHER));
        $ciphertext = openssl_encrypt($plaintext, self::CIPHER, $this->key, OPENSSL_RAW_DATA, $iv);
        if ($ciphertext === false) {
            throw new \RuntimeException('Password encryption failed');
        }
        return base64_encode($iv) . ':' . base64_encode($ciphertext);
    }

    public function decrypt(string $encrypted): string
    {
        $parts = explode(':', $encrypted, 2);
        if (count($parts) !== 2) {
            throw new \InvalidArgumentException('Invalid encrypted password format');
        }
        [$ivEncoded, $ciphertextEncoded] = $parts;

        $iv = base64_decode($ivEncoded, true);
        $ciphertext = base64_decode($ciphertextEncoded, true);
        if ($iv === false || $ciphertext === false || strlen($iv) !== openssl_cipher_iv_length(self::CIPHER)) {
            throw new \InvalidArgumentException('Invalid encrypted password format');
        }

        $plaintext = openssl_decrypt($ciphertext, self::CIPHER, $this->key, OPENSSL_RAW_DATA, $iv);
        if ($plaintext === false) {
            throw new \InvalidArgumentException('Password decryption failed');
        }
        return $plaintext;
    }

    /**
     * Returns $value decrypted if it matches the base64(iv):base64(ciphertext)
     * shape, otherwise returns it unchanged (plaintext from config.yml).
     */
    public function decryptIfEncrypted(string $value): string
    {
        if ($value === '' || !self::looksEncrypted($value)) {
            return $value;
        }
        return $this->decrypt($value);
    }

    private static function looksEncrypted(string $value): bool
    {
        $parts = explode(':', $value);
        if (count($parts) !== 2) {
            return false;
        }
        [$ivEncoded, $ciphertextEncoded] = $parts;

        $iv = base64_decode($ivEncoded, true);
        $ciphertext = base64_decode($ciphertextEncoded, true);

        return $iv !== false
            && $ciphertext !== false
            && $ciphertext !== ''
            && strlen($iv) === openssl_cipher_iv_length(self::CIPHER);
    }
}
