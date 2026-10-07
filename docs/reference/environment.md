# Environment variables

`.env` contents.

## Environment Variables (.env)

Only secrets that must not appear in files committed to version control:

```
# database connection, referenced via 'db-*' keys in config.yml
DB_HOST=db
DB_PORT=3306
DB_NAME=database
DB_USER=user
DB_PASS=secret

# mail server, referenced in config.yml
IMAP_HOST=imap.example.org
SMTP_HOST=smtp.example.org
MAIL_PASSWORD=secret

# 32 random bytes, base64-encoded. Root secret — never used directly as a key;
# per-purpose subkeys (AES-256-CBC, HMAC-SHA256) are derived from it via HKDF,
# see Key Derivation.
APP_SECRET=base64encodedkey32bytes
```

All other configuration lives in `config.yml`. The `db-*` and mail keys are read via `$VAR` substitution in named config blocks and flow into the application through `ConfigResolver`.

---
