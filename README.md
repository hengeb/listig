# listig

PHP mail forwarder and list manager

# setup using Docker and docker-compose

1. configuration: see `config.yml.sample` and `env.sample`.
2. run `make image && make dev` to start the server
3. provide mailbox passwords: `make shell` and `php add-password.php user@example.com "secret-password-123"`
4. watch with `make logs`
