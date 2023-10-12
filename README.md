# listig

PHP mail forwarder and list manager

# setup using Docker and docker-compose

1. configuration: see `config.yml.sample` and `env.sample` and `docker-compose.yml`. Note that `docker-compose.yml` includes an external network to connect to the LDAP service.
2. run `make prod` to start the production server
3. provide mailbox passwords: `make shell` and `php set-password.php user@example.com "secret-password-123"`
4. watch with `make logs`

# stop service

run `docker-compose down`
