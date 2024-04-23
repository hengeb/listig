include .env

config.yml:
	$(error file config.yml is missing, see config.yml.sample)

image:
	@echo "(Re)building docker image"
	docker build --no-cache -t $(ORGNAME)/$(SERVICENAME):latest .

rebuild:
	@echo "Rebuilding docker image"
	docker build -t $(ORGNAME)/$(SERVICENAME):latest .
	make dev

dev: config.yml
	@echo "Starting DEV Server"
	docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --force-recreate --remove-orphans

prod: image config.yml
	@echo "Starting Production Server"
	docker compose up -d --force-recreate --remove-orphans app

upgrade:
	git pull
	make prod

shell:
	docker compose exec app sh

rootshell:
	docker compose exec --user root app sh

logs:
	docker compose logs -f
