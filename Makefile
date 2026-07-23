COMPOSE = docker compose -f docker/compose.yaml

.DEFAULT_GOAL := help

.PHONY: help dev stop down build rebuild logs logs-app shell db ps fresh

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

dev: ## Start all containers (app, db)
	$(COMPOSE) up -d

stop: ## Stop containers, keep data
	$(COMPOSE) stop

down: ## Stop and remove containers, keep volumes
	$(COMPOSE) down

build: ## Build Docker images
	$(COMPOSE) build

rebuild: ## Rebuild images without cache
	$(COMPOSE) build --no-cache

logs: ## Tail logs from all containers
	$(COMPOSE) logs -f

logs-app: ## Tail logs from the app container only
	$(COMPOSE) logs -f app

shell: ## Open a shell inside the app container
	$(COMPOSE) exec app sh

db: ## Open MariaDB prompt as configured user
	$(COMPOSE) exec db sh -c 'mariadb -u$$MARIADB_USER -p$$MARIADB_PASSWORD $$MARIADB_DATABASE'

ps: ## Show container status
	$(COMPOSE) ps

fresh: ## Destroy everything including DB volume and restart clean
	$(COMPOSE) down -v
	$(COMPOSE) up -d
