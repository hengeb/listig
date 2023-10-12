SERVICENAME=$(shell grep SERVICENAME .env | sed -e 's/^.\+=//' -e 's/^"//' -e 's/"$$//')

.env:
	$(error file .env is missing, see .env.sample)

image:
	@echo "(Re)building docker image"
	docker build --no-cache -t hengeb/$(SERVICENAME):latest .

rebuild:
	@echo "Rebuilding docker image"
	docker build -t hengeb/$(SERVICENAME):latest .
	make dev

dev: .env
	@echo "Starting DEV Server"
	docker-compose up -d --force-recreate --remove-orphans

prod: image .env
	@echo "Starting Production Server"
	docker-compose up -d --force-recreate --remove-orphans $(SERVICENAME)

upgrade:
	git pull
	make prod

shell:
	docker-compose exec $(SERVICENAME) sh

rootshell:
	docker-compose exec --user root $(SERVICENAME) sh

logs:
	docker-compose logs -f
