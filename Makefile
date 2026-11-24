SHELL := /bin/sh

.PHONY: help test compose-check lab-up lab-down status

help:
	@echo "test          Run Python safety tests"
	@echo "compose-check Validate Compose configuration"
	@echo "lab-up        Start isolated PHP baselines"
	@echo "lab-down      Stop and remove lab"
	@echo "status        Display container status"

test:
	python3 -m unittest discover -s tests -v

compose-check:
	docker compose config -q

lab-up:
	docker compose --profile baseline pull
	docker compose --profile baseline up -d

lab-down:
	docker compose --profile baseline down --remove-orphans

status:
	docker compose ps
