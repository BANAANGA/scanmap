.PHONY: help test run build up down logs clean

PORT ?= 8420

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-8s\033[0m %s\n", $$1, $$2}'

test: ## Run the unit tests
	python3 -m unittest discover -s tests -t . -v

run: ## Run locally without Docker (needs nmap/zmap installed)
	mkdir -p data
	SCANMAP_DATA_DIR=$(CURDIR)/data SCANMAP_PORT=$(PORT) python3 -m app.main

build: ## Build the container image
	docker build -t scanmap:latest .

up: ## Start with docker compose
	docker compose up --build -d

down: ## Stop docker compose
	docker compose down

logs: ## Follow container logs
	docker compose logs -f

clean: ## Remove Python caches
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
