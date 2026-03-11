.PHONY: build test lint docker clean help

# Build configuration
GO ?= go
IMAGE_NAME := ghcr.io/cocakoala-network/cert-manager-technitium-webhook
IMAGE_TAG := latest
CHART_DIR := charts/cert-manager-technitium-webhook

## help: Show this help message
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@sed -n 's/^## //p' $(MAKEFILE_LIST) | column -t -s ':'

## build: Build the webhook binary
build:
	CGO_ENABLED=0 $(GO) build -ldflags='-w -s' -trimpath -o webhook .

## test: Run all tests with race detection
test:
	$(GO) test -v -race -coverprofile=coverage.out ./...

## lint: Run Go linter (requires golangci-lint)
lint:
	golangci-lint run ./...

## docker: Build Docker image
docker:
	docker build --platform=linux/amd64 -t "$(IMAGE_NAME):$(IMAGE_TAG)" .

## docker-push: Build and push Docker image
docker-push: docker
	docker push "$(IMAGE_NAME):$(IMAGE_TAG)"

## helm-template: Render Helm chart templates
helm-template:
	helm template cert-manager-technitium-webhook $(CHART_DIR) \
		--namespace cert-manager \
		--set groupName=acme.example.com

## helm-lint: Lint the Helm chart
helm-lint:
	helm lint $(CHART_DIR)

## clean: Remove build artifacts
clean:
	rm -f webhook coverage.out
	rm -rf _out _test
