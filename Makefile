.PHONY: all build clean test install

BINARY_NAME=lory

all: build

build:
	@echo "==> Building standalone lory CLI binary..."
	CGO_ENABLED=0 go build -ldflags="-s -w" -o $(BINARY_NAME) apps/cli/main.go
	@echo "==> Binary built: ./$(BINARY_NAME)"

install: build
	@echo "==> Installing lory to /usr/local/bin..."
	sudo cp $(BINARY_NAME) /usr/local/bin/$(BINARY_NAME)

test:
	@echo "==> Running test suite..."
	go test -v ./...

clean:
	@rm -f $(BINARY_NAME)
