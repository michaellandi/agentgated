BINARY  := agentgated
DIST    := dist
VERSION ?= dev

.PHONY: build test fmt vet clean install

build:
	mkdir -p $(DIST)
	go build -ldflags "-X main.version=$(VERSION)" -o $(DIST)/$(BINARY) ./cmd/agentgated

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -l .

clean:
	rm -rf $(DIST)

install: build
	install -m 0755 $(DIST)/$(BINARY) /usr/local/sbin/$(BINARY)
	mkdir -p /etc/agentgated
	install -m 0644 init/agentgated.service /etc/systemd/system/agentgated.service
