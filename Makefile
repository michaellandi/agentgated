BINARY := agentgated
DIST   := dist

.PHONY: build test fmt vet clean install

build:
	mkdir -p $(DIST)
	go build -o $(DIST)/$(BINARY) ./cmd/agentgated

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
