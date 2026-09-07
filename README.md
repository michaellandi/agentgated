# agentgated

[![CI](https://github.com/michaellandi/agentgated/actions/workflows/ci.yml/badge.svg)](https://github.com/michaellandi/agentgated/actions/workflows/ci.yml)
[![Go Version](https://img.shields.io/badge/go-1.23%2B-00ADD8?logo=go&logoColor=white)](go.mod)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**agentgated** is an egress control daemon for AI agents. It sits between an
agent's tools and the network, enforcing a single allow/deny hostname policy
across every path an agent can reach the outside world through: DNS lookups
and HTTP CONNECT tunnels alike, so an agent that already knows a destination
IP can't bypass policy by skipping resolution and data can't be exfiltrated
through DNS.

Every query and connection is logged (name, type, client, allow/block
decision, and whether it was served from cache or upstream), which is
deliberate: this is step one toward using agentgated to spot data
exfiltration attempts by misbehaving or compromised agents tunneling data out
through "harmless" DNS lookups or HTTP requests.

## Features

- Transparent DNS proxy — forwards queries to an upstream resolver over UDP
  and TCP
- HTTP CONNECT tunnel proxy — filters by the tunnel's target hostname using
  the same allow/deny list as DNS, then relays bytes opaquely (no TLS
  termination)
- Static allow list or deny list filtering by hostname (suffix-matched, so an
  entry also covers its subdomains), shared by both proxies
- Configurable redirect IP for blocked A queries, or NXDOMAIN
- In-memory response cache honoring upstream TTLs, capped at a configurable
  maximum
- Structured per-query and per-connection logging to stdout or a log file
- Single static binary, no runtime dependencies

### Planned

- Exfiltration heuristics (entropy scoring on query names, per-client
  rate/beaconing anomalies) built on top of the existing query log

## Requirements

- Go 1.23+ to build
- Root (or `CAP_NET_BIND_SERVICE`) to bind port 53

## Building

```bash
make build
# binary at ./dist/agentgated
```

## Releases

Tagged versions (`vX.Y.Z`) are built automatically by
[`.github/workflows/release.yml`](.github/workflows/release.yml) into static
binaries for `linux/amd64`, `linux/arm64`, `darwin/amd64`, and
`darwin/arm64`, published on the
[Releases page](https://github.com/michaellandi/agentgated/releases) as
`agentgated_<version>_<os>_<arch>.tar.gz` alongside a `checksums.txt`.

```bash
curl -LO https://github.com/michaellandi/agentgated/releases/download/vX.Y.Z/agentgated_vX.Y.Z_linux_amd64.tar.gz
curl -LO https://github.com/michaellandi/agentgated/releases/download/vX.Y.Z/checksums.txt
sha256sum -c checksums.txt --ignore-missing
tar xzf agentgated_vX.Y.Z_linux_amd64.tar.gz
```

`agentgated -version` prints the build's version.

## Installing

```bash
sudo make install
```

This installs the binary to `/usr/local/sbin/agentgated` and the systemd unit
to `/etc/systemd/system/agentgated.service`. Then set up config:

```bash
sudo mkdir -p /etc/agentgated
sudo cp configs/agentgated.yaml.example /etc/agentgated/agentgated.yaml
sudo cp configs/allowlist.txt.example /etc/agentgated/allowlist.txt
sudo cp configs/denylist.txt.example /etc/agentgated/denylist.txt
sudo systemctl daemon-reload
sudo systemctl enable --now agentgated
```

## Configuration

Configuration is read from the path given by `-config` (default
`/etc/agentgated/agentgated.yaml`). See
[`configs/agentgated.yaml.example`](configs/agentgated.yaml.example) for all
options:

| Option | Default | Description |
|---|---|---|
| `dns_listen` | `:53` | Address to listen on for DNS (UDP and TCP) |
| `dns_upstream` | `1.1.1.1:53` | Upstream resolver for permitted DNS queries |
| `filter_mode` | `deny` | `none`, `allow`, or `deny` — applied to both DNS and CONNECT |
| `allowlist_file` | `/etc/agentgated/allowlist.txt` | Hostnames to allow, one per line |
| `denylist_file` | `/etc/agentgated/denylist.txt` | Hostnames to block, one per line |
| `dns_blocked_ip` | *(empty)* | IP to answer with for a blocked `A` query; empty means NXDOMAIN |
| `dns_cache` | `true` | Enable in-memory DNS response caching |
| `dns_cache_max_ttl` | `1h` | Upper bound on cached DNS entry lifetime |
| `log_path` | *(empty)* | Log file path; empty logs to stdout |
| `connect_listen` | *(empty)* | Address for the HTTP CONNECT proxy, e.g. `:3128`; empty disables it |

Restart the daemon after changing config or list files — they're read once
at startup.

## Running locally

```bash
go run ./cmd/agentgated -config ./configs/agentgated.yaml
dig @127.0.0.1 -p 5353 example.com   # if dns_listen: ":5353" in your config
```

Binding to port 53 requires root; for local testing without `sudo`, set
`dns_listen: "127.0.0.1:5353"` in your config.

To test the CONNECT proxy, set `connect_listen: "127.0.0.1:3128"` and:

```bash
curl -x http://127.0.0.1:3128 https://example.com
```

An agent process can be sandboxed by setting `HTTPS_PROXY=http://127.0.0.1:3128`
(and `HTTP_PROXY` if it makes plain HTTP requests too — only CONNECT tunnels
are currently supported, so plain-HTTP proxying isn't filtered).

## Origins

agentgated started as a Go port of
[dnsproxyd](https://github.com/michaellandi/dnsproxyd) (Java/gcj) — same
DNS filtering shape, one static binary, no JVM. It's since been repointed at
a narrower problem: giving an AI agent a single, auditable point of control
for what it can reach on the network, rather than being a general-purpose
DNS filter.

## License

MIT License. See [LICENSE](LICENSE) for details.
