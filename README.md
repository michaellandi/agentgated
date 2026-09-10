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
- Optional multi-tenant mode: resolve each request's allow/deny list from a
  URL template (e.g. keyed by client IP), fetched and refreshed in the
  background with fail-safe fallback to the last-known-good list
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
| `connect_allowed_ports` | `["443"]` | Ports a CONNECT target may use; empty means unrestricted |
| `connect_denylist_file` | `/etc/agentgated/connect-denylist.txt` | Hostnames a CONNECT target is always blocked against, regardless of `filter_mode` or any allow list — see [Security model and known limitations](#security-model-and-known-limitations) |
| `connect_block_private_ips` | `true` | Reject a CONNECT target resolving to a loopback/link-local/private/unspecified address, regardless of policy |
| `connect_idle_timeout` | `5m` | Close a CONNECT tunnel after this long with no data in either direction; `0` disables it |
| `connect_max_duration` | `1h` | Close a CONNECT tunnel after this long regardless of activity; `0` disables it |
| `allowlist_url_template` | *(empty)* | URL template to resolve a per-request allow list from; see [Multi-tenant policy resolution](#multi-tenant-policy-resolution) |
| `denylist_url_template` | *(empty)* | URL template to resolve a per-request deny list from; see [Multi-tenant policy resolution](#multi-tenant-policy-resolution) |
| `policy_refresh_interval` | `5m` | How often a resolved policy URL is re-fetched |
| `policy_fetch_timeout` | `10s` | Timeout for a single policy fetch |

Restart the daemon after changing config, `allowlist_file`, or
`denylist_file` — those are read once at startup. Lists resolved via
`allowlist_url_template`/`denylist_url_template` refresh themselves on
`policy_refresh_interval` without a restart.

## Multi-tenant policy resolution

Setting `allowlist_url_template` and/or `denylist_url_template` turns
agentgated into a multi-tenant system: instead of one fixed list, the URL to
fetch a request's allow/deny list from is built per-request by substituting
placeholders into the template. Two placeholders are supported:

- `{ip}` — the client's source IP. Works for both DNS and CONNECT.
- `{header.Name}` — the value of HTTP header `Name` on a CONNECT request. A
  DNS query has no headers, so a template that uses this placeholder can
  never resolve for DNS traffic — see the fallback behavior below.

```yaml
allowlist_url_template: "https://policy.internal/tenants/{ip}/allow.txt"
denylist_url_template:  "https://policy.internal/tenants/{ip}/deny.txt"
```

Resolved lists are fetched once on first use, cached, and refreshed every
`policy_refresh_interval`. If a refresh fails, agentgated keeps serving the
last successfully fetched list rather than clearing it or failing the
request. If a template can't be resolved for a given request (e.g. a
`{header.*}` placeholder on a DNS query, or a missing header), or its first
fetch fails before anything is cached, agentgated falls back to the static
`allowlist_file`/`denylist_file` for that request.

**Security note:** agentgated substitutes these values into a URL — it does
not authenticate them. A bare `{header.*}` placeholder is only as trustworthy
as your network is at preventing a client from setting that header itself;
an agent that can set its own headers on its own CONNECT requests can set
that header to whatever it wants. `{ip}` is a stronger signal in topologies
where each tenant genuinely has its own unspoofable source IP, but is not
sufficient behind a shared NAT/gateway. Ensuring the identifying value can't
be spoofed for your topology (e.g. verifying a real `Proxy-Authorization`
credential upstream before a header is ever trusted, or enforcing one IP per
tenant at the network level) is the deploying admin/architect's
responsibility.

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

## Security model and known limitations

What hostname matching does guarantee: an allow/deny entry only matches
itself and its real subdomains — `google.com` matches `mail.google.com` but
never `badgoogle.com`, `xgoogle.com`, or any other look-alike glued on
without a label boundary (`internal/filter`'s `Contains` splits on `.`
rather than doing a raw string-suffix check, so this can't regress silently;
see `TestListDoesNotMatchLookalikeDomains`). A CONNECT target that's a raw
IP literal (an agent that already has an address and skips hostname
resolution) is never implicitly allowed by "not on the deny list" — unlike
a hostname, there's no way to enumerate bad IPs in advance, so a raw IP must
be explicitly present on the allow list to pass, in every mode except
`none`.

What the CONNECT proxy additionally guarantees, independent of hostname
policy (see the `connect_*` options above):
- **Port restriction.** A target's port must be in `connect_allowed_ports`
  (default: 443 only). An allowed hostname can't be reached on a different
  port running a different service — notably a DNS-over-TLS resolver (853).
- **A hard-override denylist.** `connect_denylist_file` always blocks a
  matching host, even under `filter_mode: none` or an allow list — static or
  dynamically resolved via `allowlist_url_template` — that includes it; deny
  wins over allow here, with no override mechanism other than editing the
  file. It ships seeded with known public DNS-over-HTTPS/DNS-over-TLS
  resolver hostnames (`configs/connect-denylist.txt.example`), since on port
  443 those are otherwise indistinguishable from ordinary HTTPS traffic —
  letting an allowed tunnel become a channel for resolving (and exfiltrating
  data through) arbitrary domains entirely outside agentgated's own DNS
  filtering.
- **Private/internal-address blocking.** `connect_block_private_ips`
  (default `true`) rejects a target resolving to a loopback, link-local
  (including a cloud metadata endpoint like `169.254.169.254`), private, or
  unspecified address, regardless of any allow list. The resolved address is
  validated once and dialed directly rather than the hostname a second time,
  so a DNS answer that changes between the check and the dial can't slip a
  disallowed address through.
- **Bounded tunnel lifetime.** `connect_idle_timeout` and
  `connect_max_duration` close a tunnel after inactivity or a hard ceiling,
  respectively, so a permitted tunnel can't stay open indefinitely.

What it does not (yet) guarantee, even with every other egress path from
the network blocked and *all* traffic forced through agentgated's own
listeners: neither proxy inspects content once a target is fully permitted.
- **DNS tunneling to a permitted domain.** Suffix matching says nothing
  about the labels *under* an allowed/non-denied domain, so an agent can
  encode data into query names like `<data>.api.anthropic.com` and have it
  leave via every DNS query, regardless of what the response is. This is
  the gap the planned exfiltration heuristics (entropy/beaconing analysis
  on the query log) are meant to eventually close.
- **CONNECT tunnels are byte-blind once a target clears every check above**
  (host, port, not on the built-in denylist, not a disallowed IP). Within
  those bounds, an agent can still send arbitrary HTTP request bodies,
  paths, and headers to an allowed host — e.g. exfiltrating via an allowed
  storage/paste/gist service's own write API — since agentgated has no
  visibility into what crosses an open tunnel. The port restriction and
  built-in denylist close the specific DNS-over-HTTPS/TLS bypass this
  previously allowed through *any* allowed hostname, but they don't give
  agentgated content-level visibility in general; only TLS termination
  (which agentgated deliberately does not do) could.

In short: tightening `filter_mode: allow` to a small, trusted set of
hostnames meaningfully shrinks what an agent can reach, but a hostname
allow list alone doesn't guarantee no data can leave through an allowed
destination — only that the destination is one you chose to trust, on the
port and address you meant to trust it on.

## Origins

agentgated started as a Go port of
[dnsproxyd](https://github.com/michaellandi/dnsproxyd) (Java/gcj) — same
DNS filtering shape, one static binary, no JVM. It's since been repointed at
a narrower problem: giving an AI agent a single, auditable point of control
for what it can reach on the network, rather than being a general-purpose
DNS filter.

## License

MIT License. See [LICENSE](LICENSE) for details.
