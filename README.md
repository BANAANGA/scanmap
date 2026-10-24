# scanmap

A small, self-hosted web interface for **nmap** and **zmap**, shipped as a single
Docker container.

Two scanners, one UI: use nmap when you want detail (service/version detection,
NSE scripts, OS fingerprinting) and zmap when you want to sweep a large address
space quickly.

![CI](https://github.com/BANAANGA/scanmap/actions/workflows/ci.yml/badge.svg) ![status](https://img.shields.io/badge/status-early%20preview-orange) ![license](https://img.shields.io/badge/license-MIT-blue)

> ## ⚠️ Authorised use only
>
> Port scanning and internet-wide probing are regulated in many countries and
> are forbidden on networks you do not own or have **written permission** to
> test. You are responsible for every scan you start. The maintainers accept no
> liability for misuse or damage caused by this software. If you are unsure,
> scan only `127.0.0.1` or your own lab range.

---

## Features

- **Two scanners behind one UI** — nmap and zmap, each with their own form.
- **Live output** — job output is streamed into the browser while a scan runs.
- **Copyable results** — zmap CSV responses are shown in a table; click a cell
  to copy its value.
- **Job list** — start several scans, watch status, cancel a running one,
  download the log.
- **Allow-listed arguments** — the UI never exposes a free-form "extra flags"
  box. Targets, ports, scripts and output fields are validated server-side and
  handed to `subprocess` as an argv list (no shell), so the container does not
  become a remote shell.
- **Zero dependencies** — the backend is Python's standard library. No
  `pip install`, no build step, no JS framework.
- **Small footprint** — `debian-slim` + `nmap` + `zmap` + `python3`.
- **Runs unprivileged** — the app runs as a non-root user with only the
  `NET_RAW`/`NET_ADMIN` capabilities it needs.

## Quick start

Pull from GHCR and run with docker compose:

```bash
# Create a working directory
mkdir -p scanmap && cd scanmap

# Download compose file
curl -L -o docker-compose.yml https://raw.githubusercontent.com/BANAANGA/scanmap/main/docker-compose.yml

# Create data directory for blocklists and user DB
mkdir -p data

# Start the container (pulls ghcr.io/banaanga/scanmap:latest automatically)
docker compose up -d
```

Then open <http://localhost:8420>.

On first run, if no users exist, you'll be redirected to `/setup` to create the admin account.

Without compose:

```bash
docker pull ghcr.io/banaanga/scanmap:latest
docker run --rm -p 8420:8420 --cap-add NET_RAW --cap-add NET_ADMIN \
  -v "$PWD/data:/data" \
  ghcr.io/banaanga/scanmap:latest
```

Using environment variables:

```bash
docker run --rm -p 8420:8420 --cap-add NET_RAW --cap-add NET_ADMIN \
  -e SCANMAP_USER=admin -e SCANMAP_PASSWORD=change-me \
  -v "$PWD/data:/data" \
  ghcr.io/banaanga/scanmap:latest
```

> With `SCANMAP_USER`/`SCANMAP_PASSWORD` set, HTTP basic auth is used. Otherwise the built-in session auth is used (first-run admin registration). Put a TLS reverse proxy in front if exposing beyond localhost.

### nmap example

Target `192.168.1.0/24`, scan type *TCP SYN*, ports `22,80,443`, timing `T4`,
service detection on. The exact command is previewed live under the form:

```
nmap -v -sS -T4 -p 22,80,443 -sV 192.168.1.0/24
```

### zmap example

Target `10.0.0.0/8`, port `443`, bandwidth `10M`, output fields `saddr,dport`:

```
zmap -v 4 -p 443 -B 10M -M tcp_synscan -f saddr,dport -o - 10.0.0.0/8
```

> **Before you zmap:** zmap deliberately scans the whole address block at high
> speed. Always use a blocklist for reserved ranges. Put your blocklist in
> `data/` and reference it as `blocklist.txt` (paths are resolved inside
> `SCANMAP_DATA_DIR` only).

#### Why does zmap show no results?

zmap ships with a blocklist of private and reserved ranges (`10.0.0.0/8`,
`192.168.0.0/16`, `127.0.0.0/8`, …) and, when a scan targets one of those
ranges, aborts with `zero eligible addresses to scan`. That is the right
default for the public Internet but useless for a LAN scan, so scanmap:

- automatically passes an empty blocklist (`-b /dev/null`) when the target is a
  private, loopback or link-local address;
- exposes an **Ignore built-in blocklist** checkbox (on by default) for public
  targets;
- resolves the Docker gateway MAC from the kernel neighbor table and passes
  it to zmap, avoiding a stall during zmap's gateway discovery;
- always writes results to stdout (`-o -`) and runs zmap with `-v 4`, so the
  console shows the interface, output module and progress;
- adds a hint to the console when a zmap job finishes without a single host.

If a scan still finds nothing, the host is probably not answering on that port
(zmap only reports *successful* TCP responses: `SYN-ACK` or `RST`). Verify with
`nmap -Pn -p <port> <target>` from the same container.

## Configuration

All configuration is via environment variables:

| Variable | Default | Description |
| --- | --- | --- |
| `SCANMAP_HOST` | `0.0.0.0` | Bind address. |
| `SCANMAP_PORT` | `8420` | HTTP port. |
| `SCANMAP_DATA_DIR` | `/data` | Working directory; also the only place input files may come from. |
| `SCANMAP_MAX_PARALLEL` | `2` | How many scans may run at once. |
| `SCANMAP_MAX_JOBS` | `100` | Number of jobs kept in memory (oldest finished jobs are evicted). |
| `SCANMAP_USER` | *(empty)* | Enables HTTP basic auth when set together with the password. |
| `SCANMAP_PASSWORD` | *(empty)* | See above. |

### Setting a password

```yaml
environment:
  SCANMAP_USER: "admin"
  SCANMAP_PASSWORD: "change-me"
```

Basic auth is plain HTTP unless you terminate TLS in front of the container
(reverse proxy, `stunnel`, Cloudflare Tunnel, …). Do not expose scanmap directly
to the internet without TLS and a password. There is no built-in rate limiting,
so a compromised instance is an open scanning proxy.

## HTTP API

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/api/health` | Liveness probe. |
| `GET` | `/api/tools` | Availability and version of nmap/zmap (`?refresh=1` re-probes). |
| `POST` | `/api/preview` | Validate params and return the argv that would run. |
| `POST` | `/api/jobs` | Start a scan: `{"scanner":"nmap","params":{...}}`. |
| `GET` | `/api/jobs` | List jobs, newest first. |
| `GET` | `/api/jobs/{id}?since=N` | Job status plus output lines from offset `N`. |
| `POST` | `/api/jobs/{id}/cancel` | Send SIGTERM to the scan's process group. |
| `DELETE` | `/api/jobs/{id}` | Forget a finished job. |

Example:

```bash
curl -s localhost:8080/api/preview \
  -H 'content-type: application/json' \
  -d '{"scanner":"nmap","params":{"target":"127.0.0.1","ports":"1-1024"}}'
# {"argv": ["nmap", "-v", "-sT", "-T3", "-p", "1-1024", "-n", "127.0.0.1"]}
```

Accepted `params` per scanner:

**nmap** — `target`, `scan` (`connect|syn|udp|ping`), `ports`, `timing`
(`T0`–`T5`), `service_detection`, `version_intensity`, `default_scripts`,
`scripts`, `os_detection`, `no_ping`, `no_dns`, `open_only`.

**zmap** — `target` (single IP/CIDR), `port`, `bandwidth`, `rate`, `interface`,
`source_port`, `probe_module`, `output_fields`, `max_targets`, `cooldown`,
`blocklist`, `dry_run`.

## Update

To pull the latest image and restart:

```bash
docker compose pull
docker compose up -d
```

Or with plain docker:

```bash
docker pull ghcr.io/banaanga/scanmap:latest
docker stop scanmap 2>/dev/null; docker rm scanmap 2>/dev/null
docker run --rm -d --name scanmap -p 8420:8420 --cap-add NET_RAW --cap-add NET_ADMIN \
  -v "$PWD/data:/data" \
  ghcr.io/banaanga/scanmap:latest
```

Your data (users, blocklists) persists in the `data/` volume.

```bash
sudo apt install nmap zmap python3
git clone https://github.com/BANAANGA/scanmap.git
cd scanmap
mkdir -p data
SCANMAP_DATA_DIR=$PWD/data python3 -m app.main
```

## Tests

```bash
python3 -m unittest discover -s tests -t .
```

## How it is wired

```
browser ──HTTP──> app/main.py (stdlib http.server)
                     │  validates + builds argv
                     ▼
                  app/jobs.py  ──subprocess (argv, no shell)──> nmap / zmap
                     │
                     └─ bounded in-memory output buffer ──> browser polling
```

- `app/scanners.py` — argument construction and validation. The single place
  that knows which flags are allowed.
- `app/jobs.py` — thread-per-job runner with a semaphore, process-group
  cancellation and capped output.
- `app/main.py` — routing, JSON, static files, optional basic auth.
- `app/static/` — the UI (vanilla HTML/CSS/JS).

## Security notes

- Commands are built from a fixed allow-list; targets, ports, script names and
  zmap output fields are pattern-checked, and arguments are never interpolated
  into a shell.
- Blocklist files must resolve inside `SCANMAP_DATA_DIR`; path traversal is
  rejected.
- The process runs as UID 10001 with `NET_RAW`/`NET_ADMIN`, not as root.
- Jobs are in-memory only, so a restart clears history.
- Still: treat scanmap as a privileged internal tool. Put it behind a VPN or an
  authenticating reverse proxy.

## Roadmap

- [ ] Persist job history and results (SQLite) with XML/JSON/CSV downloads.
- [ ] Server-sent events instead of polling.
- [ ] Scheduled/recurring scans.
- [ ] Saved scan profiles.
- [ ] Multi-arch image and automated releases.

## License

MIT — see [LICENSE](LICENSE).
