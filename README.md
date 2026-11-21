# lan-scan

Discover and identify services on the local network — passive fingerprints
only: TCP connect, read a bounded response, never send credentials.

```
$ lan-scan
192.0.2.1       80    http          HTTP 200 · example-router
192.0.2.1       445   smb
192.0.2.10      5001  dangbei-tv    HTTP 200 · BaseHTTP/0.6 · 当贝市场
192.0.2.9       22    lab-device    unlocked · SSH-2.0-dropbear_2024.81
```

The last line comes from a rule installed by another tool (see [Rules](#rules)):
a plain scan still reports `ssh`, the rule turns it into a named device.

## Kinds

| kind | how it is decided |
| --- | --- |
| `ssh` | TCP answered with an `SSH-` banner; the line before it (if any) is kept as evidence |
| `http` | HTTP server; detail is `status · Server · <title>` |
| `dangbei-tv` | HTTP/5001 serving Dangbei Market's remote-push page |
| `https` | TCP/443 open (TLS not inspected) |
| `smb` | TCP/445 open |
| `tcp` | other probed port answered |
| *anything* | a rule's `kind`, when its evidence matches (see below) |

## Options

    --subnet=192.168.1     probe this /24 (repeatable); default: local /24s
    --include=IP           also probe an address outside any /24 (repeatable,
                           comma-separated); e.g. a USB gadget address
    --ports=22,80,...      ports to fingerprint; default: 22,80,443,445,5001,8080
                           plus the ports of active rules
    --rules=FILE           add a rule file (repeatable); `-` reads stdin.
                           Explicit --rules replaces the installed rules.d
    --profile=NAME         activate only rules tagged NAME (`all` = every rule;
                           untagged rules always run)
    --no-rules             ignore installed rules; do a plain generic scan
    --filter=KIND          only print findings whose kind contains KIND
    --timeout=MS           connect+read timeout per probe (default 1500)
    --workers=N            parallel probes (default 128)
    --json                 emit a JSON array
    --jsonl                emit one JSON object per line (same schema)

Subnets are always clamped to /24. Scans read at most 16 KB per probe and
never send usernames, passwords or keys.

A port is probed for SSH first when its rule asks for SSH evidence (SSH
servers speak first); HTTP is probed only when the port is an HTTP port or a
rule asks for HTTP fields. One TCP connection per port is reused for both.

## Rules

A rule is **data, never code**: one file describes one device class, the
ports/hosts it lives on, and the passive evidence a probe must see. Rules are
read from `~/.config/lan-scan/rules.d/*.conf` (or `$XDG_CONFIG_HOME`), or from
`--rules FILE`.

```ini
schema     = 1                  # required
kind       = lab-device         # required: the label printed/JSON'd
label      = Example lab device
profile    = lab                # tag; untagged rules always run
ports      = 22
hosts      = 192.0.2.9          # extra targets, outside the /24 subnets
match      = ssh.gate == unlocked
match      = ssh.banner ~ dropbear
confidence = definitive
```

* `match` fields: `ssh.gate`, `ssh.banner`, `http.status`, `http.server`,
  `http.title`, `http.body`; operators `==` (exact, case-insensitive) and
  `~` (contains, case-insensitive).
* Every `match` line must pass. A rule with only `ports` matches any answered
  port in that set (a candidate, not proof).
* `confidence` defaults to `definitive` when matchers exist and `candidate`
  when only ports are given.
* Unknown keys, unknown fields and a missing `schema`/`kind` are errors —
  rules are validated on load and on install. `http.body` is used for
  matching only and never printed.

A fingerprint says "this looks like X", not "this is mine": lan-scan never
authenticates, and tools that send credentials must keep their own
verification.

### Managing installed rules

```sh
lan-scan rules install examples/lab-device.conf  # validated copy into rules.d
lan-scan rules list                               # name, kind, ports, profiles
lan-scan rules dir                                # where rules.d lives
lan-scan rules remove lab-device                  # by file stem
```

### Ad-hoc rules, without installing

```sh
lan-scan --rules ./tv.conf --profile tv --jsonl
lan-scan --rules - --include 192.0.2.9 < lab-device.conf
```

## JSON

`--json` prints an array, `--jsonl` one object per line; both use the same
object:

```json
{"schema": 1, "ip": "192.0.2.9", "port": 22, "kind": "lab-device",
 "detail": "unlocked · SSH-2.0-dropbear_2024.81",
 "rule": "lab-device", "label": "Example lab device",
 "confidence": "definitive",
 "evidence": {"gate": "unlocked", "banner": "SSH-2.0-dropbear_2024.81"}}
```

`rule`, `label` and `confidence` appear only when a rule claimed the finding.
`evidence` contains only fields the peer actually provided (`gate`, `banner`,
`status`, `server`, `title`); the response body is never included. The schema
is versioned so consumers can parse it without guessing.

## Build

    make check      # fmt + clippy + tests
    make release    # target/release/lan-scan
    make install    # cargo install --path .
