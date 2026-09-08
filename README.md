<h1 align="center">pfsense-abuseipdb</h1>

<p align="center">
  <a href="https://github.com/tmiland/pfsense-abuseipdb/releases"><img alt="platform" src="https://img.shields.io/badge/platform-pfSense%202.8-blue"></a>
  <img alt="shell" src="https://img.shields.io/badge/shell-bash-4EAA25?logo=gnu-bash&logoColor=white">
  <img alt="package" src="https://img.shields.io/badge/pkg-pfSense--pkg--abuseipdb-orange">
  <a href="LICENSE"><img alt="license" src="https://img.shields.io/badge/license-MIT-green"></a>
  <a href="https://opencode.ai"><img alt="built with opencode" src="https://img.shields.io/badge/built%20with-opencode-blueviolet"></a>
</p>

<p align="center">
  Suricata alert watcher for pfSense that reports attacker IPs to
  <a href="https://www.abuseipdb.com">AbuseIPDB</a>, files X-ARF reports with
  <a href="https://abusix.com">Abusix</a>, and logs every report to MySQL —
  with a native pfSense web UI.
</p>

---

## Features

- **Live watcher** — tails the Suricata `eve.json` alert log and parses every alert safely (comma-proof field parsing)
- **AbuseIPDB reporting** — category-mapped reports with confidence-score gating and a per-IP cooldown
- **X-ARF to Abusix** — structured abuse reports with alert evidence attached
- **MySQL logging** — every report stored for history and deduplication
- **GeoIP + WHOIS** — ipinfo.io lookup and WHOIS abuse-contact resolution, cached per IP
- **Native pfSense UI** — Status and Settings pages under **Services → AbuseIPDB**, theme-aware (light and dark)
- **Proper FreeBSD service** — rc.d script with crash-restart and log rotation
- **Installable package** — `pfSense-pkg-abuseipdb` from a hosted pkg repo

## Table of contents

- [Quick start](#quick-start)
- [How it works](#how-it-works)
- [Requirements](#requirements)
- [Configuration](#configuration)
- [Web UI](#web-ui)
- [Service management](#service-management)
- [Manual install](#manual-install)
- [Block log and cooldown](#block-log-and-cooldown)
- [Credits](#credits)
- [License](#license)

## Quick start

On the pfSense host — add the pkg repo and install:

```sh
cat > /usr/local/etc/pkg/repos/pfsense-abuseipdb.conf <<'EOF'
FreeBSD: { enabled: no }

pfsense-abuseipdb: {
  url: "https://tmiland.github.io/pfsense-abuseipdb/repo",
  mirror_type: "NONE",
  signature_type: "none",
  enabled: yes
}
EOF
pkg update -r pfsense-abuseipdb
pkg install -y -r pfsense-abuseipdb pfSense-pkg-abuseipdb
```

That's it — the watcher starts automatically and appears under
**Services → AbuseIPDB** in the web UI.

> pfSense pins the Package Manager *Available Packages* tab to the official
> Netgate repo, so third-party packages install from the CLI. Updates
> afterwards work with `pkg upgrade -r pfsense-abuseipdb`.

## How it works

1. `tail -f eve.json` — each alert parsed into timestamp, IPs, ports, signature, category, severity, direction
2. Optional ipinfo.io GeoIP lookup and WHOIS abuse-mailbox lookup for the source IP (cached per IP)
3. Skips alerts whose source IP is in a pf table listed in `suricata_whitelists`
4. Skips traffic not `to_server`, alerts sourced from the WAN IP itself, and IPv6 sources (for now)
5. Maps the ET signature category to AbuseIPDB category codes and X-ARF types
6. Once an IP has more than `report_limit` block-log entries, is outside its
   `report_cooldown` window, and has AbuseIPDB confidence above
   `abuseipdb_confidense_score_limit`: file the report (comments carry a
   credit link back to this repo), insert into MySQL, optionally email the
   WHOIS abuse contact, and send an X-ARF report

AbuseIPDB report errors and invalid X-ARF payloads can fire a pfSense
notification (all configured channels, throttled to one per hour) via the
`notifications` setting.

## Requirements

Installed on pfSense (FreeBSD): `bash`, `jq`, `curl`, `whois`, `mysql`
client, `uuidgen`, `pfctl`, GNU `base64`. A MySQL/MariaDB server reachable
from the firewall with a `reports` table.

## Configuration

All settings live in `pfsense_abuseipdb.ini` next to the script (or edit
them in the web UI — values are stored in config.xml and the ini is
regenerated on save). If the ini is missing it is created from
`example_pfsense_abuseipdb.ini`. Secrets are never stored in the ini — it
only holds paths to credential files under `/root/.credentials/`:

- `.pfsense-token`
- `.abuseipdb-token`
- `.abuseipdb-mysql-password`
- `.ipinfo-token`
- `.abuse-email-password` (abuse email reports)
- `.xarf-report-token`

Key groups: log paths and WAN interface, reporting thresholds
(`report_limit`, `abuseipdb_confidense_score_limit`, `report_cooldown`),
secrets, MySQL connection and toggles (`use_mysql`, `show_ip_info`,
`show_ip_abusedb_email`), notifications (`notifications`), abuse email
settings (`send_abuse_email_report`, SMTP host/port/from), X-ARF settings
(`send_xarf_report`, org/contact/domain), and `suricata_whitelists`
(comma-separated pf table names). See
[`example_pfsense_abuseipdb.ini`](example_pfsense_abuseipdb.ini) for every
key with comments.

### Secrets

Secrets (AbuseIPDB/ipinfo tokens, MySQL and SMTP passwords, Abusix key) are
entered in the **Settings** page (masked inputs, never echoed back) and
stored in the pfSense config. On save they are written into the package ini
(chmod 0600); empty secret fields keep their stored value, and secrets still
sitting in legacy `/root/.credentials/` files are migrated in automatically
— the package also migrates them on install/upgrade. The `*_file` ini keys
remain as a fallback read only when the value is empty.

> Heads-up: pfSense config backups (AutoConfigBackup) will include these
> values. If you prefer secrets to never leave the box, keep using the
> legacy credential files and leave the fields blank.

## Web UI

The package adds **Services → AbuseIPDB** to the pfSense menu with three tabs:

- **Status** — running state, today's AbuseIPDB reports / X-ARF acceptances /
  errors, recent block-log events, and a live service-log tail (auto-refresh
  every 60 seconds)
- **Reports** — browse recent reports: each collapsible entry shows the full
  report comment (with the alert log excerpt) plus the AbuseIPDB and X-ARF
  API responses
- **Settings** — every ini key as a form field, grouped into tabs (General,
  AbuseIPDB, Lookups, MySQL, Email, X-ARF); saving regenerates the ini and
  restarts the watcher. Secrets are masked inputs stored in the pfSense config.

Both pages are theme-agnostic and follow the selected webGUI stylesheet —
including custom light/dark themes.

## Service management

```sh
service pfsense_abuseipdb start    # also: stop, restart, status
sysrc pfsense_abuseipdb_enable=YES # start at boot
```

The service runs the watcher under `daemon(8)`: it restarts the watcher if it
dies, reopens its log on rotation, and the log is rotated by newsyslog
(1 MB, 3 generations). `status`/`stop` find the watcher via `pgrep -f`,
since `daemon(8)` retitles its process and its pidfile goes stale across
restarts.

## Manual install

Without the package, deploy the pieces by hand (the package is recommended —
it also migrates an existing manual installation on install):

```sh
scp pfsense_abuseipdb.sh pfsense_abuseipdb.ini root@pfsense:/root/scripts/
scp pfsense_abuseipdb root@pfsense:/usr/local/etc/rc.d/pfsense_abuseipdb
```

```sh
./pfsense_abuseipdb.sh          # run the live watcher loop
./pfsense_abuseipdb.sh debug    # strict modes + tracing (still a live loop!)
```

> Even in debug mode the loop is live: it processes the newest alerts
> immediately and sends real reports.

## Block log and cooldown

Every processed alert is appended to `/var/log/abuseipdb_block.log`; the
per-IP count in that file drives the reporting threshold. The cooldown uses
the same file: the timestamp of the last `Reporting IP:` entry for an IP is
compared against `report_cooldown` seconds (default 900 = 15 minutes,
AbuseIPDB's per-IP reporting limit). IPs inside the cooldown are skipped
before any API call.

## Credits

Developed by [Tommy Miland](https://github.com/tmiland) with
[opencode](https://opencode.ai) — AI pair engineering behind the debugging,
the ini-based configuration, the rc.d service, the pfSense package pipeline,
and the web UI pages.

## License

[MIT](LICENSE)
