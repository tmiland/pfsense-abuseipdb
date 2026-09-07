# pfsense-abuseipdb

Suricata alert watcher for pfSense that reports attacker IPs to AbuseIPDB,
sends X-ARF reports to Abusix, and logs every report to MySQL.

The script tails `/var/log/suricata/suricata_igb0*/eve.json`, parses each
alert with `jq`, resolves GeoIP info (ipinfo.io) and the WHOIS abuse
contact, and — once an IP has been logged `report_limit` times and has an
AbuseIPDB confidence score above `abuseipdb_confidense_score_limit` — files
a categorized report with a 1024-character comment built from the alert
logs.

## Flow

1. `tail -f eve.json` → each alert parsed into timestamp, IPs, ports,
   signature, category, severity, direction.
2. Optional ipinfo.io lookup and WHOIS abuse-mailbox lookup for the source IP.
3. Skips alerts whose source IP is in a pf table listed in
   `suricata_whitelists` (checked via `pfctl -t <table> -T show`).
4. Skips traffic not `to_server` and alerts sourced from the WAN IP itself.
5. Maps the ET signature category (second word of the signature) to AbuseIPDB
   category codes and X-ARF types.
6. Once the IP is in the block log more than `report_limit` times and
   AbuseIPDB confidence > limit: report to AbuseIPDB, insert into MySQL,
   optionally email the WHOIS abuse contact, and send an X-ARF report.

## Requirements

Installed on pfSense (FreeBSD): `bash`, `jq`, `curl`, `whois`, `mysql`
client, `uuidgen`, `pfctl`, GNU `base64`. A MySQL/MariaDB server reachable
from the firewall with a `reports` table.

## Credentials

The ini points at credential files read at startup (default
`/root/.credentials/` on the firewall):

- `.pfsense-token`
- `.abuseipdb-token`
- `.abuseipdb-mysql-password`
- `.ipinfo-token`
- `.abuse-email-password` (abuse email reports)
- `.xarf-report-token`

## Configuration

All settings live in `pfsense_abuseipdb.ini`, sourced from the script
directory at startup. If the file is missing, it is created from
`example_pfsense_abuseipdb.ini`. Secrets are not stored in the ini — it only
holds paths to credential files under `/root/.credentials/`.

Keys: `alerts_file`, `block_log_file`, `wan`, `abuseipdb_user_id`,
`report_limit`, `abuseipdb_confidense_score_limit`, `domain`,
`mysql_host`, `mysql_user`, `mysql_password_file`, `mysql_database`,
`use_mysql`, `show_ip_info`, `show_ip_abusedb_email`,
`send_abuse_email_report`, `email_report_limit`, `report_name`,
`report_email`, `report_smtp_host`, `report_smtp_port`,
`send_xarf_report`, `xarf_org`, `xarf_contact`, `xarf_domain`,
`suricata_whitelists` (comma-separated pf table names), and the
credential file paths (`*_file`).

On the firewall the script and ini live in `/root/scripts/`; deploy with:

```sh
scp pfsense_abuseipdb.sh pfsense_abuseipdb.ini root@pfsense:/root/scripts/
```

## Usage

```sh
./pfsense_abuseipdb.sh          # run the live watcher loop
./pfsense_abuseipdb.sh debug    # same loop with set -o errexit/pipefail/nounset/xtrace
```

The debug argument enables strict shell modes and tracing. Note that even
in debug mode the loop is live: it processes the newest alerts immediately
and sends real reports.

## Service (pfSense / FreeBSD)

pfSense has no systemd; the equivalent service file is the rc.d script
`pfsense_abuseipdb` in this repo. It runs the watcher under `daemon(8)`
(`-r` restarts it if it dies), logs stdout to
`/var/log/pfsense_abuseipdb_service.log`, and exports `/usr/local/bin` in
PATH for the child.

```sh
scp pfsense_abuseipdb root@pfsense:/usr/local/etc/rc.d/pfsense_abuseipdb
ssh root@pfsense chmod 755 /usr/local/etc/rc.d/pfsense_abuseipdb
ssh root@pfsense sysrc pfsense_abuseipdb_enable=YES
ssh root@pfsense service pfsense_abuseipdb start   # also: stop, status, restart
```

`status`/`stop` find the watcher via `pgrep -f`, since daemon(8) retitles
its process and its pidfile goes stale across `-r` restarts.

## Block log

Every processed alert is appended to `/var/log/abuseipdb_block.log`; the
per-IP count in that file is what drives the reporting threshold.
