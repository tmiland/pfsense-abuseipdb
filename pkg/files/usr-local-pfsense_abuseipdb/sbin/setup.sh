#!/bin/sh
# pfsense_abuseipdb package setup: registers/unregisters the service and
# menu entries in config.xml (the same wiring the GUI installer does for
# packages installed through the web UI) and migrates an existing ini.

PKG_BASE="/usr/local/pfsense_abuseipdb"

register_config() {
  php <<'PHP'
<?php
global $config;
require_once("/etc/inc/config.inc");
$config = parse_config(true);

$name = 'pfsense_abuseipdb';
$svc = array(
    'name' => $name,
    'rcfile' => 'pfsense_abuseipdb',
    'description' => 'AbuseIPDB Watcher',
    'custom_php_service_status_command' =>
        'exec("/usr/bin/pgrep -f pfsense_abuseipdb.sh", $o); $rc = (count($o) > 1);'
);
$menu = array(
    'name' => 'AbuseIPDB',
    'tooltiptext' => 'AbuseIPDB Watcher status and settings',
    'section' => 'Services',
    'url' => '/packages/pfsense_abuseipdb/status.php'
);

$services = config_get_path('installedpackages/service', []);
$found = false;
foreach ($services as $k => $s) {
    if (isset($s['name']) && $s['name'] == $name) {
        $services[$k] = $svc;
        $found = true;
        break;
    }
}
if (!$found) {
    $services[] = $svc;
}
config_set_path('installedpackages/service', $services);

$menus = config_get_path('installedpackages/menu', []);
$found = false;
foreach ($menus as $k => $m) {
    if (isset($m['name']) && $m['name'] == $menu['name']) {
        $menus[$k] = $menu;
        $found = true;
        break;
    }
}
if (!$found) {
    $menus[] = $menu;
}
config_set_path('installedpackages/menu', $menus);

write_config("Installed pfSense-pkg-abuseipdb: registered service and menu");
PHP
}

unregister_config() {
  php <<'PHP'
<?php
global $config;
require_once("/etc/inc/config.inc");
$config = parse_config(true);

$name = 'pfsense_abuseipdb';
$services = config_get_path('installedpackages/service', []);
$out = array();
foreach ($services as $s) {
    if (isset($s['name']) && $s['name'] == $name) {
        continue;
    }
    $out[] = $s;
}
config_set_path('installedpackages/service', $out);

$menus = config_get_path('installedpackages/menu', []);
$out = array();
foreach ($menus as $m) {
    if (isset($m['name']) && $m['name'] == 'AbuseIPDB') {
        continue;
    }
    $out[] = $m;
}
config_set_path('installedpackages/menu', $out);

write_config("Removed pfSense-pkg-abuseipdb: unregistered service and menu");
PHP
}

migrate_secret() {
  # Copy a secret from its legacy credential file into the ini (value key),
  # unless the value key is already present.
  ini="${PKG_BASE}/etc/pfsense_abuseipdb.ini"
  vkey="$1"
  fkey="$2"
  [ -f "$ini" ] || return 0
  grep -q "^${vkey}=" "$ini" && return 0
  fpath=$(sed -n "s/^${fkey}=//p" "$ini" | head -1)
  [ -n "$fpath" ] && [ -r "$fpath" ] || return 0
  printf '%s=%s\n' "$vkey" "$(cat "$fpath")" >> "$ini"
}

case "$1" in
install)
  # Migrate the real ini from the old manual location if it exists.
  if [ -f /root/scripts/pfsense_abuseipdb.ini ] && [ ! -f "${PKG_BASE}/etc/pfsense_abuseipdb.ini" ]; then
    cp -p /root/scripts/pfsense_abuseipdb.ini "${PKG_BASE}/etc/pfsense_abuseipdb.ini"
  fi
  # Migrate secrets from the legacy credential files into the ini.
  migrate_secret abuseipdb_token abuseipdb_token_file
  migrate_secret ipinfo_token ipinfo_token_file
  migrate_secret mysql_password mysql_password_file
  migrate_secret abuse_email_password abuseip_email_password_file
  migrate_secret xarf_token xarf_token_file
  migrate_secret pfsense_token pfsense_token_file
  migrate_secret gmail_app_password gmail_app_password_file
  # The ini now carries secrets: lock it down.
  [ -f "${PKG_BASE}/etc/pfsense_abuseipdb.ini" ] && chmod 600 "${PKG_BASE}/etc/pfsense_abuseipdb.ini"
  register_config
  # Replace any watcher started from the old manual location, then start
  # the packaged one.
  pkill -f "/root/scripts/pfsense_abuseipdb.sh" 2>/dev/null
  /usr/local/etc/rc.d/pfsense_abuseipdb stop 2>/dev/null
  /usr/sbin/service pfsense_abuseipdb onestart >/dev/null 2>&1
  ;;
deinstall)
  /usr/local/etc/rc.d/pfsense_abuseipdb stop 2>/dev/null
  unregister_config
  ;;
*)
  echo "Usage: $0 install|deinstall"
  exit 1
  ;;
esac
