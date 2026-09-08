<?php
/*
 * sync_protection.php - CLI helper for the pfSense-pkg-abuseipdb DDoS
 * protection. Creates/removes the "abuseipdb_block" alias and the floating
 * WAN block rule that feeds it, then reloads the filter.
 *
 * Usage: php sync_protection.php on|off
 */
require_once("/etc/inc/config.inc");
global $config;
$config = parse_config(true);

$enabled = (($argv[1] ?? '') === 'on');
$alias_name = 'abuseipdb_block';
$rule_descr = 'pfSense-pkg-abuseipdb auto block';

$aliases = config_get_path('aliases/alias', []);
$found = false;
foreach ($aliases as $a) {
    if (($a['name'] ?? '') === $alias_name) {
        $found = true;
        break;
    }
}
if ($enabled && !$found) {
    $aliases[] = array(
        'name' => $alias_name,
        'type' => 'host',
        'address' => '',
        'descr' => 'AbuseIPDB DDoS blocklist (managed by pfSense-pkg-abuseipdb)',
        'detail' => ''
    );
    config_set_path('aliases/alias', $aliases);
}

$rules = config_get_path('filter', []);
$kept = array();
$rule_found = false;
foreach ($rules as $r) {
    if (($r['descr'] ?? '') === $rule_descr) {
        $rule_found = true;
        if ($enabled) {
            $kept[] = $r;
        }
        continue;
    }
    $kept[] = $r;
}
if ($enabled && !$rule_found) {
    $kept[] = array(
        'type' => 'block',
        'interface' => 'wan',
        'ipprotocol' => 'inet',
        'source' => array('address' => $alias_name),
        'destination' => array('any' => ''),
        'descr' => $rule_descr,
        'floating' => 'yes',
        'quick' => 'yes',
        'direction' => 'any',
        'log' => '',
        'created' => array('time' => (string)time(), 'username' => 'pfSense-pkg-abuseipdb'),
        'tracker' => (string)mt_rand(1000000000, 9999999999)
    );
}
config_set_path('filter', $kept);
write_config("AbuseIPDB protection " . ($enabled ? "enabled" : "disabled"));
filter_configure();
echo "protection " . ($enabled ? "on" : "off") . ": alias + rule synced\n";
