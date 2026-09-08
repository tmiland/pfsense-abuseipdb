<?php
/*
 * abuseipdb.widget.php
 *
 * Dashboard widget for the AbuseIPDB Watcher package: service state,
 * detection source, reports filed today, banned IP count and the last
 * block-log events, linking into the package Status page.
 */
require_once("guiconfig.inc");
require_once("service-utils.inc");
require_once("/usr/local/www/widgets/include/abuseipdb.inc");

$block_log = '/var/log/abuseipdb_block.log';
$pkg_ini = '/usr/local/pfsense_abuseipdb/etc/pfsense_abuseipdb.ini';

/* Read the few keys we display (ini is chmod 600; webgui runs as root) */
$ini = array();
if (file_exists($pkg_ini)) {
	foreach (file($pkg_ini, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $l) {
		if (preg_match('/^([a-z_]+)=(.*)$/', trim($l), $m)) {
			$ini[$m[1]] = trim($m[2]);
		}
	}
}
$protect_on = (($ini['protection'] ?? '') === 'yes');
$detection_label = (($ini['detection_source'] ?? '') === 'pf') ?
	gettext('pf firewall (native)') : gettext('Suricata alert stream');

$watcher_running = is_service_running('pfsense_abuseipdb');

$reports_today = 0;
$last_events = array();
$banned = 0;
$protect_running = false;

if ($watcher_running) {
	/* Bounded tail: never grep the whole (large) block log from a widget */
	exec("/usr/bin/tail -n 500 " . escapeshellarg($block_log) . " 2>/dev/null", $lines);
	$today = date('Y-m-d');
	foreach (array_reverse($lines) as $line) {
		if (strpos($line, $today) === 0 && strpos($line, 'Reporting IP:') !== false) {
			$reports_today++;
		}
	}
	$last_events = array_slice($lines, -3);
	if ($protect_on) {
		exec("/sbin/pfctl -t abuseipdb_block -T show 2>/dev/null", $banned_list);
		$banned = count($banned_list);
		exec("/bin/pgrep -f pfsense_abuseipdb_protect", $protect_pids);
		$protect_running = !empty($protect_pids);
	}
}
?>
<div class="content">
	<table class="table table-striped table-hover">
		<tbody>
			<tr>
				<td><?= gettext('Service') ?></td>
				<td>
<?php if ($watcher_running): ?>
					<span class="text-success"><i class="fa-solid fa-circle-check"></i> <?= gettext('running') ?></span>
<?php else: ?>
					<span class="text-danger"><i class="fa-solid fa-circle-xmark"></i> <?= gettext('not running') ?></span>
<?php endif ?>
				</td>
			</tr>
			<tr>
				<td><?= gettext('Detection source') ?></td>
				<td><?= htmlspecialchars($detection_label) ?></td>
			</tr>
			<tr>
				<td><?= gettext('Reports today') ?></td>
				<td><?= $reports_today ?></td>
			</tr>
<?php if ($protect_on): ?>
			<tr>
				<td><?= gettext('Protection') ?></td>
				<td>
<?php if ($protect_running): ?>
					<span class="text-success"><?= sprintf(gettext('on, %1$d IP(s) banned'), $banned) ?></span>
<?php else: ?>
					<span class="text-warning"><?= gettext('enabled, engine not running') ?></span>
<?php endif ?>
				</td>
			</tr>
<?php endif ?>
		</tbody>
	</table>
<?php if (!empty($last_events)): ?>
	<table class="table table-condensed">
		<tbody>
<?php foreach ($last_events as $ev):
	if (!preg_match('/^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) - (.*)$/', $ev, $m)) { continue; }
	$msg = (mb_strlen($m[2]) > 64) ? mb_substr($m[2], 0, 63) . '…' : $m[2];
?>
			<tr>
				<td class="text-muted" style="white-space: nowrap;"><?= htmlspecialchars(substr($m[1], 11)) ?></td>
				<td class="text-muted"><?= htmlspecialchars($msg) ?></td>
			</tr>
<?php endforeach ?>
		</tbody>
	</table>
<?php endif ?>
	<div class="text-right" style="padding-bottom: 5px;">
		<a href="/packages/pfsense_abuseipdb/status.php"><?= gettext('Open AbuseIPDB status') ?> <i class="fa-solid fa-arrow-right"></i></a>
	</div>
</div>
