<?php
/*
 * status.php
 *
 * Status page for the AbuseIPDB Suricata Watcher package.
 */
require_once("guiconfig.inc");
require_once("service-utils.inc");

$pgtitle = array(gettext("Services"), gettext("AbuseIPDB"), gettext("Status"));
include("head.inc");

/* Theme-agnostic styling: inherit colors so both light and dark themes work. */
?>
<style>
	pre.abuseipdb-log {
		background: transparent;
		color: inherit;
		border: 1px solid currentColor;
		border-radius: 4px;
		overflow-wrap: anywhere;
		white-space: pre-wrap;
	}
	td.abuseipdb-error {
		font-weight: 700;
	}
	td.abuseipdb-muted {
		opacity: 0.65;
	}
</style>
<?php

$tab_array = array();
$tab_array[] = array(gettext("Status"), true, "/packages/pfsense_abuseipdb/status.php");
$tab_array[] = array(gettext("Settings"), false, "/packages/pfsense_abuseipdb/settings.php");
display_top_tabs($tab_array);

$script = '/usr/local/pfsense_abuseipdb/bin/pfsense_abuseipdb.sh';
$block_log = '/var/log/abuseipdb_block.log';
$service_log = '/var/log/pfsense_abuseipdb_service.log';

$running = is_service_running('pfsense_abuseipdb');

/* Event categories matched against the block log message text. */
$event_patterns = array(
    'Reporting IP:' => 'info',
    'AbuseIPDB Confidence Score:' => 'info',
    'Response:' => 'muted',
    'X-ARF Response:' => 'info',
    'ERROR' => 'error',
    'Trigger:' => 'muted',
    'JSON is' => 'muted'
);

$events = array();
$today = date('Y-m-d');
$stats = array('reported' => 0, 'xarf_ok' => 0, 'errors' => 0);

if (file_exists($block_log)) {
    exec("/usr/bin/tail -n 300 " . escapeshellarg($block_log) . " 2>/dev/null", $lines);
    foreach (array_reverse($lines) as $line) {
        if (!preg_match('/^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) - (.*)$/', $line, $m)) {
            continue;
        }
        $type = 'other';
        foreach ($event_patterns as $needle => $cls) {
            if (strpos($m[2], $needle) !== false) {
                $type = $cls;
                break;
            }
        }
        if (substr($m[1], 0, 10) == $today) {
            if ($type == 'info' && strpos($m[2], 'Reporting IP:') !== false) {
                $stats['reported']++;
            }
            if (strpos($m[2], 'X-ARF Response') !== false && strpos($m[2], '"success"') !== false) {
                $stats['xarf_ok']++;
            }
            if ($type == 'error') {
                $stats['errors']++;
            }
        }
        $events[] = array('ts' => $m[1], 'class' => $type, 'msg' => $m[2]);
        if (count($events) >= 100) {
            break;
        }
    }
}
$events = array_reverse($events);
?>

<?php if (!$running): ?>
	<div class="alert alert-warning">
		<strong><?= gettext('The AbuseIPDB Suricata Watcher service is not running.') ?></strong>
		<?= gettext('Start it from') ?> <a href="status_services.php"><?= gettext('Status &gt; Services') ?></a>.
	</div>
<?php else: ?>
	<div class="alert alert-success">
		<strong><?= gettext('AbuseIPDB Suricata Watcher is running.') ?></strong>
	</div>
<?php endif; ?>

<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?= gettext('Activity today') ?></h2></div>
	<div class="panel-body">
		<div class="row">
			<div class="col-md-4">
				<div class="panel panel-default">
					<div class="panel-body text-center">
						<h3><?= htmlspecialchars($stats['reported']) ?></h3>
						<span><?= gettext('AbuseIPDB reports filed') ?></span>
					</div>
				</div>
			</div>
			<div class="col-md-4">
				<div class="panel panel-default">
					<div class="panel-body text-center">
						<h3><?= htmlspecialchars($stats['xarf_ok']) ?></h3>
						<span><?= gettext('X-ARF reports accepted') ?></span>
					</div>
				</div>
			</div>
			<div class="col-md-4">
				<div class="panel panel-default">
					<div class="panel-body text-center">
						<h3><?= htmlspecialchars($stats['errors']) ?></h3>
						<span><?= gettext('Errors today') ?></span>
					</div>
				</div>
			</div>
		</div>
	</div>
</div>

<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?= gettext('Recent events (block log)') ?></h2></div>
	<div class="panel-body">
		<div class="table-responsive">
			<table class="table table-striped table-hover table-condensed">
				<thead>
					<tr>
						<th><?= gettext('Time') ?></th>
						<th><?= gettext('Event') ?></th>
					</tr>
				</thead>
				<tbody>
<?php foreach ($events as $e): ?>
					<tr>
						<td style="white-space: nowrap;"><?= htmlspecialchars($e['ts']) ?></td>
						<td class="<?= ($e['class'] == 'error') ? 'abuseipdb-error' : (($e['class'] == 'muted') ? 'abuseipdb-muted' : '') ?>">
							<?= htmlspecialchars($e['msg']) ?>
						</td>
					</tr>
<?php endforeach ?>
				</tbody>
			</table>
		</div>
	</div>
</div>

<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?= gettext('Service log tail') ?></h2></div>
	<div class="panel-body">
		<pre class="abuseipdb-log"><?= htmlspecialchars(implode("\n", array_slice(explode("\n", shell_exec("tail -n 40 " . escapeshellarg($service_log) . " 2>/dev/null")), -40))) ?></pre>
	</div>
</div>

<?php include("foot.inc");
