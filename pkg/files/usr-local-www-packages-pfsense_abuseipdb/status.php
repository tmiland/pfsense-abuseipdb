<?php
/*
 * status.php
 *
 * Status page for the AbuseIPDB Suricata Watcher package. Split into
 * sub-views (Overview / Events / Blocked IPs / Service log) selectable via
 * the "view" URL parameter; the Activity-today counters link into the
 * filtered Events view.
 */
require_once("guiconfig.inc");
require_once("service-utils.inc");

$pgtitle = array(gettext("Services"), gettext("AbuseIPDB"), gettext("Status"));
include("head.inc");

$tab_array = array();
$tab_array[] = array(gettext("Status"), true, "/packages/pfsense_abuseipdb/status.php");
$tab_array[] = array(gettext("Reports"), false, "/packages/pfsense_abuseipdb/reports.php");
$tab_array[] = array(gettext("Settings"), false, "/packages/pfsense_abuseipdb/settings.php");
display_top_tabs($tab_array);

$script = '/usr/local/pfsense_abuseipdb/bin/pfsense_abuseipdb.sh';
$block_log = '/var/log/abuseipdb_block.log';
$service_log = '/var/log/pfsense_abuseipdb_service.log';

$running = is_service_running('pfsense_abuseipdb');

/* DDoS protection: blocked IPs (only when the toggle is on) */
$protection = '';
$pkg_ini = '/usr/local/pfsense_abuseipdb/etc/pfsense_abuseipdb.ini';
if (file_exists($pkg_ini)) {
    foreach (file($pkg_ini, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $l) {
        if (preg_match('/^protection=(.*)$/', $l, $m)) {
            $protection = trim($m[1]);
        }
    }
}
$blocked = array();
if ($protection === 'yes') {
    exec("/sbin/pfctl -t abuseipdb_block -T show 2>/dev/null", $blocked);
}

/* Sub-view selection */
$views = array('overview', 'events', 'blocked', 'log');
$view = $_GET['view'] ?? 'overview';
if (!in_array($view, $views, true)) {
    $view = 'overview';
}
$filter = $_GET['filter'] ?? '';
$filter_labels = array('reports' => gettext('AbuseIPDB reports'), 'errors' => gettext('errors'), 'xarf' => gettext('X-ARF results'));
if (!isset($filter_labels[$filter])) {
    $filter = '';
}

/* Event categories matched against the block log message text. Most
   specific needles first: "X-ARF Response:" contains "Response:". */
$event_patterns = array(
    'Reporting IP:' => array('info', 'reports'),
    'AbuseIPDB Confidence Score:' => array('info', ''),
    'X-ARF Response:' => array('info', 'xarf'),
    'Response:' => array('muted', ''),
    'ERROR' => array('error', 'errors'),
    'Trigger:' => array('muted', ''),
    'JSON is' => array('muted', '')
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
        $bucket = '';
        foreach ($event_patterns as $needle => $meta) {
            if (strpos($m[2], $needle) !== false) {
                $type = $meta[0];
                $bucket = $meta[1];
                break;
            }
        }
        if (substr($m[1], 0, 10) == $today) {
            if ($bucket == 'reports') {
                $stats['reported']++;
            }
            if ($bucket == 'xarf' && strpos($m[2], '"success"') !== false) {
                $stats['xarf_ok']++;
            }
            if ($type == 'error') {
                $stats['errors']++;
            }
        }
        $events[] = array('ts' => $m[1], 'class' => $type, 'bucket' => $bucket, 'msg' => $m[2]);
        if (count($events) >= 100) {
            break;
        }
    }
}
$events = array_reverse($events);

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
	a.abuseipdb-card, a.abuseipdb-card:hover {
		text-decoration: none;
		color: inherit;
	}
</style>
<?php

/* Sub-view navigation (page reloads keep the auto-refresh parameters). */
$subtabs = array(
    'overview' => gettext('Overview'),
    'events' => gettext('Events'),
    'blocked' => gettext('Blocked IPs'),
    'log' => gettext('Service log')
);
?>
<ul class="nav nav-tabs">
<?php foreach ($subtabs as $vid => $vname): ?>
	<li<?= ($view === $vid) ? ' class="active"' : '' ?>><a href="status.php?view=<?= htmlspecialchars($vid) ?>"><?= htmlspecialchars($vname) ?></a></li>
<?php endforeach ?>
</ul>

<?php if ($view == 'overview'): ?>

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
				<div class="col-md-3">
					<a class="abuseipdb-card" href="status.php?view=events&filter=reports">
						<div class="panel panel-default">
							<div class="panel-body text-center">
								<h3><?= htmlspecialchars($stats['reported']) ?></h3>
								<span><?= gettext('AbuseIPDB reports filed') ?></span>
							</div>
						</div>
					</a>
				</div>
				<div class="col-md-3">
					<a class="abuseipdb-card" href="status.php?view=events&filter=xarf">
						<div class="panel panel-default">
							<div class="panel-body text-center">
								<h3><?= htmlspecialchars($stats['xarf_ok']) ?></h3>
								<span><?= gettext('X-ARF reports accepted') ?></span>
							</div>
						</div>
					</a>
				</div>
				<div class="col-md-3">
					<a class="abuseipdb-card" href="status.php?view=events&filter=errors">
						<div class="panel panel-default">
							<div class="panel-body text-center">
								<h3><?= htmlspecialchars($stats['errors']) ?></h3>
								<span><?= gettext('Errors today') ?></span>
							</div>
						</div>
					</a>
				</div>
				<div class="col-md-3">
					<a class="abuseipdb-card" href="status.php?view=blocked">
						<div class="panel panel-default">
							<div class="panel-body text-center">
								<h3><?= htmlspecialchars(count($blocked)) ?></h3>
								<span><?= gettext('IPs banned (DDoS protection)') ?></span>
							</div>
						</div>
					</a>
				</div>
			</div>
		</div>
	</div>

<?php elseif ($view == 'events'): ?>

	<div class="panel panel-default">
		<div class="panel-heading">
			<h2 class="panel-title">
<?php if ($filter !== ''): ?>
				<?= sprintf(gettext('Events: %1$s (last 100)'), $filter_labels[$filter]) ?>
				&mdash; <a href="status.php?view=events"><?= gettext('show all') ?></a>
<?php else: ?>
				<?= gettext('Recent events (block log)') ?>
<?php endif ?>
			</h2>
		</div>
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
<?php $shown = 0; foreach ($events as $e): if ($filter !== '' && $e['bucket'] !== $filter) { continue; } $shown++; ?>
						<tr>
							<td style="white-space: nowrap;"><?= htmlspecialchars($e['ts']) ?></td>
							<td class="<?= ($e['class'] == 'error') ? 'abuseipdb-error' : (($e['class'] == 'muted') ? 'abuseipdb-muted' : '') ?>">
								<?= htmlspecialchars($e['msg']) ?>
							</td>
						</tr>
<?php endforeach; if ($shown === 0): ?>
						<tr><td colspan="2" class="text-muted"><?= gettext('No matching events in the recent log window.') ?></td></tr>
<?php endif ?>
					</tbody>
				</table>
			</div>
		</div>
	</div>

<?php elseif ($view == 'blocked'): ?>

<?php if ($protection !== 'yes'): ?>
	<div class="alert alert-info">
		<?= gettext('DDoS protection is disabled. Enable it under Settings > Protection.') ?>
	</div>
<?php else: ?>
	<div class="panel panel-default">
		<div class="panel-heading"><h2 class="panel-title"><?= gettext('DDoS protection - blocked IPs') ?> (<?= count($blocked) ?>)</h2></div>
		<div class="panel-body">
<?php if (empty($blocked)): ?>
			<p class="text-muted"><?= gettext('Block table is empty.') ?></p>
<?php else: ?>
			<pre class="abuseipdb-log"><?= htmlspecialchars(implode("\n", $blocked)) ?></pre>
<?php endif ?>
		</div>
	</div>
<?php endif ?>

<?php elseif ($view == 'log'): ?>

	<div class="panel panel-default">
		<div class="panel-heading"><h2 class="panel-title"><?= gettext('Service log tail') ?></h2></div>
		<div class="panel-body">
			<pre class="abuseipdb-log"><?= htmlspecialchars(implode("\n", array_slice(explode("\n", shell_exec("tail -n 40 " . escapeshellarg($service_log) . " 2>/dev/null")), -40))) ?></pre>
		</div>
	</div>

<?php endif ?>

<script>
	setTimeout(function() { location.reload(); }, 60000);
</script>

<?php include("foot.inc");
