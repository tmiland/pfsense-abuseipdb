<?php
/*
 * reports.php
 *
 * Report browser for the AbuseIPDB Suricata Watcher package. Each entry in
 * /var/log/abuseipdb_reports.log (JSON, written by the watcher on every
 * successful report) is shown as a collapsible panel with the full comment
 * (including the alert log excerpt) and the AbuseIPDB / X-ARF responses.
 */
require_once("guiconfig.inc");

$pgtitle = array(gettext("Services"), gettext("AbuseIPDB"), gettext("Reports"));
include("head.inc");

$tab_array = array();
$tab_array[] = array(gettext("Status"), false, "/packages/pfsense_abuseipdb/status.php");
$tab_array[] = array(gettext("Reports"), true, "/packages/pfsense_abuseipdb/reports.php");
$tab_array[] = array(gettext("Settings"), false, "/packages/pfsense_abuseipdb/settings.php");
display_top_tabs($tab_array);

$reports_log = '/var/log/abuseipdb_reports.log';

$reports = array();
if (file_exists($reports_log)) {
    exec("/usr/bin/tail -n 20 " . escapeshellarg($reports_log) . " 2>/dev/null", $lines);
    foreach (array_reverse($lines) as $line) {
        $rec = json_decode($line, true);
        if (is_array($rec)) {
            $reports[] = $rec;
        }
    }
}
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
	.abuseipdb-collapse .panel-heading {
		cursor: pointer;
	}
</style>

<?php if (empty($reports)): ?>
	<div class="alert alert-info">
		<?= gettext('No reports recorded yet. Every successful AbuseIPDB report (with its X-ARF result) is recorded here.') ?>
	</div>
<?php endif; ?>

<?php foreach ($reports as $i => $r): ?>
	<div class="panel panel-default abuseipdb-collapse">
		<div class="panel-heading" data-toggle="collapse" href="#abuseipdb-report-<?= $i ?>">
			<h2 class="panel-title">
				<?= htmlspecialchars($r['time'] ?? '?') ?> &mdash;
				<strong><?= htmlspecialchars($r['ip'] ?? '?') ?></strong>
				&mdash; <?= gettext('categories') ?> <?= htmlspecialchars($r['categories'] ?? '-') ?>
<?php if (isset($r['abuseipdb']['abuseConfidenceScore'])): ?>
				&mdash; <?= gettext('confidence') ?> <?= htmlspecialchars($r['abuseipdb']['abuseConfidenceScore']) ?>%
<?php endif ?>
<?php if (isset($r['xarf']['state'])): ?>
				&mdash; X-ARF <?= htmlspecialchars($r['xarf']['state']) ?>
<?php endif ?>
			</h2>
		</div>
		<div id="abuseipdb-report-<?= $i ?>" class="panel-collapse collapse">
			<div class="panel-body">
				<pre class="abuseipdb-log"><?= htmlspecialchars(json_encode($r, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)) ?></pre>
			</div>
		</div>
	</div>
<?php endforeach ?>

<?php include("foot.inc");
