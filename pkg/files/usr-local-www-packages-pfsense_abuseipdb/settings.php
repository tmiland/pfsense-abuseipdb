<?php
/*
 * settings.php
 *
 * Settings page for the AbuseIPDB Suricata Watcher package. Values are
 * stored in config.xml (installedpackages/pfsense_abuseipdb/settings) and
 * generated into the package ini on save, then the service is restarted.
 * Secrets are entered here (masked) and stored in config.xml; on save,
 * empty secret fields keep their existing value, and secrets still only
 * present in legacy credential files under /root/.credentials/ are
 * migrated in automatically. The generated ini is chmod 0600 since it
 * then contains the secrets.
 */
require_once("guiconfig.inc");

$ini_file = '/usr/local/pfsense_abuseipdb/etc/pfsense_abuseipdb.ini';
$rcd = '/usr/local/etc/rc.d/pfsense_abuseipdb';

/* Settings grouped into tabs: key => array(label, type, help, tab) */
$tabs = array(
    'general' => 'General',
    'abuseipdb' => 'AbuseIPDB',
    'lookups' => 'Lookups',
    'mysql' => 'MySQL',
    'email' => 'Email',
    'xarf' => 'X-ARF'
);

$fields = array(
    /* General */
    'alerts_file' => array('Suricata eve.json path', 'text', 'Path to the eve.json alert log.', 'general'),
    'block_log_file' => array('Block log path', 'text', 'Per-IP detection log that drives the reporting threshold.', 'general'),
    'wan' => array('WAN interface', 'text', 'Interface name, e.g. igb0.', 'general'),
    'domain' => array('Domain', 'text', 'Local domain used in reports.', 'general'),
    'notifications' => array('pfSense notifications', 'select', 'Notify the admin via System > Advanced > Notifications channels on report errors (max 1 per hour).', 'general'),
    'suricata_whitelists' => array('Whitelist pf tables', 'text', 'Comma-separated pf table names used to whitelist source IPs.', 'general'),
    'pfsense_token' => array('pfSense API token', 'secret', 'Used by the (optional) filterlog section.', 'general'),
    'pfsense_url' => array('pfSense API URL', 'text', '', 'general'),
    'gmail_app_password' => array('Gmail app password', 'secret', 'Reserved for future use.', 'general'),
    /* AbuseIPDB */
    'abuseipdb_token' => array('AbuseIPDB API token', 'secret', 'Reported comments carry a link back to the project.', 'abuseipdb'),
    'abuseipdb_user_id' => array('AbuseIPDB user id', 'text', 'Your AbuseIPDB account id.', 'abuseipdb'),
    'report_limit' => array('Report limit', 'number', 'Detections in the block log required before an IP is reported.', 'abuseipdb'),
    'abuseipdb_confidense_score_limit' => array('Confidence score limit', 'number', 'AbuseIPDB confidence score required to file a report (past 90 days).', 'abuseipdb'),
    'report_cooldown' => array('Report cooldown (seconds)', 'number', 'Minimum seconds between reports for the same IP. 0 disables the cooldown.', 'abuseipdb'),
    /* Lookups */
    'ipinfo_token' => array('ipinfo token', 'secret', '', 'lookups'),
    'show_ip_info' => array('Show IP info', 'select', 'GeoIP lookup for each alert.', 'lookups'),
    'show_ip_abusedb_email' => array('Show abuse contact', 'select', 'WHOIS abuse-mailbox lookup for each alert.', 'lookups'),
    /* MySQL */
    'use_mysql' => array('Use MySQL', 'select', 'Log every report to MySQL.', 'mysql'),
    'mysql_host' => array('MySQL host', 'text', '', 'mysql'),
    'mysql_user' => array('MySQL user', 'text', '', 'mysql'),
    'mysql_password' => array('MySQL password', 'secret', 'Migrated from the legacy password file on save.', 'mysql'),
    'mysql_database' => array('MySQL database', 'text', '', 'mysql'),
    /* Email */
    'send_abuse_email_report' => array('Send abuse email', 'select', 'Email the WHOIS abuse contact.', 'email'),
    'email_report_limit' => array('Email report limit', 'number', 'Detections required before an abuse email is sent.', 'email'),
    'report_name' => array('Report name', 'text', 'Display name of the email sender.', 'email'),
    'report_email' => array('Report email', 'text', 'From address for abuse emails.', 'email'),
    'abuse_email_password' => array('Abuse email password', 'secret', 'SMTP password for abuse email reports.', 'email'),
    'report_smtp_host' => array('SMTP host', 'text', '', 'email'),
    'report_smtp_port' => array('SMTP port', 'number', '', 'email'),
    /* X-ARF */
    'send_xarf_report' => array('Send X-ARF reports', 'select', 'Report to abusix via X-ARF.', 'xarf'),
    'xarf_token' => array('X-ARF API key', 'secret', 'Abusix datachannels API key.', 'xarf'),
    'xarf_org' => array('X-ARF org', 'text', '', 'xarf'),
    'xarf_contact' => array('X-ARF contact', 'text', 'Abuse contact address sent with X-ARF reports.', 'xarf'),
    'xarf_domain' => array('X-ARF domain', 'text', '', 'xarf')
);

/* Yes/no toggles render as selects. */
$yesno_keys = array();
foreach ($fields as $key => $f) {
    if ($f[1] == 'select') {
        $yesno_keys[] = $key;
    }
}

function pfsense_abuseipdb_ini_value($file, $key) {
    if (!file_exists($file)) {
        return '';
    }
    foreach (file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        if (preg_match('/^([a-z_]+)=(.*)$/', $line, $m) && $m[1] === $key) {
            return $m[2];
        }
    }
    return '';
}

function pfsense_abuseipdb_read_ini($file, $keys) {
    $vals = array();
    if (file_exists($file)) {
        foreach (file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
            if (preg_match('/^([a-z_]+)=(.*)$/', $line, $m) && isset($keys[$m[1]])) {
                $vals[$m[1]] = $m[2];
            }
        }
    }
    return $vals;
}

function pfsense_abuseipdb_gen_ini($v) {
    return "; pfsense_abuseipdb.ini - generated by the pfSense package settings page\n" .
        "; contains secrets - keep chmod 600\n" .
        "pfsense_token={$v['pfsense_token']}\n" .
        "abuseipdb_token={$v['abuseipdb_token']}\n" .
        "ipinfo_token={$v['ipinfo_token']}\n" .
        "gmail_app_password={$v['gmail_app_password']}\n" .
        "mysql_password={$v['mysql_password']}\n" .
        "abuse_email_password={$v['abuse_email_password']}\n" .
        "xarf_token={$v['xarf_token']}\n" .
        "pfsense_url={$v['pfsense_url']}\n" .
        "alerts_file={$v['alerts_file']}\n" .
        "block_log_file={$v['block_log_file']}\n" .
        "wan={$v['wan']}\n" .
        "abuseipdb_user_id={$v['abuseipdb_user_id']}\n" .
        "report_limit={$v['report_limit']}\n" .
        "abuseipdb_confidense_score_limit={$v['abuseipdb_confidense_score_limit']}\n" .
        "report_cooldown={$v['report_cooldown']}\n" .
        "notifications={$v['notifications']}\n" .
        "domain={$v['domain']}\n" .
        "mysql_host={$v['mysql_host']}\n" .
        "mysql_user={$v['mysql_user']}\n" .
        "mysql_database={$v['mysql_database']}\n" .
        "use_mysql={$v['use_mysql']}\n" .
        "show_ip_info={$v['show_ip_info']}\n" .
        "show_ip_abusedb_email={$v['show_ip_abusedb_email']}\n" .
        "send_abuse_email_report={$v['send_abuse_email_report']}\n" .
        "email_report_limit={$v['email_report_limit']}\n" .
        "report_name={$v['report_name']}\n" .
        "report_email={$v['report_email']}\n" .
        "report_smtp_host={$v['report_smtp_host']}\n" .
        "report_smtp_port={$v['report_smtp_port']}\n" .
        "send_xarf_report={$v['send_xarf_report']}\n" .
        "xarf_org={$v['xarf_org']}\n" .
        "xarf_contact={$v['xarf_contact']}\n" .
        "xarf_domain={$v['xarf_domain']}\n" .
        "suricata_whitelists={$v['suricata_whitelists']}\n";
}

/* Legacy credential-file keys (fallback + migration source) */
$secret_file_keys = array(
    'abuseipdb_token' => 'abuseipdb_token_file',
    'ipinfo_token' => 'ipinfo_token_file',
    'mysql_password' => 'mysql_password_file',
    'abuse_email_password' => 'abuseip_email_password_file',
    'xarf_token' => 'xarf_token_file',
    'pfsense_token' => 'pfsense_token_file',
    'gmail_app_password' => 'gmail_app_password_file'
);

/* Initial values: config.xml settings first, then the live ini as fallback. */
$vals = array();
foreach ($fields as $key => $f) {
    $vals[$key] = config_get_path("installedpackages/pfsense_abuseipdb/settings/{$key}");
    if ($vals[$key] === null) {
        $vals[$key] = '';
    }
}
$ini_vals = pfsense_abuseipdb_read_ini($ini_file, $fields);
foreach ($fields as $key => $f) {
    if ($vals[$key] === '' && isset($ini_vals[$key])) {
        $vals[$key] = $ini_vals[$key];
    }
}
if ($vals['report_cooldown'] === '') {
    $vals['report_cooldown'] = '900';
}

$input_errors = array();
$saved = false;

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $new = array();
    foreach ($fields as $key => $f) {
        $val = trim($_POST[$key] ?? '');
        $val = str_replace(array("\r", "\n", "\0"), '', $val);
        if ($f[1] == 'select' && !in_array($val, array('yes', 'no'))) {
            $val = 'no';
        }
        if ($f[1] == 'number' && $val !== '' && !ctype_digit($val)) {
            $input_errors[] = sprintf(gettext('%s must be a number.'), $f[0]);
        }
        $new[$key] = $val;
    }
    /* Secrets: empty input keeps the stored value; if none is stored yet,
       migrate it in from the legacy credential file. */
    foreach ($secret_file_keys as $vk => $fk) {
        if ($new[$vk] === '') {
            $new[$vk] = $vals[$vk] ?? '';
        }
        if ($new[$vk] === '') {
            $path = pfsense_abuseipdb_ini_value($ini_file, $fk);
            if ($path !== '' && is_readable($path)) {
                $new[$vk] = trim(file_get_contents($path));
            }
        }
    }
    foreach (array('alerts_file', 'block_log_file', 'wan') as $req) {
        if ($new[$req] === '') {
            $input_errors[] = sprintf(gettext('%s is required.'), $fields[$req][0]);
        }
    }
    if (empty($input_errors)) {
        foreach ($yesno_keys as $key) {
            if ($new[$key] === '') {
                $new[$key] = 'no';
            }
        }
        config_set_path('installedpackages/pfsense_abuseipdb/settings', $new);
        write_config("AbuseIPDB package settings updated");
        file_put_contents($ini_file, pfsense_abuseipdb_gen_ini($new));
        chmod($ini_file, 0600);
        mwexec_bg("/usr/local/etc/rc.d/pfsense_abuseipdb restart");
        $saved = true;
        $vals = $new;
    }
}

$pgtitle = array(gettext("Services"), gettext("AbuseIPDB"), gettext("Settings"));
include("head.inc");

/* Theme-agnostic styling: inherit colors so both light and dark themes work. */
?>
<style>
	code.abuseipdb-key {
		background: transparent;
		color: inherit;
		padding: 0;
		font-size: 85%;
	}
</style>
<?php

$tab_array = array();
$tab_array[] = array(gettext("Status"), false, "/packages/pfsense_abuseipdb/status.php");
$tab_array[] = array(gettext("Reports"), false, "/packages/pfsense_abuseipdb/reports.php");
$tab_array[] = array(gettext("Settings"), true, "/packages/pfsense_abuseipdb/settings.php");
display_top_tabs($tab_array);

if ($saved) {
    print_info_box(gettext('Settings saved, ini regenerated and the watcher service was restarted.'), 'success');
}
if (!empty($input_errors)) {
    print_input_errors($input_errors);
}
?>

<form action="settings.php" method="post">
	<div class="panel panel-default">
		<div class="panel-heading"><h2 class="panel-title"><?= gettext('AbuseIPDB Suricata Watcher settings') ?></h2></div>
		<div class="panel-body">
			<ul class="nav nav-tabs">
<?php $first = true; foreach ($tabs as $tid => $tname): ?>
				<li<?= $first ? ' class="active"' : '' ?>><a data-toggle="tab" href="#<?= htmlspecialchars($tid) ?>"><?= htmlspecialchars($tname) ?></a></li>
<?php $first = false; endforeach ?>
			</ul>
			<div class="tab-content" style="padding-top: 10px;">
<?php $first = true; foreach ($tabs as $tid => $tname): ?>
				<div class="tab-pane<?= $first ? ' active' : '' ?>" id="<?= htmlspecialchars($tid) ?>">
					<div class="table-responsive">
						<table class="table table-striped table-hover">
							<tbody>
<?php foreach ($fields as $key => $f): if ($f[3] !== $tid) { continue; } ?>
								<tr>
									<td style="width: 30%;">
										<strong><?= htmlspecialchars($f[0]) ?></strong><br />
										<code class="abuseipdb-key"><?= htmlspecialchars($key) ?></code>
									</td>
									<td>
<?php if ($f[1] == 'select'): ?>
										<select class="form-control" name="<?= htmlspecialchars($key) ?>">
											<option value="yes" <?= ($vals[$key] == 'yes') ? 'selected' : '' ?>><?= gettext('yes') ?></option>
											<option value="no" <?= ($vals[$key] != 'yes') ? 'selected' : '' ?>><?= gettext('no') ?></option>
										</select>
<?php elseif ($f[1] == 'secret'): ?>
										<input class="form-control" type="password" name="<?= htmlspecialchars($key) ?>" value="" autocomplete="new-password" placeholder="<?= ($vals[$key] !== '') ? gettext('(stored - leave blank to keep)') : gettext('(blank - migrated from legacy file on save)') ?>" />
<?php else: ?>
										<input class="form-control" type="text" name="<?= htmlspecialchars($key) ?>" value="<?= htmlspecialchars($vals[$key]) ?>" autocomplete="off" />
<?php endif ?>
<?php if (!empty($f[2])): ?>
										<span class="help-block"><?= htmlspecialchars($f[2]) ?></span>
<?php endif ?>
									</td>
								</tr>
<?php endforeach ?>
							</tbody>
						</table>
					</div>
				</div>
<?php $first = false; endforeach ?>
			</div>
		</div>
		<div class="panel-footer">
			<button type="submit" class="btn btn-primary" name="save" value="save">
				<i class="fa fa-save icon-embed-btn"></i><?= gettext('Save and restart watcher') ?>
			</button>
			<span class="help-block">
				<?= gettext('All tabs are saved together. Secrets are stored in the pfSense config (masked here, never echoed back). Leave a secret blank to keep its stored value; secrets still living in /root/.credentials/ files are migrated in automatically on save. Note: pfSense config backups (AutoConfigBackup) will include these values.') ?>
			</span>
		</div>
	</div>
</form>

<?php include("foot.inc");
