#!/bin/sh
# Builds pfSense-pkg-abuseipdb and pkg(8) repo metadata.
# Run ON a pfSense host (or matching FreeBSD box): sh pkg/build.sh
# Output: <workdir>/out/packages/<ABI>/{All/*.pkg, meta.*, digests.*}
set -eu

PKGDIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO=$(dirname "$PKGDIR")
WORK=$(mktemp -d /tmp/pfsense-abuseipdb-build.XXXXXX)
STAGE="$WORK/stage"
META="$WORK/meta"
OUT="/tmp/pfsense-abuseipdb-repo-out"
rm -rf "$OUT"
mkdir -p "$STAGE" "$META" "$OUT"

PBASE="usr/local/pfsense_abuseipdb"
WBASE="usr/local/www/packages/pfsense_abuseipdb"
mkdir -p "$STAGE/$PBASE/bin" "$STAGE/$PBASE/etc" "$STAGE/$PBASE/sbin" \
	"$STAGE/$PBASE/share" "$STAGE/$WBASE" "$STAGE/usr/local/etc/rc.d"

install -m 0755 "$REPO/pfsense_abuseipdb.sh" "$STAGE/$PBASE/bin/pfsense_abuseipdb.sh"
install -m 0755 "$PKGDIR/files/usr-local-pfsense_abuseipdb/bin/pfsense_abuseipdb_protect.sh" \
	"$STAGE/$PBASE/bin/pfsense_abuseipdb_protect.sh"
install -m 0644 "$REPO/example_pfsense_abuseipdb.ini" "$STAGE/$PBASE/etc/example_pfsense_abuseipdb.ini"
install -m 0644 "$PKGDIR/files/usr-local-pfsense_abuseipdb/share/pfsense_abuseipdb.xml" \
	"$STAGE/$PBASE/share/pfsense_abuseipdb.xml"
install -m 0644 "$PKGDIR/files/usr-local-pfsense_abuseipdb/share/sync_protection.php" \
	"$STAGE/$PBASE/share/sync_protection.php"
install -m 0755 "$PKGDIR/files/usr-local-pfsense_abuseipdb/sbin/setup.sh" \
	"$STAGE/$PBASE/sbin/setup.sh"
install -m 0755 "$PKGDIR/files/usr-local-etc-rc.d-pfsense_abuseipdb" \
	"$STAGE/usr/local/etc/rc.d/pfsense_abuseipdb"
# Stage every www page automatically so new pages cannot be forgotten
for page in "$PKGDIR"/files/usr-local-www-packages-pfsense_abuseipdb/*.php; do
	install -m 0644 "$page" "$STAGE/$WBASE/$(basename "$page")"
done

php -l "$STAGE/$WBASE/status.php" >/dev/null
php -l "$STAGE/$WBASE/reports.php" >/dev/null
php -l "$STAGE/$WBASE/settings.php" >/dev/null

VERSION=$(sed -n 's/.*<version>\([^<]*\)<.*/\1/p' "$STAGE/$PBASE/share/pfsense_abuseipdb.xml" | head -1)
ABI=$(pkg config abi)
NAME="pfSense-pkg-abuseipdb"
ORIGIN="security/pfSense-pkg-abuseipdb"

cat > "$META/+PRE_INSTALL" <<'EOF'
#!/bin/sh
# Stop a watcher started from the old manual location before upgrade.
pkill -f "/root/scripts/pfsense_abuseipdb.sh" 2>/dev/null
exit 0
EOF

cat > "$META/+POST_INSTALL" <<'EOF'
#!/bin/sh
/usr/local/pfsense_abuseipdb/sbin/setup.sh install
/usr/sbin/sysrc pfsense_abuseipdb_enable=YES 2>/dev/null
exit 0
EOF

cat > "$META/+PRE_DEINSTALL" <<'EOF'
#!/bin/sh
/usr/local/pfsense_abuseipdb/sbin/setup.sh deinstall
exit 0
EOF

chmod 0755 "$META/+PRE_INSTALL" "$META/+POST_INSTALL" "$META/+PRE_DEINSTALL"

MANIFEST=$(php -r '
$stage = $argv[1]; $meta = $argv[2]; $abi = $argv[3];
$version = $argv[4]; $name = $argv[5]; $origin = $argv[6];
$files = array(); $flatsize = 0;
$it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($stage, FilesystemIterator::SKIP_DOTS));
foreach ($it as $f) {
    $rel = ltrim(str_replace($stage, "", $f->getPathname()), "/");
    $files["/" . $rel] = hash_file("sha256", $f->getPathname());
    $flatsize += $f->getSize();
}
$deps = array();
foreach (array("bash", "jq", "curl", "mysql80-client", "whois") as $dep) {
    $out = shell_exec("/usr/sbin/pkg query -q \"%n|%o|%v\" $dep 2>/dev/null");
    if (!empty(trim($out ?? ""))) {
        $parts = explode("|", trim($out));
        $deps[$parts[0]] = array("origin" => $parts[1], "version" => $parts[2]);
    }
}
$dirs = array();
foreach (array(
    "usr/local/pfsense_abuseipdb",
    "usr/local/pfsense_abuseipdb/bin",
    "usr/local/pfsense_abuseipdb/etc",
    "usr/local/pfsense_abuseipdb/sbin",
    "usr/local/pfsense_abuseipdb/share",
    "usr/local/www/packages/pfsense_abuseipdb"
) as $d) {
    $dirs["/" . $d] = "y";
}
$manifest = array(
    "name" => $name,
    "origin" => $origin,
    "version" => $version,
    "comment" => "AbuseIPDB Suricata alert watcher for pfSense",
    "desc" => "Tails Suricata eve.json and reports attacker IPs to AbuseIPDB, abusix X-ARF and MySQL. Includes pfSense UI status and settings pages.",
    "maintainer" => "kontakt@tmiland.com",
    "www" => "https://github.com/tmiland/pfsense-abuseipdb",
    "abi" => $abi,
    "arch" => $abi,
    "prefix" => "/",
    "categories" => array("pfSense"),
    "licenses" => array("MIT"),
    "flatsize" => $flatsize,
    "deps" => (object) $deps,
    "files" => (object) $files,
    "directories" => (object) $dirs,
    "scripts" => array(
        "pre-install" => "+PRE_INSTALL",
        "post-install" => "+POST_INSTALL",
        "pre-deinstall" => "+PRE_DEINSTALL"
    )
);
echo json_encode($manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
' "$STAGE" "$META" "$ABI" "$VERSION" "$NAME" "$ORIGIN")

echo "$MANIFEST" > "$META/+MANIFEST"

pkg create -m "$META" -r "$STAGE" -o "$OUT" >/dev/null

PKG_FILE=$(find "$OUT" -name "*.pkg" | head -1)
# Flat repo layout: metadata at the repo root, packages in All/
# (pfSense pkg(8) fetches ${url}/meta.conf).
REPO_OUT="$OUT"
mkdir -p "$REPO_OUT/All"
mv "$PKG_FILE" "$REPO_OUT/All/"
(cd "$REPO_OUT" && pkg repo . >/dev/null)

echo "=== Build complete: $REPO_OUT"
find "$REPO_OUT" -type f | sort
rm -rf "$WORK"