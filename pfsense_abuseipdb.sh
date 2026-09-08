#!/usr/bin/env bash

# shellcheck disable=SC1007
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
config_file="${SCRIPT_DIR}/pfsense_abuseipdb.ini"
example_config_file="${SCRIPT_DIR}/example_pfsense_abuseipdb.ini"

if [[ ! -f "$config_file" ]] && [[ -f "${SCRIPT_DIR}/../etc/pfsense_abuseipdb.ini" ]]; then
  config_file="${SCRIPT_DIR}/../etc/pfsense_abuseipdb.ini"
  example_config_file="${SCRIPT_DIR}/../etc/example_pfsense_abuseipdb.ini"
fi

if [[ ! -f "$config_file" ]]; then
  cp -rp "$example_config_file" "$config_file" \
    || echo "Error: Configuration file $config_file not found."; exit 1;
fi

config_grep() {
  sed -n "s/^$1=//p" "$config_file"
}

config_secret() {
  # Prefer the value key; fall back to the legacy credential-file key.
  local value file
  value=$(config_grep "$1")
  if [ -z "${value}" ]; then
    file=$(config_grep "$2")
    if [ -n "${file}" ] && [ -r "${file}" ]; then
      value=$(< "${file}")
    fi
  fi
  printf '%s' "${value}"
}

# Credentials (entered in the web UI settings, stored in config.xml; the
# *_file keys remain as a legacy fallback)
# shellcheck disable=SC2034
PFSENSE_TOKEN=$(config_secret pfsense_token pfsense_token_file)
# shellcheck disable=SC2034
PFSENSE_URL=$(config_grep pfsense_url)
ABUSEIPDB_TOKEN=$(config_secret abuseipdb_token abuseipdb_token_file)
IPINFO_TOKEN=$(config_secret ipinfo_token ipinfo_token_file)
# shellcheck disable=SC2034
GMAIL_APP_PASS=$(config_secret gmail_app_password gmail_app_password_file)

# Suricata
ALERTS_FILE=$(config_grep alerts_file)
block_log_file=$(config_grep block_log_file)
wan=$(config_grep wan)

# AbuseIPDB
# shellcheck disable=SC2034
abuseipdb_user_id=$(config_grep abuseipdb_user_id)
report_limit=$(config_grep report_limit)
abuseipdb_confidense_score_limit=$(config_grep abuseipdb_confidense_score_limit)
report_cooldown=$(config_grep report_cooldown)
notifications=$(config_grep notifications)

# Mysql database
domain=$(config_grep domain)
mysql_host=$(config_grep mysql_host)
mysql_user=$(config_grep mysql_user)
mysql_password=$(config_secret mysql_password mysql_password_file)
mysql_database=$(config_grep mysql_database)
use_mysql=$(config_grep use_mysql)
show_ip_info=$(config_grep show_ip_info)
show_ip_abusedb_email=$(config_grep show_ip_abusedb_email)

# Email settings
send_abuse_email_report=$(config_grep send_abuse_email_report)
email_report_limit=$(config_grep email_report_limit)
ABUSEIP_EMAIL_PASS=$(config_secret abuse_email_password abuseip_email_password_file)
report_name=$(config_grep report_name)
report_email=$(config_grep report_email)
report_smtp_host=$(config_grep report_smtp_host)
report_smtp_port=$(config_grep report_smtp_port)

# X-ARF
xarf_token=$(config_secret xarf_token xarf_token_file)
send_xarf_report=$(config_grep send_xarf_report)
xarf_org=$(config_grep xarf_org)
xarf_contact=$(config_grep xarf_contact)
xarf_domain=$(config_grep xarf_domain)

if [[ $* =~ "debug" ]]
then
  set -o errexit
  set -o pipefail
  set -o nounset
  set -o xtrace
fi

IFS="," read -ra suricata_whitelists <<< "$(config_grep suricata_whitelists)"

# abusedb_contact_email() {
#   curl -s 'GET' \
  #   "https://abusedb.cloud/api/v1/${1}" \
  #   -H 'accept: application/json' \
  #   | jq -r '.contacts[] | select(.type == "email")' \
  #   | jq -s 'sort_by(.confidence)' \
  #   | jq -r '.[].email' \
  #   | head -n 1
# }

whois_contact_email() {
  whois "${1}" | grep "abuse-mailbox:" | awk -F ':  ' '{print $2}' | tail -n 1
}

sql_escape() {
  printf '%s' "${1}" | sed "s/'/''/g"
}

mysql_query() {
  MYSQL_PWD="$mysql_password" mysql -h $mysql_host -u $mysql_user --database $mysql_database <<EOF
INSERT INTO reports (datetime, timestamp, IPv4, domain, comment, ports, categories, direction)
VALUES ('$(sql_escape "$datetime")','$(sql_escape "$timestamp")','$(sql_escape "$ip")','$(sql_escape "$domain")','$(sql_escape "$comment")','$(sql_escape "$ports")','$(sql_escape "$abipdb_category")','$(sql_escape "$direction")')
EOF
}

mysqli_query_count() {
  MYSQL_PWD="$mysql_password" mysql -h $mysql_host -u $mysql_user --database $mysql_database <<EOF
SELECT COUNT(*) FROM reports WHERE IPv4 = '$ip'
EOF
}

mysqli_query_datetime() {
  MYSQL_PWD="$mysql_password" mysql -h $mysql_host -u $mysql_user --database $mysql_database <<EOF
SELECT datetime FROM reports WHERE IPv4 = '$ip'
EOF
}

declare -A whois_cache ipinfo_cache

tail -q -f "${ALERTS_FILE}" | while read -r line; do
  # Parsing Json file via jq;
  # @tsv keeps values intact even when they contain commas; tabs are mapped
  # to the unit separator so read preserves empty fields.
  IFS=$'\037' read -r timestamp flow_id in_iface event_type src_ip src_port dest_ip dest_port proto pkt_src action signature_id signature category severity direction \
    <<< "$(jq -r '[.timestamp, .flow_id, .in_iface, .event_type, .src_ip, .src_port, .dest_ip, .dest_port, .proto, .pkt_src, .alert .action, .alert .signature_id, .alert .signature, .alert .category, .alert .severity, .direction] | @tsv' <<< "${line}" | tr '\t' '\037')"
  echo "========== Alerts ==========

Timestamp       : $timestamp
Flow id:        : $flow_id
Interface       : $in_iface
Event type      : $event_type
Source IP       : $src_ip
Source port     : $src_port
Destination IP  : $dest_ip
Destination port: $dest_port
Protocol        : $proto
Source packet   : $pkt_src
Action          : $action
Signature id    : $signature_id
Signature       : $signature
Category        : $category
Severety        : $severity
Direction       : $direction
  "

  # Rename arguments for readability.
  ip=${src_ip}
  ports=${src_port}
  message=${signature}

  if [ "${show_ip_info}" == "yes" ]; then
    if [[ -z "${ipinfo_cache[${src_ip}]:-}" ]]; then
      ip_info=$(curl -s https://api.ipinfo.io/lite/"${src_ip}" \
        -H "Authorization: Bearer ${IPINFO_TOKEN}") || true
      ipinfo_cache[${src_ip}]=$(printf '%s' "${ip_info}" | jq -r '"Asn\t\(.asn)\nAs name:\t\(.as_name)\nAs domain\t\(.as_domain)\nCountry code\t\(.country_code)\nCountry\t\(.country)\nContinent code\t\(.continent_code)\nContinent\t\(.continent)"' | expand -t 16 2>/dev/null) || true
      [[ -z "${ipinfo_cache[${src_ip}]}" ]] && ipinfo_cache[${src_ip}]="none"
    fi
    echo "========== IP Info =========="
    echo ""
    if [ "${ipinfo_cache[${src_ip}]}" == "none" ]; then
      echo "No ipinfo data available."
    else
      echo "${ipinfo_cache[${src_ip}]}"
    fi
    echo "    "

    if [ "${show_ip_abusedb_email}" == "yes" ]; then
      if [[ -z "${whois_cache[${src_ip}]:-}" ]]; then
        whois_cache[${src_ip}]=$(whois_contact_email "${src_ip}") || true
        [[ -z "${whois_cache[${src_ip}]}" ]] && whois_cache[${src_ip}]="none"
      fi
      whois_contact_email=${whois_cache[${src_ip}]}
      [ "${whois_contact_email}" == "none" ] && whois_contact_email=""
      if ! [ "${whois_contact_email}" = "" ]; then
        echo "========== IP Abuse Contact Email ==========

Abuse email     : ${whois_contact_email}
        "
      fi
    fi

  fi
  wan_ip=$(ifconfig $wan | grep 'inet ' | awk '{print $2}')
  # Use custom whitelists on pfsense
  if [[ $(command -v 'pfctl') ]]; then
    # if ! [[ $(command -v 'grepcidr') ]]; then
    #   pkg install grepcidr
    # fi
    for suricata_whitelist in "${suricata_whitelists[@]}"; do
      # Check if source ip is in whitelist
      whitelist_ip_count=$(pfctl -t "${suricata_whitelist}" -T show | grep -cF "${src_ip}" || true)
      # Skip alert if src ip is in whitelist
      if [ "$whitelist_ip_count" -gt 0 ]; then
        echo "IP ${src_ip} is in ${suricata_whitelist}"
        continue 2
      fi
    done
  fi
  # Abort if traffic is origination from server
  if ! [ "$direction" == "to_server" ]; then
    echo "Traffic originating FROM server! Exiting..."
    continue
  else
    # Abort if source IP is WAN IP
    if [ "${wan_ip}" = "${src_ip}" ]
    then
      echo "Source IP is WAN IP! Exiting..."
      continue
    fi
    # IPv6 sources are not supported yet
    if [[ "${src_ip}" == *:* ]]; then
      echo "IPv6 source address ${src_ip} - reporting not supported yet. Skipping..."
      continue
    fi
    # Get category from signature
    signature_category=$(echo "$signature" | awk -F ' ' '{print $2}')
    # Determine the appropriate AbuseIPDB category based on the trigger and comment
    # determine_category() {
    #   local signature_category=$1
    abipdb_category="18"
    xarf_category_type="login_attack"
    xarf_category="connection"
    shopt -s nocasematch
    case $signature_category in
      3CORESec)
        abipdb_category="21"
        xarf_category_type="login_attack"
        xarf_category="connection"
        ;; #This category is for signatures that are generated automatically from the 3CORESec team’s IP block lists. These blocklists are generated by 3CORESec based on malicious activity from their Honeypots. For more information see: https://blacklist.3coresec.net/lists/et-open.txt
      ACTIVEX)
        abipdb_category="21"
        xarf_category_type="vuln_scanning"
        xarf_category="connection"
        ;; #This category is for signatures that protect against attacks against Microsoft ActiveX controls and exploits targeting vulnerabilities in ActiveX controls.
      ADWARE_PUP)
        abipdb_category=""
        xarf_category_type="login_attack"
        xarf_category="connection"
        ;; #This category is for signatures to identify software that is used for ad tracking or other types of spyware related activity which is often undesirable. Note: this category is present in rulesets for Suricata 5.0 or later. In Suricata versions prior to 5.0 and Snort 2.9 these rules are in the Malware category.
      ATTACK_RESPONSE)
        ;; #This category is for signatures to identify responses indicative of intrusion—examples include but not limited to LMHost file download, presence of certain web banners and the detection of Metasploit Meterpreter kill command. These are designed to catch the results of a successful attack. Things like “id=root”, or error messages that indicate a compromise may have happened.
      "Botcc (Bot Command and Control)")
        ;; #This category is for signatures that are autogenerated from several sources of known and confirmed active botnet and other Command and Control (C2) hosts. This category is updated daily. The category’s primary data source is Shadowserver.org. For more information see www.shadowserver.org.
      "Botcc Portgrouped")
        ;; #This category is for signatures like those in the Botcc category but grouped by destination port. Rules grouped by port can offer higher fidelity than those not grouped by port.
      CHAT)
        abipdb_category=""
        xarf_category_type="login_attack"
        xarf_category="connection"
        ;; #This category is for signatures that identify traffic related to numerous chat clients such as Internet Relay Chat (IRC). Chat traffic can be indicative of possible check-in activity by threat actors.
      CINS)
        abipdb_category="18"
        xarf_category_type="vuln_scanning"
        xarf_category="connection"
        ;; #This category is for signatures that are generated using Collective Intelligence’s IP rules for blocking. For more information see www.cinsscore.com.
      COINMINER)
        abipdb_category="20"
        xarf_category_type="vuln_scanning"
        xarf_category="connection"
        ;; #This category is for signatures with rules that detect malware which performs coin mining. These signatures can also detect some legitimate (though often undesirable) coin mining software. Note: this category is present in Suricata 5.0 and later rulesets. In Suricata older than 5.0 and Snort 2.9 ruleset these signatures are in the Trojan Category ET features over 50 categories which may be assigned to individual signatures. These categories are assigned as signatures are created and updated. To help understand how these category names are selected and attributed to each signature, below is a list of definitions for each category. ET CATEGORY DESCRIPTIONS | TECH BRIEF2
      COMPROMISED)
        abipdb_category="20,18"
        xarf_category_type="vuln_scanning"
        xarf_category="connection"
        ;; #This category is for signatures based on a list of known compromised hosts that is confirmed and updated daily. The signatures in this category can vary from one to several hundred rules depending on the data sources. The data sources for this category comes from several private but highly reliable data sources. Warning: Snort can experience performance issues when handling IP matches. This category can add significant a processing load, particularly if sensors already operating near capacity. In a high-capacity situation like this, we recommend using the Botcc rules instead.
      CURRENT_EVENTS)
        abipdb_category=""
        xarf_category_type="login_attack"
        xarf_category="connection"
        ;; #This category is for signatures with rules developed in response to active and short-lived campaigns and high-profile items that are expected to be temporary. One example is fraud campaigns related to disasters. The rules in this category are ones that are not intended to be kept in in the ruleset for long, or that need to be further tested before they are considered for inclusion. Most often these will be simple sigs for the Storm binary URL of the day, sigs to catch CLSID’s of newly found vulnerable apps where we don’t have any detail on the exploit, etc. Note: In Suricata prior to 5.0 and Snort 2.9 this category includes rules are in the Current Events category in Suricata 5.0 and later.
      DELETED)
        abipdb_category=""
        xarf_category_type="login_attack"
        xarf_category="connection"
        ;; #This category is for signatures removed from the rule set. Note that typically rules are retained in a deactivated state within their respective rule files (starting with a #) but some rules that are duplicates, moved from Pro to Open (and thus need a new SID for the Open rule) or are too problematic to retain are moved to the Deleted category.
      DNS)
        abipdb_category="18"
        xarf_category_type="vuln_scanning"
        xarf_category="connection"
        ;; #This category is for signatures with rules for attacks and vulnerabilities regarding Domain Name Service (DNS). This category is also used for rules related to abuse of DNS such as tunneling.
      DOS)
        abipdb_category="4,18"
        xarf_category_type="ddos"
        xarf_category="connection"
        ;; #This category is for signatures that detect Denial of Service (DoS) attempts. These rules are intended to catch inbound DoS activity, and provide indication of outbound DoS activity.
      Drop) ;; #This category is for signatures to block IP addresses on the Spamhaus DROP (Don’t Route or Peer) list. The rules in this category are updated daily. For more information see www.spamhaus.org.
      Dshield)
        abipdb_category="18"
        xarf_category_type="login_attack"
        xarf_category="connection"
        ;; #This category is for signatures based on attackers identified by Dshield. The rules in this category are updated daily from the DShield top attackers list which is very reliable. For more information see www.dshield.org.
      EXPLOIT)
        abipdb_category="18"
        xarf_category_type="login_attack"
        xarf_category="connection"
        ;; #This category is for signatures that protect against direct exploits not otherwise covered in a specific service category. This is the category where specific attacks against vulnerabilities such as against Microsoft Windows will be found. Attacks with their own category such as SQL injection have their own category.
      EXPLOIT_KIT)
        abipdb_category=""
        xarf_category_type="login_attack"
        xarf_category="connection"
        ;; #This category is for signatures to detect activity related to Exploit Kits their infrastructure, and delivery. Note: this category is present in rulesets for Suricata 5.0 or later. In Suricata prior to 5.0 and Snort 2.9 these rules are in the Current Events category.
      FTP)
        abipdb_category="5,18"
        xarf_category_type="vuln_scanning"
        xarf_category="connection"
        ;; #This category is for signatures related to attacks, exploits, and vulnerabilities regarding File Transfer Protocol (FTP). This category also includes rules that detect non-malicious FTP activity such as logins for logging purposes.
      GAMES)
        abipdb_category=""
        xarf_category_type="login_attack"
        xarf_category="connection"
        ;; #This category is for signatures that identify of gaming traffic and attacks against those games. These rules cover games such as World of Warcraft, Starcraft, and other popular online games. While these games and their traffic are not malicious, they are often unwanted and prohibited by policy on corporate networks.
      HUNTING)
        abipdb_category=""
        xarf_category_type="login_attack"
        xarf_category="connection"
        ;; #This category is for signatures that provide indicators that when matched with other signatures can be very useful for threat hunting in an environment. These rules can provide false positives on legitimate traffic and inhibit performance. They are only recommended for use when actively researching potential threats in the environment. Note: this category is present in rulesets for Suricata 5.0 or later. In Suricata prior to 5.0 and Snort 2.9 these rules are in the Info and Policy categories.
      ICMP)
        abipdb_category="18"
        xarf_category_type="vuln_scanning"
        xarf_category="connection"
        ;; #This category is for signatures related to attacks and vulnerabilities regarding Internet Control Message Protocol (ICMP).
      ICMP_info)
        ;; #This category is for signatures related to ICMP protocol specific events, typically associated with normal operations for logging purposes.
      IMAP)
        abipdb_category="18"
        xarf_category_type="vuln_scanning"
        xarf_category="connection"
        ;; #This category is for signatures related to attacks, exploits, and vulnerabilities regarding Internet Message Access Protocol (IMAP). This category also includes rules that detect non- malicious IMAP activity for logging purposes.
      INAPPROPRIATE)
        abipdb_category=""
        xarf_category_type="login_attack"
        xarf_category="connection"
        ;; #This category is for signatures to identify potentially activity related to sites that are pornographic or otherwise no appropriate for a work environment. Warning: This category can have a significant performance impact and high rate of false positives.
      INFO)
        abipdb_category="19"
        xarf_category_type="login_attack"
        xarf_category="connection"
        ;; #This category is for signatures to help provide audit level events that are useful for correlation and identifying interesting activity which may not be inherently malicious but is often observed in malware and other threats, for example downloading an Executable over HTTP by IP address rather than domain name.
      JA3)
        abipdb_category="19"
        xarf_category_type="login_attack"
        xarf_category="connection"
        ;; #This category is for signatures to fingerprint malicious SSL certificates using JA3 hashes. These rules are based on parameters that are in the SSL handshake negotiation by both clients and servers. These rules can have a high false positive rate but can be very useful for threat hunting or malware detonation environments.
      MALWARE)
        abipdb_category="20"
        xarf_category_type="login_attack"
        xarf_category="connection"
        ;; #This category is for signatures to detect malicious software. Rules in this category detect activity related to malicious software that is detected on the network including malware in transit, active malware, malware infections, malware attacks, and updating of malware. This is also a highly important category and its highly recommended to be run. Note: this category is present in rulesets for Suricata 5.0 or later. In Suricata prior to 5.0 and Snort 2.9 these rules are in the Trojan category.
      MISC)
        abipdb_category="18"
        xarf_category_type="login_attack"
        xarf_category="connection"
        ;; #This category is for signatures not covered in other categories.
      MOBILE_MALWARE)
        abipdb_category="20"
        xarf_category_type="login_attack"
        xarf_category="connection"
        ;; #This category is for signatures that indicate malware that is associated with mobile and tablet operating systems like Google Android, Apple iOS, and others. Malware that is detected and is associated with mobile operating systems will generally be placed in this category rather than the standard categories like Malware.
      NETBIOS)
        abipdb_category="2"
        xarf_category_type="vuln_scanning"
        xarf_category="connection"
        ;; #This category is for signatures related to attacks, exploits, and vulnerabilities regarding NetBIOS. This category also includes rules that detect non-malicious NetBIOS activity for logging purposes.
      P2P) ;; #This category is for signatures for the identification of Peer- to-Peer (P2P) traffic and attacks against it. Identified P2P traffic includes torrents, edonkey, Bittorrent, Gnutella and Limewire among others. P2P traffic is not inherently malicious but is often of notable for enterprises.
      Phishing)
        abipdb_category="7"
        xarf_category_type="login_attack"
        xarf_category="connection"
        ;; #This category is for signatures which detect credential phishing activity. This includes landing pages exhibiting credential phishing as well as successful submission of credentials into credential phishing sites. Note: this category is present in rulesets for Suricata 5.0 or later. In Suricata prior to 5.0 and Snort 2.9 these rules are in the Current Events category.
      Policy) ;; #This category is for signatures that may indicate violations to an organization’s policy. This can include protocols prone to abuse, and other application-level transactions which may be of interest.
      POP3)
        abipdb_category="18,17"
        xarf_category_type="vuln_scanning"
        xarf_category="connection"
        ;; #This category is for signatures related to attacks, exploits, and vulnerabilities regarding Post Office Protocol 3.0 (POP3). This category also includes rules that detect non- malicious POP3 activity for logging purposes.
      RPC) ;; #This category is for signatures related to attacks, exploits, and vulnerabilities regarding Remote Procedure Call (RPC). This category also includes rules that detect non-malicious RPC activity for logging purposes.
      SCADA) ;; #This category is for signatures related to attacks, exploits, and vulnerabilities regarding supervisory control and data acquisition (SCADA). This category also includes rules that detect non-malicious SCADA activity for logging purposes.
      SCADA_special)
        ;; #This category is for signatures written for Snort Digital Bond based SCADA preprocessor.
      SCAN)
        abipdb_category="14"
        xarf_category_type="reconnaissance"
        xarf_category="connection"
        ;; #This category is for signatures to detect reconnaissance and probing from tools such as Nessus, Nikto, and other port scanning, tools. This category can be useful for detecting early breach activity and post-infection lateral movement within an organization.
      SHELLCODE)
        abipdb_category="18,22"
        xarf_category_type="login_attack"
        xarf_category="connection"
        ;; #This category is for signatures for remote shellcode detection. Remote shellcode is used when an attacker wants to target a vulnerable process running on another machine on a local network or intranet. If successfully executed, the shellcode can provide the attacker access to the target machine across the network. Remote shellcodes normally use standard TCP/IP socket connections to allow the attacker access to the shell on the target machine. Such shellcode can be categorized based on how this connection is set up: if the shellcode can establish this connection, it is called a “reverse shell” or a connect- back shellcode because the shellcode connects back to the attacker’s machine.
      SMTP)
        abipdb_category="18,11"
        xarf_category_type="vuln_scanning"
        xarf_category="connection"
        ;; #This category is for signatures related to attacks, exploits, and vulnerabilities regarding Simple Mail Transfer Protocol (SMTP). This category also includes rules that detect non-malicious SMTP activity for logging purposes.
      SNMP) ;; #This category is for signatures related to attacks, exploits, and vulnerabilities regarding Simple Network Management Protocol (SNMP). This category also includes rules that detect non-malicious SNMP activity for logging purposes.
      SQL)
        abipdb_category="16,18"
        xarf_category_type="vuln_scanning"
        xarf_category="connection"
        ;; #This category is for signatures related to attacks, exploits, and vulnerabilities regarding Structured Query Language (SQL). This category also includes rules that detect non-malicious SQL activity for logging purposes.
      TELNET)
        abipdb_category="14,18"
        xarf_category_type="vuln_scanning"
        xarf_category="connection"
        ;; #This category is for signatures related to attacks, exploits, and vulnerabilities regarding TELNET. This category also includes rules that detect non-malicious TELNET activity for logging purposes.
      TFTP)
        abipdb_category="5,18"
        xarf_category_type="vuln_scanning"
        xarf_category="connection"
        ;; #This category is for signatures related to attacks, exploits, and vulnerabilities regarding Trivial File Transport Protocol (TFTP). This category also includes rules that detect non- malicious TFTP activity for logging purposes.
      TOR)
        abipdb_category="9,18"
        xarf_category_type="login_attack"
        xarf_category="connection"
        ;; #This category is for signatures for the identification of traffic to and from TOR exit nodes based on IP address.
      Trojan)
        abipdb_category="20"
        xarf_category_type="login_attack"
        xarf_category="connection"
        ;; #This is a legacy category that is not used in Suricata 5.0 and later. In Suricata 5.0 and later this category is replaced with the Malware category. Members of the Trojan category are included in the Malware category in Suricata 5.0 and later. In Suricata prior to 5.0 and Snort 2.9 the rules in this category detect activity related to malicious software that is detected on the network including malware in transit, active malware, malware infections, malware attacks, and updating of malware.
      USER_AGENTS)
        abipdb_category="19"
        xarf_category_type="vuln_scanning"
        xarf_category="connection"
        ;; #This category is for signatures to detect suspicious and anomalous user agents. Known malicious user agents are generally placed in the Malware category.
      VOIP) ;; #This category is for signatures for attacks and vulnerabilities regarding Voice over IP (VOIP) including SIP, H.323 and RTP among others.
      WEB_CLIENT)
        abipdb_category="21"
        xarf_category_type="vuln_scanning"
        xarf_category="connection"
        ;; #This category is for signatures for attacks and vulnerabilities regarding web clients such as web browsers as well as client side applications like CURL, WGET and others.
      WEB_SERVER)
        abipdb_category="21"
        xarf_category_type="login_attack"
        xarf_category="connection"
        ;; #This category is for signatures to detect attacks against web server infrastructure such as APACHE, TOMCAT, NGINX, Microsoft Internet Information Services (IIS) and other web server software.
      WEB_SPECIFIC_APPS)
        abipdb_category="21"
        xarf_category_type="vuln_scanning"
        xarf_category="connection"
        ;; #This category is for signatures to detect attacks and vulnerabilities in specific web applications.
      WORM)
        abipdb_category="20"
        xarf_category_type="malware"
        xarf_category="content"
        ;; #This category is for signatures to detect malicious activity that automatically attempts to spread across the internet or within a network by exploiting a vulnerability are classified as the WORM category. While the actual exploit itself will typically be identified in the Exploit or given protocol category, an additional entry in this category may be made if the actual malware engaging in worm-like propagation can be identified as well.
        # Source: https://tools.emergingthreats.net/docs/ETPro%20Rule%20Categories.pdf
      *) abipdb_category="18"
        xarf_category_type="login_attack"
        xarf_category="connection" ;;
    esac
    # }

    # Function to convert category codes to names
    # convert_category_to_names() {
    #   local abipdb_category=$1
    #   abipdb_category=$(echo $abipdb_category | sed 's/1/DNS Compromise/g')
    #   abipdb_category=$(echo $abipdb_category | sed 's/2/DNS Poisoning/g')
    #   abipdb_category=$(echo $abipdb_category | sed 's/4/DDoS Attack/g')
    #   abipdb_category=$(echo $abipdb_category | sed 's/5/FTP/g')
    #   abipdb_category=$(echo $abipdb_category | sed 's/6/Ping of Death/g')
    #   abipdb_category=$(echo $abipdb_category | sed 's/7/Phishing/g')
    #   abipdb_category=$(echo $abipdb_category | sed 's/10/Web Spam/g')
    #   abipdb_category=$(echo $abipdb_category | sed 's/11/Email Spam/g')
    #   abipdb_category=$(echo $abipdb_category | sed 's/12/Blog Spam/g')
    #   abipdb_category=$(echo $abipdb_category | sed 's/14/Port Scan/g')
    #   abipdb_category=$(echo $abipdb_category | sed 's/15/Hacking/g')
    #   abipdb_category=$(echo $abipdb_category | sed 's/16/SQL Injection/g')
    #   abipdb_category=$(echo $abipdb_category | sed 's/17/Spoofing/g')
    #   abipdb_category=$(echo $abipdb_category | sed 's/18/Brute-Force/g')
    #   abipdb_category=$(echo $abipdb_category | sed 's/19/Bad Web Bot/g')
    #   abipdb_category=$(echo $abipdb_category | sed 's/20/Exploited Host/g')
    #   abipdb_category=$(echo $abipdb_category | sed 's/21/Web App Attack/g')
    #   abipdb_category=$(echo $abipdb_category | sed 's/22/SSH/g')
    #   echo $abipdb_category
    # }

    #timestamp=$(date -d "$timestamp" +"%Y-%m-%d %H:%M:%S")
    # timestamp=$(date -f %s "$(date)" +"%Y-%m-%d %H:%M:%S")
    #
    timestamp=$(date +%s)
    datetime=$(date '+%Y-%m-%d %H:%M:%S')
    abuseipdb_report_time=$(date +"%Y-%m-%dT%H:%M:%S%z")

    # Function to log operations to the log file
    log_operation() {
      local message=$1
      # echo "$message"
      echo "$datetime - $message" >> $block_log_file
    }

    pf_notify() {
      # Fire a pfSense notification (all configured channels), throttled to
      # one per hour to avoid spam during alert storms.
      local message=$1
      [ "${notifications}" == "yes" ] || return 0
      local throttle_file="/var/db/pfsense_abuseipdb_notify.last"
      local now_epoch last_epoch
      now_epoch=$(date +%s)
      last_epoch=0
      [ -r "${throttle_file}" ] && last_epoch=$(< "${throttle_file}")
      if [ "$((now_epoch - last_epoch))" -lt 3600 ]; then
        return 0
      fi
      echo "${now_epoch}" > "${throttle_file}"
      message=${message//\'/}
      message=${message//\"/}
      /usr/local/bin/php -r "require_once('/etc/inc/notices.inc'); notify_all_remote('${message}');" >/dev/null 2>&1 || true
      log_operation "Notification sent: ${message}"
    }

    if [ "${use_mysql}" == "yes" ]
    then
      # mysqli_query_count
      # if [ $? -eq 0 ]; then
      mysql_report_count=$(mysqli_query_count 2>/dev/null | grep "[0-9]" || true)
      if [ "${mysql_report_count:-0}" -gt 0 ]
      then
        echo "IP has been logged ${mysql_report_count} times in the MySQL database ${mysql_database}"
      else
        echo "IP has not been logged in the MySQL database ${mysql_database}"
      fi
    fi
    if grep -qF "${ip}" "${block_log_file}" 2>/dev/null
    then
      # Count the number of distributed attacks
      block_log_count=$(grep -cF "${ip}" "${block_log_file}" || true)
      echo "IP has been logged ${block_log_count} times in the ${block_log_file}"
      ip_block_logged="yes"
    else
      echo "IP has not been logged in the ${block_log_file}"
      ip_block_logged="no"
      block_log_count=0
    fi

    # Debug output for tracing
    # category=$(determine_category $signature_category "$message")
    # category_names=$(convert_category_to_names "$abipdb_category")
    log_operation "Trigger: ${signature_category}, Category: ${category}"

    if [ "$ip_block_logged" = "yes" ]; then
      if [ "${block_log_count:-0}" -gt "${report_limit}" ]; then
        # Skip if the IP was already reported within the cooldown window
        if [ "${report_cooldown:-900}" -gt 0 ]; then
          last_reported=$(grep "Reporting IP: ${ip} with comment" "${block_log_file}" 2>/dev/null | tail -n 1 | awk '{print $1, $2}') || true
          if [ -n "${last_reported}" ]; then
            last_reported_epoch=$(date -j -f "%Y-%m-%d %H:%M:%S" "${last_reported}" +%s 2>/dev/null || date -d "${last_reported}" +%s 2>/dev/null || echo 0)
            now_epoch=$(date +%s)
            if [ "${last_reported_epoch:-0}" -gt 0 ] && [ "$((now_epoch - last_reported_epoch))" -lt "${report_cooldown:-900}" ]; then
              echo "IP ${ip} was reported $((now_epoch - last_reported_epoch)) seconds ago, cooldown is ${report_cooldown:-900} seconds. Skipping..."
              continue
            fi
          fi
        fi
        #   # Extract relevant logs for the current IP
        #   ip_logs=$(cat "$block_log_file" | grep "$ip")
        #   # Construct the comment string for
        #   comment="Detected $block_log_count attacks from $ip.; Logs: $(echo "$ip_logs" | tr '\n' ' ')"
        # else
        # Extract relevant logs for the current IP (last 10 MB is plenty of
        # fresh evidence and keeps X-ARF payloads sane)
        # Full-file evidence grep (X-ARF payload); reports are rare after the
        # cooldown, so the scan cost is acceptable
        logs=$(grep -F "${ip}" "${ALERTS_FILE}" 2>/dev/null || true)
        # Construct the comment string for other triggers
        comment="Suricata Detected ${block_log_count} attacks from $ip.; ${message}; IP: ${ip}; Ports: ${ports}; Direction: ${direction}; Trigger: ${signature_category}; Category: ${category}; Severity: ${severity}"

        ABUSEIPDB_CHECK=$(curl -sG https://api.abuseipdb.com/api/v2/check \
            --data-urlencode "ipAddress=$ip" \
            -d maxAgeInDays=90 \
            -d verbose \
            -H "Key: $ABUSEIPDB_TOKEN" \
          -H "Accept: application/json")

        abuseipdb_confidence_score=$(echo "${ABUSEIPDB_CHECK}" | jq -r '.data.abuseConfidenceScore // 0' || true)

        if [ "${abuseipdb_confidence_score:-0}" -gt "${abuseipdb_confidense_score_limit}" ]; then
          echo "AbuseIPDB Confidence Score ${abuseipdb_confidence_score} is greater than limit ${abuseipdb_confidense_score_limit} past 90 days..."
          echo "Sending a new report to AbuseIPDB"
        else
          echo "AbuseIPDB Confidence Score ${abuseipdb_confidence_score} is lower than limit ${abuseipdb_confidense_score_limit}..."
          echo "Not sending report to AbuseIPDB."
          continue
        fi
        abuseipdb_is_whitelisted=$(echo "${ABUSEIPDB_CHECK}" | jq -r '.data.isWhitelisted')

        if [ "${abuseipdb_is_whitelisted}" == "true" ]; then
          echo "IP is whitelisted on AbuseIPDB, sending report anyways..."
        fi
        # If not reported today, send a new report
        # mysql_latest_report_datetime=$(mysqli_query_datetime | tail -n 1)
        # mysql_latest_report_datetime=$(date -d "+15 minutes $mysql_latest_report_datetime" '+%Y-%m-%d %H:%M:%S')
        # echo $ABUSEIPDB_CHECK | jq -r '.data.reports[] | select(.reporterId == 1)'

        # reporterId=$(echo "${ABUSEIPDB_CHECK}" | jq -r '.data.reports[].reporterId')
        # reportedAt=$(echo "${ABUSEIPDB_CHECK}" | jq -r '.data.reports[].reportedAt')
        # # reportedAt_timestamp=$(date -d "$reportedAt" +"%s")
        # reportedAt_timestamp=$(date -f %s "$reportedAt" +"%s")
        #
        # if ((reportedAt_timestamp + timestamp > 900 ))
        # then
        #   echo "Less than 15 minutes has passed since $ip was reported..."
        #   continue
        # else
        #   echo "More than 15 minutes has passed since $ip was reported..."
        # fi

        # if ! [ "$reporterId" = $abuseipdb_user_id ]
        # then
        log_operation "Reporting IP: ${ip} with comment: ${comment}"

        # Include the most recent alert line before the credit, keeping the
        # AbuseIPDB 1024-char limit
        report_credit="Reported by pfsense-abuseipdb: https://github.com/tmiland/pfsense-abuseipdb"
        max_comment=$((1024 - ${#report_credit} - 1))
        if [ -n "${logs}" ]; then
          last_log=$(printf '%s\n' "${logs}" | tail -n 1)
          logs_budget=$((max_comment - ${#comment} - 8))
          if [ ${logs_budget} -gt 40 ]; then
            logs_start=$(( ${#last_log} > logs_budget ? ${#last_log} - logs_budget : 0 ))
            comment="${comment}; Logs: ${last_log:${logs_start}}"
          fi
        fi
        if [[ ${#comment} -gt ${max_comment} ]]; then
          log_operation "Truncated comment to ${max_comment} characters..."
          comment=${comment:0:max_comment}
        fi
        comment="${comment} ${report_credit}"

        # Send report
        ABUSEIPDB_RESPONSE=$(curl -s https://api.abuseipdb.com/api/v2/report \
            --data-urlencode "ip=${ip}" \
            -d categories="${abipdb_category}" \
            --data-urlencode "comment=${comment}" \
            --data-urlencode "${abuseipdb_report_time}" \
            -H "Key: ${ABUSEIPDB_TOKEN}" \
          -H "Accept: application/json")

        errors=$(echo "${ABUSEIPDB_RESPONSE}" | grep "errors" || true)
        if [ -n "$errors" ]; then
          ABUSEIPDB_STATUS=$(echo "${ABUSEIPDB_RESPONSE}" \
              | jq -r '.errors[]' \
            | jq '.status')
          ABUSEIPDB_DETAIL=$(echo "${ABUSEIPDB_RESPONSE}" \
            | jq -r '.errors[]' | jq '.detail')
          echo "ERROR! Something went wrong."
          echo "Status: ${ABUSEIPDB_STATUS}"
          echo "Message: ${ABUSEIPDB_DETAIL}"
          log_operation "ERROR! Something went wrong. Status: ${ABUSEIPDB_STATUS} Message: ${ABUSEIPDB_DETAIL}"
          pf_notify "pfsense-abuseipdb: AbuseIPDB report error for ${ip}. Status: ${ABUSEIPDB_STATUS} Message: ${ABUSEIPDB_DETAIL}"
          continue
        else
          # Parse and log the ABUSEIPDB_RESPONSE
          ABUSEIPDB_CONFIDENCE_SCORE=$(echo "${ABUSEIPDB_RESPONSE}" | jq -r '.data.abuseConfidenceScore')
          log_operation "AbuseIPDB Categories: ${abipdb_category}"
          if [ -n "${ABUSEIPDB_CONFIDENCE_SCORE}" ]; then
            log_operation "AbuseIPDB Confidence Score: ${ABUSEIPDB_CONFIDENCE_SCORE}"
          else
            log_operation "AbuseIPDB Confidence Score: Not Available"
          fi
          log_operation "Response: ${ABUSEIPDB_RESPONSE}"
          # else
          #   echo "Already Reported..."
          # fi
          if [[ ${ABUSEIPDB_RESPONSE} == *"You can only report the same IP address once in 15 minutes."* ]]; then
            echo "Status: $(echo "${ABUSEIPDB_RESPONSE}" | jq -r '.status')"
            echo "Message: $(echo "${ABUSEIPDB_RESPONSE}" | jq -r '.detail')"
            continue
          else
            # Add ip to mysql database
            if [ "${use_mysql}" == "yes" ]; then
              if mysql_query; then
                echo "IP ${ip} successfully added to MySql Database ${mysql_host}"
              else
                echo "Failed to add IP ${ip} to MySql Database"
              fi
            fi
            if [ "${send_abuse_email_report}" == "yes" ]; then
              if [ "${block_log_count:-0}" -gt "${email_report_limit}" ]; then
                if ! [ "$whois_contact_email" = "" ]; then
                  # for whois_contact_emails in ${whois_contact_email[@]}; do
                  email_tmp=$(mktemp) || { echo "Failed to create temp file"; exit 1; }
                  trap 'rm -rf -- "$email_tmp"' EXIT
# @formatter:off
echo "From: ${report_name} <${report_email}>
To: abuse <${whois_contact_email}>
Subject: Abuse IP Report for ${ip}
Date: $(date)

Dear Mr Receiver.

I am writing to inform you of abuse from IP ${ip} originating from your network.

Log: ${signature}

Category: ${category}

The IP has been reported to AbuseIPDB.

Comment: ${comment}

AbuseIPDB Confidence Score: ${ABUSEIPDB_CONFIDENCE_SCORE}

Link: https://www.abuseipdb.com/check/${ip}

Conditions for detection:

- AbuseIPDB Confidence Score ${abuseipdb_confidence_score} is higher than limit ${abuseipdb_confidense_score_limit}
- IP has been logged ${block_log_count} times, and is higher than email report limit ${email_report_limit}

Software: Suricata on pfsense

This report is sendt to the abuse email provided in the WHOIS information provided on the reported IP address.

These emails are automated and will stop when the attacks coming from your network ceases.

----
Best regards,
${report_email}" | tee "${email_tmp}" >/dev/null 2>&1
# @formatter:on
                  if curl -s --ssl-reqd \
                    --url "smtps://${report_smtp_host}:${report_smtp_port}" \
                    --user "${report_email}":"${ABUSEIP_EMAIL_PASS}" \
                    --mail-from "${report_email}" \
                    --mail-rcpt "${whois_contact_email}" \
                    --upload-file "${email_tmp}"; then
                    echo "IP ${ip} successfully reported to ${whois_contact_email}"
                  else
                    echo "Failed to report IP ${ip} to ${whois_contact_email}"
                  fi
                fi
              fi
            fi
          fi
          if [ $? -eq 0 ]; then
            echo "IP ${ip} successfully reported to AbuseIPDB"
          else
            echo "Failed to report IP ${ip} to AbuseIPDB"
          fi
          if [ "${send_xarf_report}" = "yes" ]; then
            # Set the URL you want to make the POST request to
            xarf_url="https://datachannels.abusix.com/data/xarf"

            xarf_date=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
            xarf_uuid=$(uuidgen)
            # get evidence from log
            # xarf_evidence_source=$(echo "$message" | grep -Po "\([^U]*\)" | tr -d '(|)')
            xarf_content_type="message/rfc822"
            # tempfile
            xarf_temp_file=$(mktemp) || { echo "Failed to create temp file"; exit 1; }
            trap 'rm -rf -- "$xarf_temp_file"' EXIT

            # Payload
            xarf_payload=$(echo -n "$logs" | base64 -w 0)

            # Set the data you want to send in the POST request
            xarf_data=$(printf '{
              "xarf_version": "4.0.0",
              "report_id": "%s",
              "timestamp": "%s",
              "reporter": {
                "org": "%s",
                "contact": "%s",
                "domain": "%s"
              },
              "sender": {
                "org": "%s",
                "contact": "%s",
                "domain": "%s"
              },
              "source_identifier": "%s",
              "category": "%s",
              "type": "%s",
              "source_port": %s,
              "evidence": [
                {
                  "content_type": "%s",
                  "description": "%s",
                  "payload": "%s"
                }
              ]
            }' "$xarf_uuid" "$xarf_date" "$xarf_org" \
            "$xarf_contact" "$xarf_domain" "$xarf_org" \
            "$xarf_contact" "$xarf_domain" "$ip" "$xarf_category" \
            "$xarf_category_type" "$ports" \
            "$xarf_content_type" "$message" "$xarf_payload")

            # Save to file
            echo -n "$xarf_data" > "$xarf_temp_file"
            # Test if json is valid
            # Source: https://github.com/jqlang/jq/issues/1637#issuecomment-693469750
            if jq empty "$xarf_temp_file"; then
              log_operation "JSON is valid"
              # Make the POST request using curl
              log_operation "Sending X-ARF report to abusix.com"
              xarf_response=$(curl -s \
                  -H "Content-Type: application/json" \
                  -H "x-api-key: $xarf_token" \
                -d @"$xarf_temp_file" "$xarf_url") || true
                rm -rf "$xarf_temp_file"
              log_operation "X-ARF Response: $xarf_response"
            else
              log_operation "JSON is invalid"
              pf_notify "pfsense-abuseipdb: X-ARF report JSON invalid for ${ip}"
            fi
          fi
        fi
      else
        echo "IP has only been logged ${block_log_count} time, and will not be reported until it has been logged ${report_limit} times."
      fi
    fi
    # sleep 3
  fi
done

# tail -fn0 "$filter_log" \
  #   | grep -F --line-buffered 'pfsense filterlog' \
  #   | while read -r line; do
#   filter_log() {
#     echo "$line" | awk -F ',' '{print $'"$1"'}'
#   }
#   id=$(filter_log 4)
#   ip=$(filter_log 19)
#   ports=$(filter_log 21)
#   iface=$(filter_log 5)
#   # permanent=$(filter_log 21)
#   # proto=$(cat /var/log/filter.log | awk -F ',' '{print $17}' | tail -n 1)
#   direction=$(filter_log 8)
#   # timeout=$(filter_log 21)
#   # msg=$(filter_log 21)
#   # log=$(filter_log 21)
#   trigger=$(filter_log 17)
#
#   # Get firewall rules
#   FIREWAL_RULES=$(curl -ks -X 'GET' \
  #       "$PFSENSE_URL/api/v2/firewall/rules" \
  #       -H 'accept: application/json' \
  #       -H "X-API-Key: $PFSENSE_TOKEN" \
  #     | jq -r '.data[]' | jq -r '. | select(.tracker == '"$id"')')
#
#   id=$(echo "$FIREWAL_RULES" | jq -r '.id')
#   descr=$(echo "$FIREWAL_RULES" | jq -r '.descr')
#   if [ "$iface" = $wan ]; then
#     echo "ip: $ip port: $ports direction: $direction description: $descr protocol: $trigger";
#   fi
# done
