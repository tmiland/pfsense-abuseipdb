#!/usr/bin/env bash
#
# pfsense_abuseipdb_protect.sh - native DDoS protection engine.
# Counts blocked packets (pf filter.log) or Suricata alerts per source IP
# within a sliding window and adds offenders to the pf table
# "abuseipdb_block" (referenced by a pfSense floating block rule) with an
# automatic expiry. Runs as a separate daemon next to the watcher.

set -o errexit
set -o pipefail
set -o nounset

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
config_file="${SCRIPT_DIR}/../etc/pfsense_abuseipdb.ini"
if [[ ! -f "$config_file" ]]; then
  config_file="${SCRIPT_DIR}/pfsense_abuseipdb.ini"
fi

config_grep() {
  sed -n "s/^$1=//p" "$config_file"
}

config_secret() {
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

PFSENSE_TOKEN=$(config_secret pfsense_token pfsense_token_file)
# shellcheck disable=SC2034
PFSENSE_URL=$(config_grep pfsense_url)
block_log_file=$(config_grep block_log_file)
wan=$(config_grep wan)
protection=$(config_grep protection)
detection_source=$(config_grep detection_source)
protection_threshold=$(config_grep protection_threshold)
protection_window=$(config_grep protection_window)
ban_time=$(config_grep ban_time)
max_table_entries=$(config_grep max_table_entries)

if [ "${protection}" != "yes" ]; then
  echo "Protection is disabled in the ini. Exiting."
  exit 0
fi

detection_source=${detection_source:-pf}
protection_threshold=${protection_threshold:-50}
protection_window=${protection_window:-60}
ban_time=${ban_time:-86400}
max_table_entries=${max_table_entries:-2000}

wan_ip=$(ifconfig "${wan}" 2>/dev/null | grep 'inet ' | awk '{print $2}') || true

declare -A hits blocked_until

log_operation() {
  local message=$1
  echo "$(date '+%Y-%m-%d %H:%M:%S') - [protect] $message" >> "${block_log_file}"
}

state_file="/var/db/pfsense_abuseipdb_blocks.list"

table_count() {
  pfctl -t abuseipdb_block -T show 2>/dev/null | grep -c . || true
}

table_add() {
  local ip=$1
  local count
  count=$(table_count)
  if [ "${count}" -ge "${max_table_entries}" ]; then
    log_operation "Block table is full (${count}/${max_table_entries}) - refusing to add ${ip}"
    return 1
  fi
  pfctl -t abuseipdb_block -T add "${ip}" expire "${ban_time}" >/dev/null 2>&1 || true
  echo "${ip} $(( $(date +%s) + ban_time ))" >> "${state_file}"
  log_operation "PROTECTED: banned ${ip} for ${ban_time}s (burst >= ${protection_threshold} in ${protection_window}s)"
}

is_private() {
  local ip=$1
  [[ "${ip}" =~ ^10\. ]] && return 0
  [[ "${ip}" =~ ^192\.168\. ]] && return 0
  [[ "${ip}" =~ ^127\. ]] && return 0
  [[ "${ip}" =~ ^169\.254\. ]] && return 0
  [[ "${ip}" =~ ^172\.(1[6-9]|2[0-9]|3[01])\. ]] && return 0
  [[ "${ip}" =~ ^100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\. ]] && return 0
  return 1
}

is_whitelisted() {
  local ip=$1 table
  IFS="," read -ra whitelists <<< "$(config_grep suricata_whitelists)"
  for table in "${whitelists[@]}"; do
    if pfctl -t "${table}" -T test "${ip}" >/dev/null 2>&1; then
      return 0
    fi
  done
  return 1
}

count_hit() {
  local ip=$1 now_epoch
  now_epoch=$(date +%s)
  if [ -n "${wan_ip}" ] && [ "${ip}" == "${wan_ip}" ]; then
    return 0
  fi
  if is_private "${ip}"; then
    return 0
  fi
  if [ -n "${blocked_until[${ip}]:-}" ] && [ "${now_epoch}" -lt "${blocked_until[${ip}]}" ]; then
    return 0
  fi
  local start_epoch
  start_epoch=${hits[${ip}]:-0}
  start_epoch=${start_epoch%%|*}
  local count
  count=${hits[${ip}]:-0}
  count=${count#*|}
  if [ -z "${count}" ] || [ $((now_epoch - start_epoch)) -ge ${protection_window} ]; then
    hits[${ip}]="1|${now_epoch}"
    return 0
  fi
  count=$((count + 1))
  hits[${ip}]="$(printf '%s|%s' "${count}" "${start_epoch}")"
  if [ "${count}" -ge "${protection_threshold}" ]; then
    if is_whitelisted "${ip}"; then
      log_operation "PROTECTED: ${ip} hit the burst threshold but is whitelisted - not banning"
      hits[${ip}]="0|${now_epoch}"
      return 0
    fi
    if table_add "${ip}"; then
      blocked_until[${ip}]=$((now_epoch + ban_time))
    fi
    hits[${ip}]="0|${now_epoch}"
  fi
}

# Re-add active bans from the state file (they would be lost after a filter
# reload or reboot otherwise) and prune expired entries.
if [ -f "${state_file}" ]; then
  now_epoch=$(date +%s)
  : > "${state_file}.new"
  while read -r ip expiry; do
    [ -n "${ip}" ] || continue
    if [ "${expiry}" -gt "${now_epoch}" ]; then
      pfctl -t abuseipdb_block -T add "${ip}" expire "$((expiry - now_epoch))" >/dev/null 2>&1 || true
      echo "${ip} ${expiry}" >> "${state_file}.new"
    fi
  done < "${state_file}"
  mv "${state_file}.new" "${state_file}"
fi

IFS="," read -ra suricata_whitelists <<< "$(config_grep suricata_whitelists)"

if [ "${detection_source}" == "suricata" ]; then
  ALERTS_FILE=$(config_grep alerts_file)
  log_operation "Protection engine started (source: suricata, ${protection_threshold} alerts/${protection_window}s, ban ${ban_time}s)"
  tail -n0 -F "${ALERTS_FILE}" 2>/dev/null | while read -r line; do
    src_ip=$(jq -r '.src_ip // empty' <<< "${line}" 2>/dev/null) || true
    [ -n "${src_ip}" ] && count_hit "${src_ip}"
  done
else
  log_operation "Protection engine started (source: pf, ${protection_threshold} blocks/${protection_window}s, ban ${ban_time}s)"
  tail -n0 -F /var/log/filter.log 2>/dev/null | while read -r line; do
    [[ "${line}" == *filterlog* ]] || continue
    data=${line#*filterlog*: }
    IFS="," read -r _f1 _f2 _f3 _f4 _f5 _f6 action direction ipver _f9 _f10 _f11 _f12 _f13 _f14 _f15 _f16 _f17 _f18 src_ip _rest <<< "${data}"
    [ "${action}" == "block" ] || continue
    [ "${direction}" == "in" ] || continue
    [ "${ipver}" == "4" ] || continue
    count_hit "${src_ip}"
  done
fi
