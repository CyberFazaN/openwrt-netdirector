#!/bin/sh
set -eu

PROGRAM_NAME="netdirector"
PROGRAM_VERSION="1.0.1"
PROGRAM_AUTHOR="FazaN CyberSec <fazan@nullbyte.pro>"

RULE_FILE="/etc/nftables.d/90-netdirector.nft"
PROFILE_DIR="/etc/netdirector/profiles"

CHAIN_PRE="netdirector_prerouting"
CHAIN_POST="netdirector_postrouting"

SET_IFACES="netdirector_ifaces"
SET_CLIENTS_V4="netdirector_clients_v4"
SET_LOCAL_V4="netdirector_local_v4"
SET_LOCAL_V6="netdirector_local_v6"

LOCAL_V4_ELEMENTS='
0.0.0.0/8
10.0.0.0/8
100.64.0.0/10
127.0.0.0/8
169.254.0.0/16
172.16.0.0/12
192.168.0.0/16
224.0.0.0/4
240.0.0.0/4
'

LOCAL_V6_ELEMENTS='
::1/128
fe80::/10
fc00::/7
ff00::/8
'

PROFILE_NAME=""
PROFILE_DESC=""

INTERCEPT_IP4=""
INTERCEPT_PORT=""

DNS_IP4=""
DNS_PORT=""

IFACES=""
CLIENTS=""

FORWARD_HTTP="1"
FORWARD_HTTPS="1"
FORWARD_DNS="0"

QUIC_MODE="ignore"
IPV6_MODE="ignore"

VERBOSE="0"

COMMAND=""
TEMP_FILE=""

CLI_PROFILE_NAME=""
CLI_INTERCEPT_IP4=""
CLI_INTERCEPT_PORT=""
CLI_DNS_IP4=""
CLI_DNS_PORT=""
CLI_IFACES=""
CLI_CLIENTS=""
CLI_FORWARD_HTTP=""
CLI_FORWARD_HTTPS=""
CLI_FORWARD_DNS=""
CLI_QUIC_MODE=""
CLI_IPV6_MODE=""
CLI_VERBOSE=""
CLI_PROFILE_SAVE_NAME=""

print_usage() {
    cat <<EOF
Usage:
  $PROGRAM_NAME <command> [options]

Commands:
  on
  off
  status
  print
  check
  save-profile <name>
  load-profile <name>
  list-profiles
  delete-profile <name>
  show-profile <name>
  help

Run '$PROGRAM_NAME help' for more information.
EOF
}

print_help() {
    cat <<EOF
$PROGRAM_NAME $PROGRAM_VERSION
$PROGRAM_AUTHOR

Manage nftables/fw4 interception rules on OpenWrt.

Usage:
  $PROGRAM_NAME <command> [options]

Commands:
  on                     Generate rules, write managed file, and reload fw4
  off                    Remove managed rules and reload fw4
  status                 Show managed file and runtime chain status
  print                  Print generated nftables fragment to stdout
  check                  Validate configuration without applying it
  save-profile <name>    Save effective configuration as a profile
  load-profile <name>    Load a profile and apply it
  list-profiles          List available profiles
  delete-profile <name>  Delete a profile
  show-profile <name>    Show raw profile contents
  help                   Show this help

Options:
  --profile <name>           Load profile before applying CLI overrides
  --intercept-ip <ipv4>      Interception host IPv4 address
  --intercept-port <port>    Interception host port
  --dns-ip <ipv4>            DNS server IPv4 address
  --dns-port <port>          DNS server port
  --iface <ifname>           Interface to match, may be used multiple times
  --client <ipv4>            Client IPv4 to match, may be used multiple times
  --http on|off              Enable or disable HTTP interception
  --https on|off             Enable or disable HTTPS interception
  --dns on|off               Enable or disable DNS interception
  --quic ignore|block        UDP/443 handling mode
  --ipv6 ignore|block        IPv6 handling mode
  --verbose                  Enable verbose output
  -h, --help                 Show help
  --version                  Show version

Examples:
  $PROGRAM_NAME on \\
    --intercept-ip 192.168.30.2 \\
    --intercept-port 8080 \\
    --dns on \\
    --dns-ip 192.168.30.2 \\
    --dns-port 53 \\
    --iface br-lan \\
    --quic block \\
    --ipv6 block

  $PROGRAM_NAME on \\
    --intercept-ip 192.168.30.2 \\
    --intercept-port 8080 \\
    --https off \\
    --dns on \\
    --dns-ip 192.168.30.2 \\
    --dns-port 53 \\
    --iface br-lan \\
    --client 192.168.30.101

  $PROGRAM_NAME save-profile burp-laptop \\
    --intercept-ip 192.168.30.2 \\
    --intercept-port 8080 \\
    --dns on \\
    --dns-ip 192.168.30.2 \\
    --dns-port 53 \\
    --iface br-lan \\
    --client 192.168.30.101 \\
    --ipv6 block
EOF
}

log_info() {
    printf '%s\n' "$*"
}

log_warn() {
    printf 'WARNING: %s\n' "$*" >&2
}

log_error() {
    printf 'ERROR: %s\n' "$*" >&2
}

die() {
    log_error "$*"
    exit 1
}

usage_error() {
    log_error "$*"
    printf '\n' >&2
    print_usage >&2
    exit 2
}

require_root() {
    if [ "$(id -u)" != "0" ]; then
        die "This command must be run as root."
    fi
}

ensure_profile_dir() {
    if [ ! -d "$PROFILE_DIR" ]; then
        mkdir -p "$PROFILE_DIR" || die "Failed to create profile directory: $PROFILE_DIR"
    fi
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

require_commands() {
    required_commands="fw4 nft mktemp grep sed sort uniq mv rm cat mkdir id tr basename dirname"

    for cmd in $required_commands; do
        if ! command_exists "$cmd"; then
            die "Required command not found: $cmd"
        fi
    done
}

safe_profile_name() {
    case "$1" in
        ""|*[!A-Za-z0-9._-]*)
            return 1
            ;;
        *)
            return 0
            ;;
    esac
}

bool_to_int() {
    case "$1" in
        1|on|true|yes)
            printf '1\n'
            ;;
        0|off|false|no)
            printf '0\n'
            ;;
        *)
            return 1
            ;;
    esac
}

normalize_word_list() {
    printf '%s\n' "$1" | tr ' ' '\n' | grep -v '^$' | sort -u | tr '\n' ' ' | sed 's/[[:space:]]*$//'
}

append_word() {
    list="$1"
    word="$2"

    if [ -z "$list" ]; then
        printf '%s\n' "$word"
    else
        printf '%s %s\n' "$list" "$word"
    fi
}

normalize_ifaces() {
    IFACES="$(normalize_word_list "$IFACES")"
}

normalize_clients() {
    CLIENTS="$(normalize_word_list "$CLIENTS")"
}

normalize_flags() {
    FORWARD_HTTP="$(bool_to_int "$FORWARD_HTTP")" || die "Invalid value for HTTP flag"
    FORWARD_HTTPS="$(bool_to_int "$FORWARD_HTTPS")" || die "Invalid value for HTTPS flag"
    FORWARD_DNS="$(bool_to_int "$FORWARD_DNS")" || die "Invalid value for DNS flag"
}

normalize_config() {
    normalize_ifaces
    normalize_clients
    normalize_flags

    case "$IPV6_MODE" in
        ignore|block)
            ;;
        *)
            die "Invalid IPV6_MODE: $IPV6_MODE"
            ;;
    esac
    case "$QUIC_MODE" in
        ignore|block)
            ;;
        *)
            die "Invalid QUIC_MODE: $QUIC_MODE"
            ;;
    esac
}

validate_ipv4() {
    ip="$1"

    printf '%s\n' "$ip" | grep -E -q '^([0-9]{1,3}\.){3}[0-9]{1,3}$' || return 1

    old_ifs=$IFS
    IFS='.'
    octet1=${ip%%.*}
    rest=${ip#*.}
    octet2=${rest%%.*}
    rest=${rest#*.}
    octet3=${rest%%.*}
    octet4=${rest#*.}
    IFS=$old_ifs

    for octet in "$octet1" "$octet2" "$octet3" "$octet4"; do
        [ "$octet" -ge 0 ] && [ "$octet" -le 255 ] || return 1
    done

    return 0
}

validate_port() {
    port="$1"

    case "$port" in
        ''|*[!0-9]*)
            return 1
            ;;
    esac

    [ "$port" -ge 1 ] && [ "$port" -le 65535 ]
}

validate_iface_name() {
    iface="$1"

    case "$iface" in
        ''|*[!A-Za-z0-9._:-]*)
            return 1
            ;;
        *)
            return 0
            ;;
    esac
}

validate_ifaces_list() {
    for iface in $IFACES; do
        validate_iface_name "$iface" || die "Invalid interface name: $iface"
    done
}

validate_clients_list() {
    for ip in $CLIENTS; do
        validate_ipv4 "$ip" || die "Invalid client IPv4: $ip"
    done
}

validate_required_config() {

    [ -n "$INTERCEPT_IP4" ] || die "INTERCEPT_IP4 is required"
    validate_ipv4 "$INTERCEPT_IP4" || die "Invalid INTERCEPT_IP4: $INTERCEPT_IP4"

    [ -n "$INTERCEPT_PORT" ] || die "INTERCEPT_PORT is required"
    validate_port "$INTERCEPT_PORT" || die "Invalid INTERCEPT_PORT: $INTERCEPT_PORT"

    if [ "$FORWARD_DNS" = "1" ]; then
        [ -n "$DNS_IP4" ] || die "DNS_IP4 is required when DNS interception is enabled"
        validate_ipv4 "$DNS_IP4" || die "Invalid DNS_IP4: $DNS_IP4"

        [ -n "$DNS_PORT" ] || die "DNS_PORT is required when DNS interception is enabled"
        validate_port "$DNS_PORT" || die "Invalid DNS_PORT: $DNS_PORT"
    fi

    [ -n "$IFACES" ] || die "At least one interface must be specified"

}

validate_no_conflicts() {

    if [ "$FORWARD_HTTP" = "0" ] && [ "$FORWARD_HTTPS" = "0" ] && [ "$FORWARD_DNS" = "0" ]; then
        die "All forwarding options are disabled"
    fi

    for ip in $CLIENTS; do
        if [ "$ip" = "$INTERCEPT_IP4" ]; then
            die "Client list must not contain interception host"
        fi

        if [ -n "$DNS_IP4" ] && [ "$ip" = "$DNS_IP4" ]; then
            die "Client list must not contain DNS host"
        fi
    done
}

validate_config() {

    normalize_config

    validate_required_config
    validate_ifaces_list
    validate_clients_list
    validate_no_conflicts

}

profile_file_path() {
    name="$1"
    printf '%s/%s.conf\n' "$PROFILE_DIR" "$name"
}

load_profile_file() {
    name="$1"

    safe_profile_name "$name" || die "Invalid profile name: $name"

    file="$(profile_file_path "$name")"
    [ -f "$file" ] || die "Profile not found: $name"

    # shellcheck disable=SC1090
    . "$file"
}

save_profile_file() {
    name="$1"

    safe_profile_name "$name" || die "Invalid profile name: $name"
    ensure_profile_dir

    file="$(profile_file_path "$name")"
    tmp_file="$(mktemp "${file}.tmp.XXXXXX")" || die "Failed to create temporary profile file"

    {
        printf 'PROFILE_NAME="%s"\n' "$name"
        printf 'PROFILE_DESC="%s"\n' "$PROFILE_DESC"
        printf '\n'
        printf 'INTERCEPT_IP4="%s"\n' "$INTERCEPT_IP4"
        printf 'INTERCEPT_PORT="%s"\n' "$INTERCEPT_PORT"
        printf '\n'
        printf 'DNS_IP4="%s"\n' "$DNS_IP4"
        printf 'DNS_PORT="%s"\n' "$DNS_PORT"
        printf '\n'
        printf 'IFACES="%s"\n' "$IFACES"
        printf 'CLIENTS="%s"\n' "$CLIENTS"
        printf '\n'
        printf 'FORWARD_HTTP="%s"\n' "$FORWARD_HTTP"
        printf 'FORWARD_HTTPS="%s"\n' "$FORWARD_HTTPS"
        printf 'FORWARD_DNS="%s"\n' "$FORWARD_DNS"
        printf '\n'
        printf 'QUIC_MODE="%s"\n' "$QUIC_MODE"
        printf 'IPV6_MODE="%s"\n' "$IPV6_MODE"
    } > "$tmp_file" || {
        rm -f "$tmp_file"
        die "Failed to write profile: $file"
    }

    mv "$tmp_file" "$file" || {
        rm -f "$tmp_file"
        die "Failed to install profile: $file"
    }
}

list_profile_names() {
    ensure_profile_dir

    found=0
    for file in "$PROFILE_DIR"/*.conf; do
        [ -e "$file" ] || continue
        found=1
        basename "$file" .conf
    done

    if [ "$found" = "0" ]; then
        log_info "No profiles found."
    fi
}

delete_profile_file() {
    name="$1"

    safe_profile_name "$name" || die "Invalid profile name: $name"

    file="$(profile_file_path "$name")"
    [ -f "$file" ] || die "Profile not found: $name"

    rm -f "$file" || die "Failed to delete profile: $name"
}

show_profile_file() {
    name="$1"

    safe_profile_name "$name" || die "Invalid profile name: $name"

    file="$(profile_file_path "$name")"
    [ -f "$file" ] || die "Profile not found: $name"

    cat "$file"
}

write_metadata_header() {
    printf '# managed by %s\n' "$PROGRAM_NAME"
    printf '# profile: %s\n' "$PROFILE_NAME"
    printf '# intercept_ip4: %s\n' "$INTERCEPT_IP4"
    printf '# intercept_port: %s\n' "$INTERCEPT_PORT"
    printf '# dns_ip4: %s\n' "$DNS_IP4"
    printf '# dns_port: %s\n' "$DNS_PORT"
    printf '# ifaces: %s\n' "$IFACES"
    printf '# clients: %s\n' "$CLIENTS"
    printf '# forward_http: %s\n' "$FORWARD_HTTP"
    printf '# forward_https: %s\n' "$FORWARD_HTTPS"
    printf '# forward_dns: %s\n' "$FORWARD_DNS"
    printf '# quic_mode: %s\n' "$QUIC_MODE"
    printf '# ipv6_mode: %s\n' "$IPV6_MODE"
    printf '\n'
}

has_managed_header() {
    [ -f "$RULE_FILE" ] || return 1
    grep -q "^# managed by $PROGRAM_NAME\$" "$RULE_FILE"
}

read_metadata_value() {
    key="$1"

    [ -f "$RULE_FILE" ] || return 1
    sed -n "s/^# ${key}: //p" "$RULE_FILE" | sed -n '1p'
}

emit_rule() {
    printf '  %s\n' "$1"
}

generate_set_ifaces() {
    first=1

    printf 'set %s {\n' "$SET_IFACES"
    printf '  type ifname\n'
    printf '  elements = { '

    for iface in $IFACES; do
        if [ "$first" = "1" ]; then
            first=0
        else
            printf ', '
        fi
        printf '"%s"' "$iface"
    done

    printf ' }\n'
    printf '}\n\n'
}

generate_set_clients_v4() {
    first=1

    [ -n "$CLIENTS" ] || return 0

    printf 'set %s {\n' "$SET_CLIENTS_V4"
    printf '  type ipv4_addr\n'
    printf '  elements = { '

    for ip in $CLIENTS; do
        if [ "$first" = "1" ]; then
            first=0
        else
            printf ', '
        fi
        printf '%s' "$ip"
    done

    printf ' }\n'
    printf '}\n\n'
}

generate_set_local_v4() {
    first=1

    printf 'set %s {\n' "$SET_LOCAL_V4"
    printf '  type ipv4_addr\n'
    printf '  flags interval\n'
    printf '  elements = { '

    for cidr in $(printf '%s\n' "$LOCAL_V4_ELEMENTS" | grep -v '^$'); do
        if [ "$first" = "1" ]; then
            first=0
        else
            printf ', '
        fi
        printf '%s' "$cidr"
    done

    printf ' }\n'
    printf '}\n\n'
}

generate_set_local_v6() {
    first=1

    printf 'set %s {\n' "$SET_LOCAL_V6"
    printf '  type ipv6_addr\n'
    printf '  flags interval\n'
    printf '  elements = { '

    for cidr in $(printf '%s\n' "$LOCAL_V6_ELEMENTS" | grep -v '^$'); do
        if [ "$first" = "1" ]; then
            first=0
        else
            printf ', '
        fi
        printf '%s' "$cidr"
    done

    printf ' }\n'
    printf '}\n\n'
}

emit_prerouting_interface_guard() {
    emit_rule "iifname != @$SET_IFACES return"
}

emit_prerouting_client_guard() {
    [ -n "$CLIENTS" ] || return 0
    emit_rule "ip saddr != @$SET_CLIENTS_V4 return"
}

emit_prerouting_source_exclusions() {
    emit_rule "ip saddr $INTERCEPT_IP4 return"

    if [ -n "$DNS_IP4" ] && [ "$DNS_IP4" != "$INTERCEPT_IP4" ]; then
        emit_rule "ip saddr $DNS_IP4 return"
    fi
}

emit_prerouting_dns_rules() {
    [ "$FORWARD_DNS" = "1" ] || return 0

    emit_rule "udp dport 53 counter dnat ip to $DNS_IP4:$DNS_PORT"
    emit_rule "tcp dport 53 counter dnat ip to $DNS_IP4:$DNS_PORT"
}

emit_prerouting_http_rules() {
    [ "$FORWARD_HTTP" = "1" ] || return 0
    emit_rule "tcp dport 80 counter dnat ip to $INTERCEPT_IP4:$INTERCEPT_PORT"
}

emit_prerouting_https_rules() {
    [ "$FORWARD_HTTPS" = "1" ] || return 0
    emit_rule "tcp dport 443 counter dnat ip to $INTERCEPT_IP4:$INTERCEPT_PORT"
}

emit_prerouting_quic_rules() {
    [ "$QUIC_MODE" = "block" ] || return 0
    emit_rule "udp dport 443 counter reject"
}

emit_prerouting_ipv6_block_rules() {
    [ "$IPV6_MODE" = "block" ] || return 0

    if [ "$FORWARD_HTTP" = "1" ]; then
        emit_rule "ip6 nexthdr tcp tcp dport 80 counter reject with icmpv6 type admin-prohibited"
    fi

    if [ "$FORWARD_HTTPS" = "1" ]; then
        emit_rule "ip6 nexthdr tcp tcp dport 443 counter reject with icmpv6 type admin-prohibited"
    fi

    if [ "$QUIC_MODE" = "block" ]; then
        emit_rule "ip6 nexthdr udp udp dport 443 counter reject with icmpv6 type admin-prohibited"
    fi

    if [ "$FORWARD_DNS" = "1" ]; then
        emit_rule "ip6 nexthdr udp udp dport 53 counter reject with icmpv6 type admin-prohibited"
        emit_rule "ip6 nexthdr tcp tcp dport 53 counter reject with icmpv6 type admin-prohibited"
    fi
}

emit_postrouting_intercept_masquerade() {
    emit_rule "ip daddr $INTERCEPT_IP4 tcp dport $INTERCEPT_PORT counter masquerade"
}

# DNS masquerade is required for reliable transparent DNS redirection
# when the DNS server is located in the same LAN segment.
emit_postrouting_dns_masquerade() {
    [ "$FORWARD_DNS" = "1" ] || return 0
    emit_rule "ip daddr $DNS_IP4 udp dport $DNS_PORT counter masquerade"
    emit_rule "ip daddr $DNS_IP4 tcp dport $DNS_PORT counter masquerade"
}

generate_chain_prerouting() {
    printf 'chain %s {\n' "$CHAIN_PRE"
    printf '  type nat hook prerouting priority -100;\n'
    printf '\n'

    emit_prerouting_interface_guard
    emit_prerouting_client_guard
    emit_prerouting_source_exclusions

    emit_rule "ip daddr $INTERCEPT_IP4 return"
    if [ "$FORWARD_DNS" = "1" ]; then
        emit_rule "ip daddr $DNS_IP4 udp dport $DNS_PORT return"
        emit_rule "ip daddr $DNS_IP4 tcp dport $DNS_PORT return"
    fi

    emit_prerouting_dns_rules

    emit_rule "ip daddr @$SET_LOCAL_V4 return"
    emit_rule "ip6 daddr @$SET_LOCAL_V6 return"

    emit_prerouting_http_rules
    emit_prerouting_https_rules
    emit_prerouting_quic_rules
    emit_prerouting_ipv6_block_rules

    printf '}\n\n'
}

generate_chain_postrouting() {
    printf 'chain %s {\n' "$CHAIN_POST"
    printf '  type nat hook postrouting priority 100;\n'
    printf '\n'

    emit_rule "iifname != @$SET_IFACES return"
    emit_postrouting_intercept_masquerade
    emit_postrouting_dns_masquerade

    printf '}\n'
}

generate_nft_rules() {
    write_metadata_header
    generate_set_ifaces
    generate_set_clients_v4
    generate_set_local_v4
    generate_set_local_v6
    generate_chain_prerouting
    generate_chain_postrouting
}

create_temp_file() {
    TEMP_FILE="$(mktemp "${RULE_FILE}.tmp.XXXXXX")" || die "Failed to create temporary file"
}

cleanup_temp_file() {
    if [ -n "${TEMP_FILE:-}" ] && [ -f "$TEMP_FILE" ]; then
        rm -f "$TEMP_FILE" || true
    fi
    TEMP_FILE=""
}

install_cleanup_trap() {
    trap 'cleanup_temp_file' EXIT INT TERM HUP
}

rules_file_exists() {
    [ -f "$RULE_FILE" ]
}

write_rules_atomic() {
    mkdir -p "$(dirname "$RULE_FILE")" || die "Failed to create rules directory"

    create_temp_file

    if ! generate_nft_rules > "$TEMP_FILE"; then
        cleanup_temp_file
        die "Failed to generate rules"
    fi

    if ! mv "$TEMP_FILE" "$RULE_FILE"; then
        cleanup_temp_file
        die "Failed to install rules file: $RULE_FILE"
    fi

    TEMP_FILE=""
}

remove_rules_file() {
    if rules_file_exists; then
        rm -f "$RULE_FILE" || die "Failed to remove rules file: $RULE_FILE"
    fi
}

fw_reload() {
    fw4 reload
}

fw_restart() {
    /etc/init.d/firewall restart
}

chain_exists() {
    chain_name="$1"
    nft list chain inet fw4 "$chain_name" >/dev/null 2>&1
}

managed_chains_loaded() {
    chain_exists "$CHAIN_PRE" && chain_exists "$CHAIN_POST"
}

any_managed_chain_present() {
    chain_exists "$CHAIN_PRE" || chain_exists "$CHAIN_POST"
}

show_chain() {
    chain_name="$1"

    if chain_exists "$chain_name"; then
        nft list chain inet fw4 "$chain_name"
    else
        return 1
    fi
}

show_runtime_status() {
    if rules_file_exists; then
        log_info "FILE: present ($RULE_FILE)"
    else
        log_info "FILE: absent ($RULE_FILE)"
    fi

    if chain_exists "$CHAIN_PRE"; then
        log_info "NFT: chain loaded (inet fw4 $CHAIN_PRE)"
    else
        log_info "NFT: chain not loaded (inet fw4 $CHAIN_PRE)"
    fi

    if chain_exists "$CHAIN_POST"; then
        log_info "NFT: chain loaded (inet fw4 $CHAIN_POST)"
    else
        log_info "NFT: chain not loaded (inet fw4 $CHAIN_POST)"
    fi

    if has_managed_header; then
        log_info "Managed metadata:"
        log_info "  profile: $(read_metadata_value "profile")"
        log_info "  intercept_ip4: $(read_metadata_value "intercept_ip4")"
        log_info "  intercept_port: $(read_metadata_value "intercept_port")"
        log_info "  dns_ip4: $(read_metadata_value "dns_ip4")"
        log_info "  dns_port: $(read_metadata_value "dns_port")"
        log_info "  ifaces: $(read_metadata_value "ifaces")"
        log_info "  clients: $(read_metadata_value "clients")"
        log_info "  forward_http: $(read_metadata_value "forward_http")"
        log_info "  forward_https: $(read_metadata_value "forward_https")"
        log_info "  forward_dns: $(read_metadata_value "forward_dns")"
        log_info "  quic_mode: $(read_metadata_value "quic_mode")"
        log_info "  ipv6_mode: $(read_metadata_value "ipv6_mode")"
    fi

    if [ "$VERBOSE" = "1" ]; then
        if chain_exists "$CHAIN_PRE"; then
            printf '\n'
            show_chain "$CHAIN_PRE" || true
        fi

        if chain_exists "$CHAIN_POST"; then
            printf '\n'
            show_chain "$CHAIN_POST" || true
        fi
    fi
}

set_defaults() {
    PROFILE_NAME=""
    PROFILE_DESC=""

    INTERCEPT_IP4=""
    INTERCEPT_PORT=""

    DNS_IP4=""
    DNS_PORT=""

    IFACES=""
    CLIENTS=""

    FORWARD_HTTP="1"
    FORWARD_HTTPS="1"
    FORWARD_DNS="0"

    QUIC_MODE="ignore"
    IPV6_MODE="ignore"

    VERBOSE="0"
}

reset_cli_overrides() {
    CLI_PROFILE_NAME=""
    CLI_INTERCEPT_IP4=""
    CLI_INTERCEPT_PORT=""
    CLI_DNS_IP4=""
    CLI_DNS_PORT=""
    CLI_IFACES=""
    CLI_CLIENTS=""
    CLI_FORWARD_HTTP=""
    CLI_FORWARD_HTTPS=""
    CLI_FORWARD_DNS=""
    CLI_QUIC_MODE=""
    CLI_IPV6_MODE=""
    CLI_VERBOSE=""
    CLI_PROFILE_SAVE_NAME=""
}

apply_profile_if_requested() {
    if [ -n "$CLI_PROFILE_NAME" ]; then
        load_profile_file "$CLI_PROFILE_NAME"

        if [ -z "$PROFILE_NAME" ]; then
            PROFILE_NAME="$CLI_PROFILE_NAME"
        fi
    fi
}

apply_cli_overrides() {
    if [ -n "$CLI_INTERCEPT_IP4" ]; then
        INTERCEPT_IP4="$CLI_INTERCEPT_IP4"
    fi

    if [ -n "$CLI_INTERCEPT_PORT" ]; then
        INTERCEPT_PORT="$CLI_INTERCEPT_PORT"
    fi

    if [ -n "$CLI_DNS_IP4" ]; then
        DNS_IP4="$CLI_DNS_IP4"
    fi

    if [ -n "$CLI_DNS_PORT" ]; then
        DNS_PORT="$CLI_DNS_PORT"
    fi

    if [ -n "$CLI_IFACES" ]; then
        IFACES="$CLI_IFACES"
    fi

    if [ -n "$CLI_CLIENTS" ]; then
        CLIENTS="$CLI_CLIENTS"
    fi

    if [ -n "$CLI_FORWARD_HTTP" ]; then
        FORWARD_HTTP="$CLI_FORWARD_HTTP"
    fi

    if [ -n "$CLI_FORWARD_HTTPS" ]; then
        FORWARD_HTTPS="$CLI_FORWARD_HTTPS"
    fi

    if [ -n "$CLI_FORWARD_DNS" ]; then
        FORWARD_DNS="$CLI_FORWARD_DNS"
    fi

    if [ -n "$CLI_QUIC_MODE" ]; then
        QUIC_MODE="$CLI_QUIC_MODE"
    fi

    if [ -n "$CLI_IPV6_MODE" ]; then
        IPV6_MODE="$CLI_IPV6_MODE"
    fi

    if [ -n "$CLI_VERBOSE" ]; then
        VERBOSE="$CLI_VERBOSE"
    fi
}

finalize_profile_name() {
    if [ -z "$PROFILE_NAME" ] && [ -n "$CLI_PROFILE_NAME" ]; then
        PROFILE_NAME="$CLI_PROFILE_NAME"
    fi
}

build_effective_config() {
    set_defaults
    apply_profile_if_requested
    apply_cli_overrides
    finalize_profile_name
}

print_effective_config() {
    log_info "Effective configuration:"
    log_info "  profile_name: $PROFILE_NAME"
    log_info "  profile_desc: $PROFILE_DESC"
    log_info "  intercept_ip4: $INTERCEPT_IP4"
    log_info "  intercept_port: $INTERCEPT_PORT"
    log_info "  dns_ip4: $DNS_IP4"
    log_info "  dns_port: $DNS_PORT"
    log_info "  ifaces: $IFACES"
    log_info "  clients: $CLIENTS"
    log_info "  forward_http: $FORWARD_HTTP"
    log_info "  forward_https: $FORWARD_HTTPS"
    log_info "  forward_dns: $FORWARD_DNS"
    log_info "  quic_mode: $QUIC_MODE"
    log_info "  ipv6_mode: $IPV6_MODE"
    log_info "  verbose: $VERBOSE"
}

cmd_on() {
    build_effective_config
    validate_config

    if [ "$VERBOSE" = "1" ]; then
        print_effective_config
    fi

    write_rules_atomic

    if ! fw_reload; then
        die "fw4 reload failed"
    fi

    if managed_chains_loaded; then
        log_info "ON: rules loaded ($RULE_FILE)"
        if [ "$VERBOSE" = "1" ]; then
            printf '\n'
            show_chain "$CHAIN_PRE" || true
            printf '\n'
            show_chain "$CHAIN_POST" || true
        fi
    else
        log_error "Rules file was written, but managed chains were not loaded into inet fw4."
        log_error "Hint: inspect the firewall configuration and run: nft list ruleset | grep -n \"$CHAIN_PRE\\|$CHAIN_POST\""
        exit 1
    fi
}

cmd_off() {
    changed=0

    if rules_file_exists; then
        remove_rules_file
        changed=1
    fi

    if ! fw_reload; then
        log_warn "fw4 reload failed during off operation"
    fi

    if any_managed_chain_present; then
        log_warn "Managed chain is still present after fw4 reload"
        log_warn "Trying firewall restart"

        if ! fw_restart; then
            log_warn "Firewall restart failed during off operation"
        fi

        if any_managed_chain_present; then
            log_error "Managed chain is still present after off operation"
            if chain_exists "$CHAIN_PRE"; then
                show_chain "$CHAIN_PRE" || true
            fi
            if chain_exists "$CHAIN_POST"; then
                show_chain "$CHAIN_POST" || true
            fi
            exit 1
        fi
    fi

    if [ "$changed" = "1" ]; then
        log_info "OFF: rules removed ($RULE_FILE)"
    else
        log_info "OFF: already removed, managed chains not present"
    fi
}

cmd_status() {
    if [ "$CLI_VERBOSE" = "1" ] && [ -n "$CLI_PROFILE_NAME" ]; then
        build_effective_config
        print_effective_config
        printf '\n'
    fi

    if [ "$CLI_VERBOSE" = "1" ]; then
        VERBOSE="1"
    fi

    show_runtime_status
}

cmd_print() {
    build_effective_config
    validate_config

    if [ "$VERBOSE" = "1" ]; then
        print_effective_config
        printf '\n'
    fi

    generate_nft_rules
}

cmd_check() {
    build_effective_config
    validate_config

    if [ "$VERBOSE" = "1" ]; then
        print_effective_config
        printf '\n'
    fi

    mkdir -p "$(dirname "$RULE_FILE")" || die "Failed to create rules directory"
    create_temp_file

    if ! generate_nft_rules > "$TEMP_FILE"; then
        cleanup_temp_file
        die "Failed to generate rules for validation"
    fi

    if [ "$VERBOSE" = "1" ]; then
        log_info "Generated temporary rules file: $TEMP_FILE"
    fi

    log_info "OK: configuration is valid"
    cleanup_temp_file
}

cmd_save_profile() {
    [ -n "$CLI_PROFILE_SAVE_NAME" ] || usage_error "Profile name is required for save-profile"

    build_effective_config
    validate_config

    PROFILE_NAME="$CLI_PROFILE_SAVE_NAME"
    save_profile_file "$CLI_PROFILE_SAVE_NAME"
    log_info "Profile saved: $CLI_PROFILE_SAVE_NAME"
}

cmd_load_profile() {
    [ -n "$CLI_PROFILE_NAME" ] || usage_error "Profile name is required for load-profile"
    cmd_on
}

cmd_list_profiles() {
    list_profile_names
}

cmd_delete_profile() {
    [ -n "$CLI_PROFILE_SAVE_NAME" ] || usage_error "Profile name is required for delete-profile"
    delete_profile_file "$CLI_PROFILE_SAVE_NAME"
    log_info "Profile deleted: $CLI_PROFILE_SAVE_NAME"
}

cmd_show_profile() {
    [ -n "$CLI_PROFILE_SAVE_NAME" ] || usage_error "Profile name is required for show-profile"
    show_profile_file "$CLI_PROFILE_SAVE_NAME"
}

parse_on_off_value() {
    value="$1"

    case "$value" in
        on)
            printf '1\n'
            ;;
        off)
            printf '0\n'
            ;;
        *)
            return 1
            ;;
    esac
}

parse_cli() {
    reset_cli_overrides

    if [ "$#" -eq 0 ]; then
        usage_error "No command specified"
    fi

    COMMAND="$1"
    shift

    case "$COMMAND" in
        on|off|status|print|check|list-profiles|help)
            ;;
        save-profile|load-profile|delete-profile|show-profile)
            if [ "$#" -eq 0 ]; then
                usage_error "Missing required profile name for command: $COMMAND"
            fi

            case "$COMMAND" in
                save-profile|delete-profile|show-profile)
                    CLI_PROFILE_SAVE_NAME="$1"
                    ;;
                load-profile)
                    CLI_PROFILE_NAME="$1"
                    ;;
            esac
            shift
            ;;
        -h|--help)
            COMMAND="help"
            ;;
        --version)
            COMMAND="version"
            ;;
        *)
            usage_error "Unknown command: $COMMAND"
            ;;
    esac

    while [ "$#" -gt 0 ]; do
        case "$1" in
            --profile)
                [ "$#" -ge 2 ] || usage_error "Missing value for --profile"
                CLI_PROFILE_NAME="$2"
                shift 2
                ;;
            --intercept-ip)
                [ "$#" -ge 2 ] || usage_error "Missing value for --intercept-ip"
                CLI_INTERCEPT_IP4="$2"
                shift 2
                ;;
            --intercept-port)
                [ "$#" -ge 2 ] || usage_error "Missing value for --intercept-port"
                CLI_INTERCEPT_PORT="$2"
                shift 2
                ;;
            --dns-ip)
                [ "$#" -ge 2 ] || usage_error "Missing value for --dns-ip"
                CLI_DNS_IP4="$2"
                shift 2
                ;;
            --dns-port)
                [ "$#" -ge 2 ] || usage_error "Missing value for --dns-port"
                CLI_DNS_PORT="$2"
                shift 2
                ;;
            --iface)
                [ "$#" -ge 2 ] || usage_error "Missing value for --iface"
                CLI_IFACES="$(append_word "$CLI_IFACES" "$2")"
                shift 2
                ;;
            --client)
                [ "$#" -ge 2 ] || usage_error "Missing value for --client"
                CLI_CLIENTS="$(append_word "$CLI_CLIENTS" "$2")"
                shift 2
                ;;
            --http)
                [ "$#" -ge 2 ] || usage_error "Missing value for --http"
                CLI_FORWARD_HTTP="$(parse_on_off_value "$2")" || usage_error "Invalid value for --http: $2"
                shift 2
                ;;
            --https)
                [ "$#" -ge 2 ] || usage_error "Missing value for --https"
                CLI_FORWARD_HTTPS="$(parse_on_off_value "$2")" || usage_error "Invalid value for --https: $2"
                shift 2
                ;;
            --dns)
                [ "$#" -ge 2 ] || usage_error "Missing value for --dns"
                CLI_FORWARD_DNS="$(parse_on_off_value "$2")" || usage_error "Invalid value for --dns: $2"
                shift 2
                ;;
            --quic)
                [ "$#" -ge 2 ] || usage_error "Missing value for --quic"
                case "$2" in
                    ignore|block)
                        CLI_QUIC_MODE="$2"
                        ;;
                    *)
                        usage_error "Invalid value for --quic: $2"
                        ;;
                esac
                shift 2
                ;;
            --ipv6)
                [ "$#" -ge 2 ] || usage_error "Missing value for --ipv6"
                case "$2" in
                    ignore|block)
                        CLI_IPV6_MODE="$2"
                        ;;
                    *)
                        usage_error "Invalid value for --ipv6: $2"
                        ;;
                esac
                shift 2
                ;;
            --verbose)
                CLI_VERBOSE="1"
                shift
                ;;
            -h|--help)
                COMMAND="help"
                shift
                ;;
            --version)
                COMMAND="version"
                shift
                ;;
            *)
                usage_error "Unknown option: $1"
                ;;
        esac
    done
}

print_version() {
    printf '%s %s\n' "$PROGRAM_NAME" "$PROGRAM_VERSION"
    if [ -n "${PROGRAM_AUTHOR:-}" ]; then
        printf '%s\n' "$PROGRAM_AUTHOR"
    fi
}

main() {
    parse_cli "$@"

    case "$COMMAND" in
        help)
            print_help
            exit 0
            ;;
        version)
            print_version
            exit 0
            ;;
    esac

    require_root
    require_commands
    install_cleanup_trap

    case "$COMMAND" in
        on)
            cmd_on
            ;;
        off)
            cmd_off
            ;;
        status)
            cmd_status
            ;;
        print)
            cmd_print
            ;;
        check)
            cmd_check
            ;;
        save-profile)
            cmd_save_profile
            ;;
        load-profile)
            cmd_load_profile
            ;;
        list-profiles)
            cmd_list_profiles
            ;;
        delete-profile)
            cmd_delete_profile
            ;;
        show-profile)
            cmd_show_profile
            ;;
        *)
            usage_error "Unsupported command: $COMMAND"
            ;;
    esac
}

main "$@"