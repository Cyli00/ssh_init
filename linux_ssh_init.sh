#!/usr/bin/env bash
set -euo pipefail

# ══════════════════════════════════════════════════════════════════════════════
# Colors and Formatting
# ══════════════════════════════════════════════════════════════════════════════
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[0;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly BOLD='\033[1m'
readonly NC='\033[0m' # No Color

# Box drawing characters
readonly LINE_H="═"
readonly LINE_L="─"
readonly ARROW="→"
readonly CHECK="✔"
readonly CROSS="✖"
readonly WARN="⚠"

# ══════════════════════════════════════════════════════════════════════════════
# Global Variables
# ══════════════════════════════════════════════════════════════════════════════
DISTRO=""
SSH_SERVICE=""
TOTAL_STEPS=5
CURRENT_STEP=0
SSHD_BIN=""
CONFIG_FILE=""
CONFIG_BACKUP=""
CONFIG_TEMP=""
CONFIG_HAD_PREVIOUS=0
CONFIG_CHANGED=0

# ══════════════════════════════════════════════════════════════════════════════
# UI Functions
# ══════════════════════════════════════════════════════════════════════════════
print_header() {
    local title="$1"
    local width=50
    local line=""
    for ((i=0; i<width; i++)); do line+="$LINE_H"; done

    echo ""
    echo -e "${CYAN}${line}${NC}"
    printf "${CYAN}   %s${NC}\n" "$title"
    echo -e "${CYAN}${line}${NC}"
    echo ""
}

print_separator() {
    local width=50
    local line=""
    for ((i=0; i<width; i++)); do line+="$LINE_L"; done
    echo -e "${CYAN}${line}${NC}"
}

print_step() {
    local step_num="$1"
    local step_title="$2"
    echo ""
    echo -e "${BOLD}${BLUE}[${step_num}/${TOTAL_STEPS}] ${step_title}${NC}"
}

print_action() {
    echo -e "${ARROW} $*"
}

print_ok() {
    echo -e "${GREEN}${CHECK} $*${NC}"
}

print_err() {
    echo -e "${RED}${CROSS} $*${NC}" >&2
}

print_warn() {
    echo -e "${YELLOW}${WARN} $*${NC}" >&2
}

print_info() {
    echo -e "${CYAN}${ARROW} $*${NC}"
}

print_footer_success() {
    echo ""
    print_separator
    echo -e "${GREEN}${CHECK} SSH hardening completed successfully${NC}"
    echo ""
    echo -e "Test in a ${BOLD}NEW${NC} terminal:"
    echo -e "  ${CYAN}ssh -p ${SSH_PORT} ${TARGET_USER}@<SERVER_IP>${NC}"
    echo ""
    print_warn "Do NOT close this session until confirmed."
    if [[ -n "${CLOUD_WARNING:-}" ]]; then
        print_warn "If using cloud provider, also allow TCP ${SSH_PORT} in security group."
    fi
    print_separator
    echo ""
}

# ══════════════════════════════════════════════════════════════════════════════
# System Detection
# ══════════════════════════════════════════════════════════════════════════════
detect_distro() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck source=/dev/null
        source /etc/os-release
        case "${ID:-}" in
            debian)
                DISTRO="debian"
                SSH_SERVICE="ssh"
                ;;
            ubuntu)
                DISTRO="ubuntu"
                SSH_SERVICE="ssh"
                ;;
            *)
                # Try to detect Debian-based systems
                if [[ "${ID_LIKE:-}" == *"debian"* ]] || [[ "${ID_LIKE:-}" == *"ubuntu"* ]]; then
                    DISTRO="${ID}"
                    SSH_SERVICE="ssh"
                else
                    print_err "Unsupported distribution: ${ID:-unknown}"
                    print_info "This script supports Debian and Ubuntu based systems."
                    exit 1
                fi
                ;;
        esac
    else
        print_err "Cannot detect distribution (missing /etc/os-release)"
        exit 1
    fi
}

get_distro_name() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck source=/dev/null
        source /etc/os-release
        echo "${PRETTY_NAME:-${ID:-Unknown}}"
    else
        echo "Unknown"
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
# Validation Functions
# ══════════════════════════════════════════════════════════════════════════════
require_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        print_err "This script must be run as root"
        print_info "Usage: sudo bash $0"
        exit 1
    fi
}

is_valid_port() {
    local p="$1"
    # Reject leading zeros and signs rather than letting Bash parse octal.
    [[ "$p" =~ ^[1-9][0-9]{0,4}$ ]] && (( 10#$p <= 65535 ))
}

is_valid_username() {
    local u="$1"
    # Username: start with letter, contain only letters, numbers, underscore, hyphen
    [[ "$u" =~ ^[a-z_][a-z0-9_-]*$ ]] || return 1
    return 0
}

validate_pubkey() {
    local key="$1"
    local tmp

    # Only accept a single, unadorned authorized_keys public key, not options,
    # arbitrary text, or multiline input. ssh-keygen verifies the key blob.
    [[ "$key" != *$'\r'* && "$key" != *$'\n'* ]] || return 1
    [[ "$key" =~ ^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)[[:space:]]+([A-Za-z0-9+/]+={0,2})([[:space:]].*)?$ ]] || return 1

    tmp="$(mktemp)" || return 1
    chmod 600 "$tmp"
    printf '%s\n' "$key" > "$tmp"
    if ssh-keygen -l -f "$tmp" >/dev/null 2>&1; then
        rm -f -- "$tmp"
        return 0
    fi
    rm -f -- "$tmp"
    return 1
}

# ══════════════════════════════════════════════════════════════════════════════
# User Functions
# ══════════════════════════════════════════════════════════════════════════════
default_target_user() {
    if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
        echo "${SUDO_USER}"
    else
        echo "root"
    fi
}

user_exists() {
    id "$1" >/dev/null 2>&1
}

ensure_sudo_installed() {
    if command -v sudo >/dev/null 2>&1; then
        return 0
    fi
    print_action "Installing sudo..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq >/dev/null 2>&1
    apt-get install -y -qq sudo >/dev/null 2>&1
    print_ok "sudo installed"
}

create_user_if_missing() {
    local u="$1"
    if user_exists "$u"; then
        print_info "User: ${u} (existing)"
        return 0
    fi
    print_action "Creating user: ${u}"
    adduser --disabled-password --gecos "" "$u" >/dev/null 2>&1
    print_ok "User created: ${u}"
}

ensure_user_in_sudo_group() {
    local u="$1"
    usermod -aG sudo "$u"
}

configure_passwordless_sudo() {
    local u="$1"
    local f="/etc/sudoers.d/90-${u}-nopasswd"
    local tmp

    # Validate the replacement before touching a previously working rule.
    tmp="$(mktemp "/etc/sudoers.d/.90-${u}-nopasswd.XXXXXX")"
    printf '%s\n' "${u} ALL=(ALL) NOPASSWD:ALL" > "$tmp"
    chmod 0440 "$tmp"
    if ! visudo -cf "$tmp" >/dev/null 2>&1; then
        print_err "sudoers configuration validation failed"
        rm -f -- "$tmp"
        return 1
    fi
    mv -f -- "$tmp" "$f"
}

# ══════════════════════════════════════════════════════════════════════════════
# SSH Functions
# ══════════════════════════════════════════════════════════════════════════════
install_pubkey() {
    local u="$1"
    local key="$2"
    local home_dir user_group ssh_dir auth_keys

    home_dir="$(getent passwd "$u" | cut -d: -f6)"
    [[ -n "$home_dir" && -d "$home_dir" ]] || {
        print_err "Cannot get home directory for user: $u"
        return 1
    }
    user_group="$(id -gn "$u")"
    ssh_dir="$home_dir/.ssh"
    auth_keys="$ssh_dir/authorized_keys"

    # Never write through a symlink controlled by the target account.
    if [[ -L "$ssh_dir" || -L "$auth_keys" ||
          ( -e "$ssh_dir" && ! -d "$ssh_dir" ) ||
          ( -e "$auth_keys" && ! -f "$auth_keys" ) ]]; then
        print_err "Unsafe .ssh or authorized_keys path (symlink or wrong type)"
        return 1
    fi

    print_action "Installing public key to ${auth_keys}"
    mkdir -p -- "$ssh_dir"
    chmod 700 "$ssh_dir"
    if [[ ! -e "$auth_keys" ]]; then
        : > "$auth_keys"
    fi
    chmod 600 "$auth_keys"

    if grep -Fqx -- "$key" "$auth_keys"; then
        print_info "Public key already exists (skipped)"
    else
        printf '%s\n' "$key" >> "$auth_keys"
        print_ok "Public key installed"
    fi

    # Do not recursively re-own unrelated private keys or other .ssh files.
    chown "$u:$user_group" "$ssh_dir" "$auth_keys"
}

write_sshd_config() {
    local port="$1"
    local permit_root="$2"
    local dropin_dir="/etc/ssh/sshd_config.d"
    local dropin_file="$dropin_dir/99-harden-ssh.conf"

    print_action "Writing sshd config"
    mkdir -p -- "$dropin_dir"
    if [[ -L "$dropin_file" || ( -e "$dropin_file" && ! -f "$dropin_file" ) ]]; then
        print_err "Refusing to replace an unsafe sshd drop-in path"
        return 1
    fi

    CONFIG_FILE="$dropin_file"
    if [[ -e "$CONFIG_FILE" ]]; then
        CONFIG_HAD_PREVIOUS=1
        CONFIG_BACKUP="$(mktemp "$dropin_dir/.99-harden-ssh.rollback.XXXXXX")"
        cp -p -- "$CONFIG_FILE" "$CONFIG_BACKUP"
    fi

    CONFIG_TEMP="$(mktemp "$dropin_dir/.99-harden-ssh.conf.XXXXXX")"
    cat > "$CONFIG_TEMP" <<EOF
# Managed by linux_ssh_init.sh
# Distribution: ${DISTRO}

Port ${port}
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
PermitRootLogin ${permit_root}
EOF

    chmod 0644 "$CONFIG_TEMP"
    mv -f -- "$CONFIG_TEMP" "$CONFIG_FILE"
    CONFIG_TEMP=""
    CONFIG_CHANGED=1
    print_ok "Config written: ${CONFIG_FILE}"
}

sshd_check() {
    print_action "Checking SSH syntax and effective settings"
    if ! "$SSHD_BIN" -t; then
        print_err "sshd configuration syntax check failed"
        return 1
    fi
    verify_sshd_effective || return 1
    print_ok "Configuration valid and effective"
}

restart_sshd() {
    print_action "Restarting SSH service"
    if systemctl restart "${SSH_SERVICE}" 2>/dev/null; then
        print_ok "SSH service restarted"
    else
        print_err "Failed to restart SSH service"
        exit 1
    fi
}

open_ufw_if_present() {
    local port="$1"
    if command -v ufw >/dev/null 2>&1; then
        if ufw status 2>/dev/null | grep -qiE 'Status:\s+active'; then
            print_action "Configuring UFW firewall"
            ufw allow "${port}/tcp" >/dev/null 2>&1
            print_ok "UFW: TCP ${port} allowed"
        fi
    fi
}

# Preflight and rollback are intentionally limited to the sshd drop-in.
# User accounts and authorized_keys are not deleted on an SSH failure.
preflight_ssh() {
    SSHD_BIN="$(command -v sshd || true)"
    if [[ -z "$SSHD_BIN" && -x /usr/sbin/sshd ]]; then
        SSHD_BIN="/usr/sbin/sshd"
    fi
    if [[ -z "$SSHD_BIN" ]] || ! command -v ssh-keygen >/dev/null 2>&1 ||
       ! command -v systemctl >/dev/null 2>&1; then
        print_err "Required tools: sshd, ssh-keygen, and systemctl"
        return 1
    fi
    if ! "$SSHD_BIN" -t; then
        print_err "Existing sshd configuration is invalid; not making changes"
        return 1
    fi
    # A running systemd SSH socket can keep listening on the old port even
    # when sshd -T reports the new one. Avoid silently claiming success.
    if [[ "$SSH_PORT" != "22" ]] &&
       { systemctl is-active --quiet ssh.socket || systemctl is-enabled --quiet ssh.socket; }; then
        print_err "ssh.socket is active/enabled; disable socket activation and use ssh.service before changing ports"
        return 1
    fi
}

verify_sshd_effective() {
    local effective key expected actual spec
    if ! effective="$("$SSHD_BIN" -T -C "user=${TARGET_USER},host=localhost,addr=127.0.0.1")"; then
        print_err "Could not inspect effective sshd settings"
        return 1
    fi
    # OpenSSH uses the first value for most directives; Port may accumulate.
    # Detect ignored drop-ins, cloud-init overrides, and additional ports.
    for spec in "port:${SSH_PORT}" "passwordauthentication:no" \
                "kbdinteractiveauthentication:no" "pubkeyauthentication:yes" \
                "permitrootlogin:${PERMIT_ROOT}"; do
        key="${spec%%:*}"
        expected="${spec#*:}"
        actual="$(awk -v k="$key" '$1 == k { print $2 }' <<< "$effective")"
        if [[ "$actual" != "$expected" ]]; then
            print_err "Effective ${key} is '${actual:-unset}', expected '${expected}'"
            print_info "Review earlier sshd_config.d files, Port directives, and Match blocks."
            return 1
        fi
    done
}

rollback_on_exit() {
    local status="$1"
    trap - EXIT
    if (( status != 0 && CONFIG_CHANGED == 1 )); then
        print_warn "Restoring previous SSH configuration after failure"
        if (( CONFIG_HAD_PREVIOUS == 1 )); then
            if ! mv -f -- "$CONFIG_BACKUP" "$CONFIG_FILE"; then
                print_err "Automatic rollback failed; restore ${CONFIG_BACKUP} manually!"
                CONFIG_BACKUP="" # Never delete the only copy after a failed restore.
            fi
        elif ! rm -f -- "$CONFIG_FILE"; then
            print_err "Automatic rollback failed; remove ${CONFIG_FILE} manually!"
        fi
        # If the new service was started, restore its previous configuration.
        if ! systemctl restart "$SSH_SERVICE" 2>/dev/null; then
            print_err "Could not restart the previous SSH service; inspect it manually"
        fi
    fi
    [[ -z "$CONFIG_TEMP" ]] || rm -f -- "$CONFIG_TEMP"
    [[ -z "$CONFIG_BACKUP" ]] || rm -f -- "$CONFIG_BACKUP"
    exit "$status"
}

has_usable_sudo_password() {
    local status
    status="$(passwd -S "$1" 2>/dev/null)" || return 1
    # Debian/Ubuntu use P for an active account password, L/NP otherwise.
    [[ "$(awk '{print $2}' <<< "$status")" == "P" ]]
}

read_passwordless_sudo() {
    local answer=""
    echo -ne "${ARROW} Grant NOPASSWD:ALL sudo to ${TARGET_USER}? [y/N]: " >&2
    read -r answer || return 1
    [[ "${answer,,}" == "y" ]]
}

# ══════════════════════════════════════════════════════════════════════════════
# Interactive Input Functions
# ══════════════════════════════════════════════════════════════════════════════
read_port() {
    local default_port="${1:-22}"
    local port=""

    while true; do
        echo -ne "${ARROW} New SSH port [${default_port}]: " >&2
        read -r port
        port="${port:-$default_port}"

        if is_valid_port "$port"; then
            if (( port < 1024 )) && (( port != 22 )); then
                print_warn "Port ${port} is a privileged port (< 1024)"
                echo -ne "   Continue anyway? [y/N]: " >&2
                read -r confirm
                [[ "${confirm,,}" == "y" ]] && break
            else
                break
            fi
        else
            print_warn "Invalid port. Please enter a number between 1-65535."
        fi
    done

    echo "$port"
}

read_username() {
    local default_user="$1"
    local username=""

    while true; do
        echo -ne "${ARROW} Login user [${default_user}]: " >&2
        read -r username
        username="${username:-$default_user}"

        if is_valid_username "$username"; then
            break
        else
            print_warn "Invalid username. Use lowercase letters, numbers, underscore, hyphen."
        fi
    done

    echo "$username"
}

read_permit_root() {
    echo -e "${ARROW} Root login policy:" >&2
    echo "   1) Allow root with key only (prohibit-password)" >&2
    echo "   2) Disable root login completely (no)" >&2

    local choice=""
    while true; do
        echo -ne "${ARROW} Select [1]: " >&2
        read -r choice
        choice="${choice:-1}"

        case "$choice" in
            1) echo "prohibit-password"; return ;;
            2) echo "no"; return ;;
            *) print_warn "Please enter 1 or 2" ;;
        esac
    done
}

read_pubkey() {
    echo -e "${ARROW} Paste your SSH public key (ssh-ed25519/ssh-rsa/ecdsa):" >&2
    local key=""

    while true; do
        echo -ne "   " >&2
        IFS= read -r key || return 1

        if validate_pubkey "$key"; then
            echo "$key"
            return 0
        fi
        print_warn "Invalid public key. Paste a complete OpenSSH public key; cannot bypass validation."
    done
}

# ══════════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════════
main() {
    # Pre-flight checks
    require_root
    detect_distro

    local distro_name
    distro_name="$(get_distro_name)"

    # Header
    print_header "SSH Hardening (Interactive)"
    print_info "Detected: ${distro_name}"

    # ─────────────────────────────────────────────────────────────────────────
    # Step 1: SSH Port
    # ─────────────────────────────────────────────────────────────────────────
    print_step 1 "SSH Port"
    SSH_PORT="$(read_port 10022)"

    # ─────────────────────────────────────────────────────────────────────────
    # Step 2: Login User
    # ─────────────────────────────────────────────────────────────────────────
    print_step 2 "Login User"
    local default_user
    default_user="$(default_target_user)"
    TARGET_USER="$(read_username "$default_user")"

    # ─────────────────────────────────────────────────────────────────────────
    # Step 3: Root Login Policy
    # ─────────────────────────────────────────────────────────────────────────
    print_step 3 "Root Login Policy"
    PERMIT_ROOT="$(read_permit_root)"
    print_info "PermitRootLogin: ${PERMIT_ROOT}"

    # Sanity check
    if [[ "$PERMIT_ROOT" == "no" && "$TARGET_USER" == "root" ]]; then
        echo ""
        print_err "Configuration conflict detected!"
        print_info "You chose to disable root login but selected root as login user."
        print_info "This would lock you out. Please use a non-root user."
        exit 1
    fi

    # ─────────────────────────────────────────────────────────────────────────
    # Step 4: Public Key
    # ─────────────────────────────────────────────────────────────────────────
    print_step 4 "Public Key"
    PUBKEY="$(read_pubkey)"

    # ─────────────────────────────────────────────────────────────────────────
    # Step 5: Apply Configuration
    # ─────────────────────────────────────────────────────────────────────────
    print_step 5 "Apply Configuration"

    # Abort before touching accounts or configuration if SSH is not healthy.
    preflight_ssh
    trap 'rollback_on_exit "$?"' EXIT
    print_warn "Check any cloud security group and retain this session until a new login succeeds."

    # User setup
    if [[ "$TARGET_USER" != "root" ]]; then
        ensure_sudo_installed
        create_user_if_missing "$TARGET_USER"
        ensure_user_in_sudo_group "$TARGET_USER"
        if read_passwordless_sudo; then
            configure_passwordless_sudo "$TARGET_USER"
            print_ok "Passwordless sudo explicitly enabled"
        else
            if [[ "$PERMIT_ROOT" == "no" ]] &&
               [[ ! -e "/etc/sudoers.d/90-${TARGET_USER}-nopasswd" ]] &&
               ! has_usable_sudo_password "$TARGET_USER"; then
                print_err "Root SSH is disabled and this user has no usable sudo password."
                print_info "Set a password with 'passwd ${TARGET_USER}' or rerun and opt in to passwordless sudo."
                return 1
            fi
            print_warn "Passwordless sudo not added. Set an account password with passwd if sudo is needed."
            if [[ -e "/etc/sudoers.d/90-${TARGET_USER}-nopasswd" ]]; then
                print_warn "A pre-existing passwordless sudo rule remains; review it manually."
            fi
        fi
        print_ok "User added to sudo group"
    else
        create_user_if_missing "$TARGET_USER"
    fi

    # Install public key
    install_pubkey "$TARGET_USER" "$PUBKEY"

    # SSH configuration
    write_sshd_config "$SSH_PORT" "$PERMIT_ROOT"
    sshd_check

    # Firewall
    open_ufw_if_present "$SSH_PORT"

    # Restart SSH
    restart_sshd
    # The rollback trap can now remove the temporary backup on clean exit.
    CONFIG_CHANGED=0

    # Set cloud warning flag
    CLOUD_WARNING=1

    # Success footer
    print_footer_success
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
