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
    echo -e "${YELLOW}${WARN} $*${NC}"
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
    [[ "$p" =~ ^[0-9]+$ ]] || return 1
    (( p >= 1 && p <= 65535 )) || return 1
    return 0
}

is_valid_username() {
    local u="$1"
    # Username: start with letter, contain only letters, numbers, underscore, hyphen
    [[ "$u" =~ ^[a-z_][a-z0-9_-]*$ ]] || return 1
    return 0
}

validate_pubkey() {
    local key="$1"
    if [[ "$key" =~ ^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp|sk-ssh-ed25519|sk-ecdsa-sha2-nistp) ]]; then
        return 0
    fi
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
    echo "${u} ALL=(ALL) NOPASSWD:ALL" > "$f"
    chmod 0440 "$f"
    if ! visudo -cf "$f" >/dev/null 2>&1; then
        print_err "sudoers configuration validation failed"
        rm -f "$f"
        exit 1
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
# SSH Functions
# ══════════════════════════════════════════════════════════════════════════════
install_pubkey() {
    local u="$1"
    local key="$2"

    local home_dir
    home_dir="$(getent passwd "$u" | cut -d: -f6)"
    [[ -n "$home_dir" && -d "$home_dir" ]] || {
        print_err "Cannot get home directory for user: $u"
        exit 1
    }

    local ssh_dir="$home_dir/.ssh"
    local auth_keys="$ssh_dir/authorized_keys"

    print_action "Installing public key to ${auth_keys}"

    mkdir -p "$ssh_dir"
    chmod 700 "$ssh_dir"
    touch "$auth_keys"
    chmod 600 "$auth_keys"

    if grep -Fqx "$key" "$auth_keys" 2>/dev/null; then
        print_info "Public key already exists (skipped)"
    else
        echo "$key" >> "$auth_keys"
        print_ok "Public key installed"
    fi

    chown -R "$u:$u" "$ssh_dir"
}

write_sshd_config() {
    local port="$1"
    local permit_root="$2"
    local dropin_dir="/etc/ssh/sshd_config.d"
    local dropin_file="$dropin_dir/99-harden-ssh.conf"

    print_action "Writing sshd config"

    mkdir -p "$dropin_dir"
    if [[ -f "$dropin_file" ]]; then
        cp -a "$dropin_file" "${dropin_file}.bak.$(date +%Y%m%d%H%M%S)"
    fi

    cat > "$dropin_file" <<EOF
# Managed by linux_ssh_init.sh - $(date +%Y-%m-%d)
# Distribution: ${DISTRO}

Port ${port}

# Key-only authentication
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes

# Root login policy
PermitRootLogin ${permit_root}
EOF

    print_ok "Config written: ${dropin_file}"
}

sshd_check() {
    print_action "Checking configuration"
    if sshd -t 2>/dev/null; then
        print_ok "Configuration valid"
    else
        print_err "sshd configuration check failed"
        print_info "Check /etc/ssh/sshd_config and /etc/ssh/sshd_config.d/"
        exit 1
    fi
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

# ══════════════════════════════════════════════════════════════════════════════
# Interactive Input Functions
# ══════════════════════════════════════════════════════════════════════════════
read_port() {
    local default_port="${1:-22}"
    local port=""

    while true; do
        echo -ne "${ARROW} New SSH port [${default_port}]: "
        read -r port
        port="${port:-$default_port}"

        if is_valid_port "$port"; then
            if (( port < 1024 )) && (( port != 22 )); then
                print_warn "Port ${port} is a privileged port (< 1024)"
                echo -ne "   Continue anyway? [y/N]: "
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
        echo -ne "${ARROW} Login user [${default_user}]: "
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
    echo -e "${ARROW} Root login policy:"
    echo "   1) Allow root with key only (prohibit-password)"
    echo "   2) Disable root login completely (no)"

    local choice=""
    while true; do
        echo -ne "${ARROW} Select [1]: "
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
    echo -e "${ARROW} Paste your SSH public key (ssh-ed25519/ssh-rsa/ecdsa):"
    local key=""

    while true; do
        echo -ne "   "
        IFS= read -r key

        if [[ -z "$key" ]]; then
            print_warn "Public key cannot be empty"
            continue
        fi

        if validate_pubkey "$key"; then
            break
        else
            print_warn "This doesn't look like a valid public key format."
            echo -ne "   Use anyway? [y/N]: "
            read -r confirm
            [[ "${confirm,,}" == "y" ]] && break
        fi
    done

    echo "$key"
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

    # User setup
    if [[ "$TARGET_USER" != "root" ]]; then
        ensure_sudo_installed
        create_user_if_missing "$TARGET_USER"
        ensure_user_in_sudo_group "$TARGET_USER"
        configure_passwordless_sudo "$TARGET_USER"
        print_ok "User configured with sudo access"
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

    # Set cloud warning flag
    CLOUD_WARNING=1

    # Success footer
    print_footer_success
}

main "$@"
