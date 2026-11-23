#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
bash -n linux_ssh_init.sh
# Sourcing does not run main; validate functions without touching host SSH.
# shellcheck source=../linux_ssh_init.sh
source ./linux_ssh_init.sh

die() { echo "FAIL: $*" >&2; exit 1; }
expect_accept() { "$@" || die "unexpected rejection: $*"; }
expect_reject() { if "$@"; then die "unexpected acceptance: $*"; fi; }

for p in 1 22 10022 65535; do expect_accept is_valid_port "$p"; done
for p in 0 00022 08 65536 -1 22x '' 999999999999; do
    expect_reject is_valid_port "$p"
done

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
ssh-keygen -q -t ed25519 -N '' -f "$tmp/testkey"
key="$(cat "$tmp/testkey.pub")"
expect_accept validate_pubkey "$key"
expect_reject validate_pubkey "ssh-ed25519 fakekey"
expect_reject validate_pubkey "ssh-ed25519"
expect_reject validate_pubkey "command=evil $key"
expect_reject validate_pubkey "$key"$'\n'"PermitRootLogin yes"

# Test effective settings using a fake sshd -T, without needing root.
cat > "$tmp/sshd" <<'MOCK'
#!/usr/bin/env bash
printf '%s\n' "${EFFECTIVE_CONFIG}"
MOCK
chmod +x "$tmp/sshd"
SSHD_BIN="$tmp/sshd"
TARGET_USER=testuser
SSH_PORT=10022
PERMIT_ROOT=no
export EFFECTIVE_CONFIG=$'port 10022\npasswordauthentication no\nkbdinteractiveauthentication no\npubkeyauthentication yes\npermitrootlogin no'
expect_accept verify_sshd_effective
EFFECTIVE_CONFIG+=$'\nport 22'
expect_reject verify_sshd_effective
EFFECTIVE_CONFIG=$'port 10022\npasswordauthentication yes\nkbdinteractiveauthentication no\npubkeyauthentication yes\npermitrootlogin no'
expect_reject verify_sshd_effective

echo "All non-destructive hardening checks passed."
