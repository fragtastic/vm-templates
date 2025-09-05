#!/usr/bin/env sh


enable_community_repo() {
    echo ">>> Enabling community repo"
    sed -i 's/^#\(.*\/community\)/\1/' /etc/apk/repositories
    apk update
}

install_docker() {
    echo ">>> Installing Docker"
    enable_community_repo
    apk add --no-cache docker docker-cli-compose

    rc-update add docker default
    rc-service docker start
}

install_qemu_guest_agent() {
    echo ">>> Installing QEMU Guest Agent"
    enable_community_repo
    apk add --no-cache qemu-guest-agent

    rc-update add qemu-guest-agent boot
    rc-service qemu-guest-agent start
}

install_curl() {
    echo ">>> Installing curl and ca-certificates"
    apk add --no-cache ca-certificates curl
}

enable_color_prompt() {
    echo ">>> Enabling colored prompt"
    if [ -f /etc/profile.d/color_prompt.sh.disabled ]; then
        mv /etc/profile.d/color_prompt.sh.disabled /etc/profile.d/color_prompt.sh
    fi
}

harden_ssh() {
    echo ">>> Adding hardened values to /etc/ssh/sshd_config.d/99-hardening.conf"
    # NOTE - must stay NOT indented after this line.
    tee /etc/ssh/sshd_config.d/99-hardening.conf > /dev/null <<'EOF'
# Disable root login
PermitRootLogin no

# Disable password authentication, keys only
PasswordAuthentication no
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
HostbasedAuthentication no
IgnoreRhosts yes
PermitUserEnvironment no

# Explicitly enable public key authentication
PubkeyAuthentication yes

# Use only strong ciphers, MACs, and key exchange
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512

# Protocol and logging
Protocol 2
LogLevel VERBOSE

# Limit auth retries
MaxAuthTries 3
MaxSessions 5

# Disconnect idle sessions
ClientAliveInterval 300
ClientAliveCountMax 2

# Disable X11 forwarding and agent forwarding
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
EOF
    rc-service sshd reload
}

create_user_from_github() {
    install_curl()
    USER=$1
    GHUSER=$2

    if [ -z "$GHUSER" ]; then
        echo "Usage: create_user <local_username> <github_username>"
        return 1
    fi

    echo ">>> Creating user \"${USER}\" and pulling keys from https://github.com/${USER}.keys"

    # Create user if missing
    if ! id "$USER" >/dev/null 2>&1; then
        adduser -D -h /home/$USER -s /bin/sh $USER
        echo "Created user $USER"
    fi

    HOME_DIR=/home/$USER
    SSH_DIR=$HOME_DIR/.ssh
    mkdir -p "$SSH_DIR"
    chmod 700 "$SSH_DIR"
    chown $USER:$USER "$SSH_DIR"

    # Fetch keys from GitHub
    curl -fsSL "https://github.com/${GHUSER}.keys" -o "$SSH_DIR/authorized_keys"
    chmod 600 "$SSH_DIR/authorized_keys"
    chown $USER:$USER "$SSH_DIR/authorized_keys"

    # Add to sudo/wheel group
    if getent group sudo >/dev/null 2>&1; then
        adduser $USER sudo
    elif getent group wheel >/dev/null 2>&1; then
        adduser $USER wheel
    else
        echo "No sudo or wheel group found — skipping admin group."
    fi

    echo "User $USER configured with keys from $GHUSER and admin rights."
}

usage() {
    echo "Usage: $0 [docker|qemu-agent|color|ssh|user <local_username> <github_username>|all]"
    echo "Note: [all] does not handle [user], please run that separately as needed."
    exit 1
}

# Run based on arguments
if [ $# -eq 0 ]; then
    usage
fi

for arg in "$@"; do
    case "$arg" in
        all)
            harden_ssh
            install_qemu_guest_agent
            enable_color_prompt
            install_docker
            ;;
        color) enable_color_prompt ;;
        docker) install_docker ;;
        ssh) harden_ssh ;;
        qemu-agent) install_qemu_guest_agent ;;
        user) shift; create_user_from_github "$@" ;;
        *) usage ;;
    esac
done