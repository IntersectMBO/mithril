#!/bin/bash

# Sets up an IPFS replica of the Mithril immutable archives.
#
# The script installs a Kubo node (binary with a systemd service, or Docker container), then a systemd
# service and timer that resolve the IPNS name of the archives every 30 minutes and pin each new
# version of the directory, keeping the previous versions pinned.

set -euo pipefail

DEPLOYMENT=${DEPLOYMENT:-binary}
KUBO_VERSION=${KUBO_VERSION:-v0.43.1}
PUBLIC_IP_ADDRESS=${PUBLIC_IP_ADDRESS:-}
IPNS_NAME=${IPNS_NAME:-}
CONTAINER_NAME=mithril-ipfs
INSTALL_DIR=/opt/mithril-ipfs
REPOSITORY_DIR=/var/lib/mithril-ipfs
REPLICATION_SCRIPT=$INSTALL_DIR/replicate-immutable-archives.sh
BITSWAP_SETTINGS=(
    "Internal.Bitswap.TaskWorkerCount 32"
    "Internal.Bitswap.EngineTaskWorkerCount 32"
    "Internal.Bitswap.EngineBlockstoreWorkerCount 256"
    "Internal.Bitswap.MaxOutstandingBytesPerPeer 8388608"
)

print_help() {
    cat << EOF
Sets up an IPFS replica of the Mithril immutable archives (Kubo node, replication service and timer).

Usage:
  IPNS_NAME=<name> [OPTIONAL_VARIABLES] bash setup_ipfs_replica.sh

Required variables:
  IPNS_NAME          IPNS name of the immutable archives (eg, /ipns/k51...)

Optional variables:
  DEPLOYMENT         'binary' (default) or 'docker'
  PUBLIC_IP_ADDRESS  Public IPv4 or IPv6 address announced by the node, if it is behind a NAT
  KUBO_VERSION       Kubo version to install (default: v0.43.1)

Options:
  -h, --help         Print this help
EOF
}

fail() {
    echo ">> ERROR: $1" >&2
    exit 1
}

check_commands() {
    local command_name
    for command_name in "$@"; do
        command -v "$command_name" > /dev/null || fail "The '$command_name' command is required but not installed."
    done
}

check_dependencies() {
    check_commands sudo systemctl
    sudo -v || fail "The current user must have sudo rights."
    if [ "$DEPLOYMENT" = "binary" ]; then
        check_commands curl tar sha512sum mktemp uname useradd install
    else
        check_commands docker
        docker info > /dev/null 2>&1 || fail "The Docker daemon is not reachable by the current user (eg, add it to the 'docker' group)."
    fi
}

check_variables() {
    [ -n "$IPNS_NAME" ] || fail "Required environment variable IPNS_NAME is not set (see --help)."
    [[ "$IPNS_NAME" =~ ^/ipns/[A-Za-z0-9.-]+$ ]] || fail "IPNS_NAME must look like '/ipns/<name>', got '$IPNS_NAME'."
    [[ "$KUBO_VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-rc[0-9]+)?$ ]] || fail "KUBO_VERSION must look like 'v0.43.1', got '$KUBO_VERSION'."
    [ "$DEPLOYMENT" = "binary" ] || [ "$DEPLOYMENT" = "docker" ] || fail "DEPLOYMENT must be 'binary' or 'docker', got '$DEPLOYMENT'."
}

announced_addresses() {
    local protocol
    if [[ "$PUBLIC_IP_ADDRESS" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        protocol=ip4
    elif [[ "$PUBLIC_IP_ADDRESS" =~ ^[0-9A-Fa-f:]+$ ]] && [[ "$PUBLIC_IP_ADDRESS" == *:* ]]; then
        protocol=ip6
    else
        fail "PUBLIC_IP_ADDRESS must be an IPv4 or IPv6 address, got '$PUBLIC_IP_ADDRESS'."
    fi
    echo "[\"/$protocol/$PUBLIC_IP_ADDRESS/tcp/4001\", \"/$protocol/$PUBLIC_IP_ADDRESS/udp/4001/quic-v1\"]"
}

write_replication_script() {
    echo ">> Writing the replication script $REPLICATION_SCRIPT"
    sudo mkdir -p "$INSTALL_DIR"
    sudo tee "$REPLICATION_SCRIPT" > /dev/null << "EOF"
#!/bin/sh

# Pins the latest version of the immutable archives directory published under an IPNS name,
# keeping the previous versions pinned as older snapshots still reference them.

set -eu

ipns_name="$1"
state_file="${IPFS_PATH}/replicated-directory.path"
pin_timeout_seconds=14400

latest_path=$(ipfs name resolve --nocache "${ipns_name}")
previous_path=$(cat "${state_file}" 2>/dev/null || true)

if [ "${latest_path}" = "${previous_path}" ]; then
  echo "Replica is up to date: ${latest_path}"
  exit 0
fi

if [ -n "${previous_path}" ] && ipfs pin ls --type=recursive "${previous_path}" > /dev/null 2>&1; then
  timeout "${pin_timeout_seconds}" ipfs pin update --unpin=false "${previous_path}" "${latest_path}"
else
  timeout "${pin_timeout_seconds}" ipfs pin add --progress=false "${latest_path}"
fi

echo "${latest_path}" > "${state_file}.tmp"
mv "${state_file}.tmp" "${state_file}"
echo "Replica updated to: ${latest_path}"
EOF
    sudo chmod +x "$REPLICATION_SCRIPT"
}

write_replication_timer() {
    echo ">> Writing the replication timer"
    sudo tee /etc/systemd/system/mithril-ipfs-replication.timer > /dev/null << EOF
[Unit]
Description=Immutable archives replication timer

[Timer]
OnBootSec=5min
OnUnitInactiveSec=30min

[Install]
WantedBy=timers.target
EOF
}

start_replication() {
    echo ">> Starting the replication"
    sudo systemctl daemon-reload
    sudo systemctl start --no-block mithril-ipfs-replication.service
    sudo systemctl enable --now mithril-ipfs-replication.timer
}

wait_for_node() {
    local ipfs_command=("$@")
    echo ">> Waiting for the Kubo node to be ready"
    for _ in $(seq 1 30); do
        if "${ipfs_command[@]}" swarm peers > /dev/null 2>&1; then
            return 0
        fi
        sleep 2
    done
    fail "The Kubo node is not ready after 60 seconds."
}

install_kubo_binary() {
    local architecture
    case "$(uname -m)" in
        x86_64) architecture=amd64 ;;
        aarch64) architecture=arm64 ;;
        *) fail "Unsupported architecture $(uname -m)." ;;
    esac

    local archive="kubo_${KUBO_VERSION}_linux-${architecture}.tar.gz"
    local download_dir
    download_dir=$(mktemp -d)

    echo ">> Downloading Kubo $KUBO_VERSION"
    curl --fail -sL -o "$download_dir/$archive" "https://github.com/ipfs/kubo/releases/download/$KUBO_VERSION/$archive"
    curl --fail -sL -o "$download_dir/$archive.sha512" "https://github.com/ipfs/kubo/releases/download/$KUBO_VERSION/$archive.sha512"
    (cd "$download_dir" && sha512sum --quiet -c "$archive.sha512")
    tar -xzf "$download_dir/$archive" -C "$download_dir" --strip-components=1 kubo/ipfs

    sudo mkdir -p "$INSTALL_DIR"
    sudo install -o root -g root -m 755 "$download_dir/ipfs" "$INSTALL_DIR/ipfs"
    rm -rf "$download_dir"
    "$INSTALL_DIR/ipfs" --version
}

setup_binary() {
    local ipfs_node=(sudo -u mithril-ipfs env IPFS_PATH="$REPOSITORY_DIR" "$INSTALL_DIR/ipfs")

    install_kubo_binary

    if ! id mithril-ipfs > /dev/null 2>&1; then
        echo ">> Creating the mithril-ipfs user"
        sudo useradd --system --create-home --home-dir "$REPOSITORY_DIR" --shell /usr/sbin/nologin mithril-ipfs
    fi

    if ! sudo test -f "$REPOSITORY_DIR/config"; then
        echo ">> Initializing the Kubo repository"
        "${ipfs_node[@]}" init --profile server > /dev/null
    fi
    if [ -n "$PUBLIC_IP_ADDRESS" ]; then
        "${ipfs_node[@]}" config --json Addresses.AppendAnnounce "$(announced_addresses)"
    fi
    local setting key value
    for setting in "${BITSWAP_SETTINGS[@]}"; do
        read -r key value <<< "$setting"
        "${ipfs_node[@]}" config --json "$key" "$value"
    done

    echo ">> Writing the Kubo node service"
    sudo tee /etc/systemd/system/mithril-ipfs.service > /dev/null << EOF
[Unit]
Description=IPFS Kubo node service
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
Restart=always
RestartSec=60
User=mithril-ipfs
Environment=IPFS_PATH=$REPOSITORY_DIR
LimitNOFILE=65536
ExecStart=$INSTALL_DIR/ipfs daemon --migrate

[Install]
WantedBy=multi-user.target
EOF
    sudo systemctl daemon-reload
    sudo systemctl enable mithril-ipfs.service
    sudo systemctl restart mithril-ipfs.service
    wait_for_node "${ipfs_node[@]}"

    write_replication_script
    echo ">> Writing the replication service"
    sudo tee /etc/systemd/system/mithril-ipfs-replication.service > /dev/null << EOF
[Unit]
Description=Immutable archives replication service
Requires=mithril-ipfs.service
After=mithril-ipfs.service

[Service]
Type=oneshot
User=mithril-ipfs
Environment=IPFS_PATH=$REPOSITORY_DIR
Environment=PATH=$INSTALL_DIR:/usr/bin:/bin
TimeoutStartSec=5h
ExecStart=$REPLICATION_SCRIPT $IPNS_NAME
EOF
}

setup_docker() {
    if docker container inspect "$CONTAINER_NAME" > /dev/null 2>&1; then
        fail "A container named $CONTAINER_NAME already exists, remove it with 'docker rm -f $CONTAINER_NAME'."
    fi

    echo ">> Writing the Kubo node configuration script"
    sudo mkdir -p "$INSTALL_DIR/container-init.d"
    {
        echo "#!/bin/sh"
        echo "set -e"
        echo "ipfs config Addresses.API /ip4/127.0.0.1/tcp/5001"
        echo "ipfs config Addresses.Gateway /ip4/127.0.0.1/tcp/8080"
        if [ -n "$PUBLIC_IP_ADDRESS" ]; then
            echo "ipfs config --json Addresses.AppendAnnounce '$(announced_addresses)'"
        fi
        for setting in "${BITSWAP_SETTINGS[@]}"; do
            echo "ipfs config --json $setting"
        done
    } | sudo tee "$INSTALL_DIR/container-init.d/configure-node.sh" > /dev/null

    write_replication_script

    echo ">> Starting the Kubo container"
    docker run -d --quiet --name "$CONTAINER_NAME" --restart always \
        -e IPFS_PROFILE=server \
        -v mithril-ipfs-data:/data/ipfs \
        -v "$INSTALL_DIR/container-init.d:/container-init.d:ro" \
        -v "$REPLICATION_SCRIPT:/usr/local/bin/replicate-immutable-archives.sh:ro" \
        -p 4001:4001 -p 4001:4001/udp \
        "ipfs/kubo:$KUBO_VERSION" > /dev/null
    wait_for_node docker exec "$CONTAINER_NAME" ipfs

    echo ">> Writing the replication service"
    sudo tee /etc/systemd/system/mithril-ipfs-replication.service > /dev/null << EOF
[Unit]
Description=Immutable archives replication service
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
TimeoutStartSec=5h
ExecStart=$(command -v docker) exec $CONTAINER_NAME replicate-immutable-archives.sh $IPNS_NAME
EOF
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    print_help
    exit 0
fi

check_variables
if [ -n "$PUBLIC_IP_ADDRESS" ]; then
    announced_addresses > /dev/null
fi
check_dependencies

"setup_$DEPLOYMENT"
write_replication_timer
start_replication

echo ">> Congrats, your IPFS replica is set up! The initial synchronization runs in the background."
echo ">> Follow it with: journalctl -u mithril-ipfs-replication -f"
