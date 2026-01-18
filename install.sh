#!/bin/bash
# ZTHFS Automated Deployment Script
# This script installs and configures ZTHFS on a Linux system

set -e

# Version
VERSION="0.1.0"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   log_error "This script must be run as root (sudo)"
   exit 1
fi

# Detect OS
if [[ -f /etc/debian_version ]]; then
    OS="debian"
    PACKAGE_MANAGER="apt-get"
elif [[ -f /etc/redhat-release ]]; then
    OS="redhat"
    PACKAGE_MANAGER="yum"
elif [[ -f /etc/fedora-release ]]; then
    OS="fedora"
    PACKAGE_MANAGER="dnf"
elif [[ -f /etc/SuSE-release ]] || grep -q "openSUSE" /etc/os-release 2>/dev/null; then
    OS="opensuse"
    PACKAGE_MANAGER="zypper"
else
    log_error "Unsupported operating system"
    exit 1
fi

log_info "Detected OS: $OS"

# Get the invoking user (the one who ran sudo)
if [[ -n "$SUDO_USER" ]]; then
    REAL_USER="$SUDO_USER"
    REAL_HOME=$(eval echo ~"$SUDO_USER")
else
    REAL_USER="${USER:-root}"
    REAL_HOME="${HOME:-/root}"
fi

# Get user IDs for configuration
REAL_UID=$(id -u "$REAL_USER")
REAL_GID=$(id -g "$REAL_USER")
REAL_USER_GROUPS=$(id -G "$REAL_USER" 2>/dev/null || echo "")

log_info "Deployment user: $REAL_USER (UID: $REAL_UID, GID: $REAL_GID)"

# Install system dependencies
log_info "Installing system dependencies..."
case $OS in
    debian)
        $PACKAGE_MANAGER update -y
        $PACKAGE_MANAGER install -y curl build-essential pkg-config libfuse-dev fuse jq
        ;;
    redhat|fedora)
        $PACKAGE_MANAGER install -y curl gcc make pkg-config fuse3 fuse3-devel fuse fuse-devel jq
        ;;
    opensuse)
        $PACKAGE_MANAGER install -y curl gcc make pkg-config fuse fuse-devel jq
        ;;
esac

# Check if FUSE is available
if [[ ! -c /dev/fuse ]]; then
    log_error "FUSE device not available. Please ensure FUSE kernel module is loaded."
    log_info "Try: modprobe fuse"
    exit 1
fi

# Check if Rust is already installed for the user
CARGO_PATH=""
if [[ -f "$REAL_HOME/.cargo/bin/cargo" ]]; then
    CARGO_PATH="$REAL_HOME/.cargo/bin/cargo"
elif sudo -u "$REAL_USER" bash -c 'command -v cargo' &>/dev/null; then
    CARGO_PATH=$(sudo -u "$REAL_USER" bash -lc 'command -v cargo')
fi

# Install Rust only if not found
if [[ -z "$CARGO_PATH" ]]; then
    log_info "Installing Rust for user $REAL_USER..."
    sudo -u "$REAL_USER" bash -c '
        curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    '
    log_success "Rust installed for $REAL_USER"
    CARGO_PATH="$REAL_HOME/.cargo/bin/cargo"
else
    log_info "Rust already installed at: $CARGO_PATH"
fi

# Determine source directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR=""

# Check if we're in the zthfs source directory
if [[ -f "$SCRIPT_DIR/Cargo.toml" ]] && grep -q "name = \"zthfs\"" "$SCRIPT_DIR/Cargo.toml"; then
    SOURCE_DIR="$SCRIPT_DIR"
    log_info "Building from local source: $SOURCE_DIR"
else
    log_error "ZTHFS source not found. Please run this script from the zthfs directory."
    exit 1
fi

cd "$SOURCE_DIR"

# Build ZTHFS as the real user
log_info "Building ZTHFS from source..."
sudo -u "$REAL_USER" bash -c '
    cd "'"$SOURCE_DIR"'" || exit 1
    if [[ -f "$HOME/.cargo/env" ]]; then
        source "$HOME/.cargo/env"
    fi
    cargo build --release
'

# Verify binary was built
if [[ ! -f "target/release/zthfs" ]]; then
    log_error "Build failed - binary not found"
    exit 1
fi

# Install binary
log_info "Installing ZTHFS binary..."
cp target/release/zthfs /usr/local/bin/
chmod +x /usr/local/bin/zthfs

# Create directories
log_info "Creating directories..."
mkdir -p /etc/zthfs
mkdir -p /var/lib/zthfs/data
mkdir -p /var/log/zthfs

# Default mount point
MOUNT_POINT="${MOUNT_POINT:-/mnt/zthfs}"
mkdir -p "$MOUNT_POINT"

# Create zthfs user if it doesn't exist
if ! id -u zthfs &>/dev/null; then
    log_info "Creating zthfs system user..."
    useradd -r -s /bin/false -d /var/lib/zthfs zthfs
fi

# Set permissions
log_info "Setting permissions..."
chown -R zthfs:zthfs /var/lib/zthfs
chown -R zthfs:zthfs /var/log/zthfs
chown zthfs:zthfs "$MOUNT_POINT"
chmod 755 "$MOUNT_POINT"

# Add zthfs user to fuse group (if it exists)
if getent group fuse > /dev/null 2>&1; then
    usermod -a -G fuse zthfs
    log_info "Added zthfs user to fuse group"
else
    log_warn "fuse group does not exist. FUSE permissions will be handled via file permissions."
fi

# Generate initial configuration
log_info "Generating configuration..."
CONFIG_FILE="/etc/zthfs/config.json"

# Run zthfs init to generate config
/usr/local/bin/zthfs init "$CONFIG_FILE"

# Update configuration with real user information
log_info "Updating configuration with user permissions..."

# Use jq to update JSON config properly
if command -v jq &> /dev/null; then
    # Backup original config
    cp "$CONFIG_FILE" "${CONFIG_FILE}.backup"

    # Update security.allowed_users with real user's UID
    jq --argjson uid "$REAL_UID" '
        if .security.allowed_users | index($uid) then .
        else .security.allowed_users += [$uid]
        end
    ' "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"

    # Update security.allowed_groups with real user's GID
    jq --argjson gid "$REAL_GID" '
        if .security.allowed_groups | index($gid) then .
        else .security.allowed_groups += [$gid]
        end
    ' "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"

    # Update data_dir and mount_point
    jq --arg dir "/var/lib/zthfs/data" '.data_dir = $dir' "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
    jq --arg mount "$MOUNT_POINT" '.mount_point = $mount' "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"

    log_success "Configuration updated successfully"
else
    log_warn "jq not installed. Configuration may need manual update."
    log_info "Please ensure your UID ($REAL_UID) and GID ($REAL_GID) are in allowed_users and allowed_groups."
fi

# Validate configuration
log_info "Validating configuration..."
if /usr/local/bin/zthfs validate "$CONFIG_FILE"; then
    log_success "Configuration is valid"
else
    log_warn "Configuration validation failed. Please review $CONFIG_FILE"
fi

# Install systemd service
log_info "Installing systemd service..."
cat > /etc/systemd/system/zthfs.service << EOF
[Unit]
Description=ZTHFS Zero-Trust Healthcare Filesystem
After=network-online.target

[Service]
Type=simple
User=root
Group=root
ExecStart=/usr/local/bin/zthfs mount $MOUNT_POINT /var/lib/zthfs/data --config $CONFIG_FILE
ExecStop=/usr/local/bin/zthfs unmount $MOUNT_POINT
Restart=on-failure
RestartSec=5s
StandardOutput=journal
StandardError=journal
SyslogIdentifier=zthfs

[Install]
WantedBy=multi-user.target
EOF

# Install unmount service for clean shutdown
cat > /etc/systemd/system/zthfs-unmount.service << EOF
[Unit]
Description=ZTHFS Unmount Service
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/true
ExecStop=/usr/local/bin/zthfs unmount $MOUNT_POINT

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd and enable service
log_info "Reloading systemd daemon..."
systemctl daemon-reload

log_info "Enabling ZTHFS service..."
systemctl enable zthfs.service zthfs-unmount.service

# Display summary
echo ""
log_success "ZTHFS deployment completed successfully!"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${BLUE}Configuration Summary${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Binary:          /usr/local/bin/zthfs"
echo "  Config:          $CONFIG_FILE"
echo "  Data directory:  /var/lib/zthfs/data"
echo "  Mount point:     $MOUNT_POINT"
echo "  Log directory:   /var/log/zthfs"
echo "  Service name:    zthfs.service"
echo "  User:            $REAL_USER (UID: $REAL_UID)"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${BLUE}Next Steps${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  1. Review configuration:"
echo "     vim $CONFIG_FILE"
echo ""
echo "  2. Start the service:"
echo "     sudo systemctl start zthfs"
echo ""
echo "  3. Check service status:"
echo "     sudo systemctl status zthfs"
echo ""
echo "  4. View logs:"
echo "     sudo journalctl -u zthfs -f"
echo ""
echo "  5. Verify mount:"
echo "     ls -la $MOUNT_POINT"
echo ""
echo "  6. Test write (as $REAL_USER):"
echo "     echo 'test' > $MOUNT_POINT/test.txt"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${YELLOW}Important Security Notes${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  • Backup your encryption keys:"
echo "      cp $CONFIG_FILE ${CONFIG_FILE}.\$(date +%Y%m%d)"
echo ""
echo "  • Store the backup in a secure, offline location"
echo ""
echo "  • If you lose the encryption keys, ALL DATA WILL BE LOST"
echo ""
echo "  • To uninstall: sudo ./uninstall.sh"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
