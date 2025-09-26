#!/bin/bash
# ZTHFS Automated Deployment Script
# This script installs and configures ZTHFS on a Linux system

set -e

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

log_info "Starting ZTHFS deployment..."

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

# Install system dependencies
log_info "Installing system dependencies..."
# $PACKAGE_MANAGER update -y

case $OS in
    debian)
        $PACKAGE_MANAGER install -y curl build-essential pkg-config libfuse-dev fuse
        ;;
    redhat|fedora)
        $PACKAGE_MANAGER install -y curl gcc make pkgconfig fuse-libs fuse-devel
        ;;
    opensuse)
        $PACKAGE_MANAGER install -y curl gcc make pkgconfig fuse fuse-devel
        ;;
esac

# Check if FUSE is available
if [[ ! -c /dev/fuse ]]; then
    log_error "FUSE device not available. Please ensure FUSE kernel module is loaded."
    exit 1
fi

# Install Rust if not present
if ! command -v cargo &> /dev/null; then
    log_info "Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source $HOME/.cargo/env
    export PATH="$HOME/.cargo/bin:$PATH"
fi

# Clone and build ZTHFS
log_info "Building ZTHFS..."
if [[ ! -d "zthfs" ]]; then
    git clone https://github.com/x-fri/zthfs.git
fi
cd zthfs
sudo rustup default stable
cargo build --release

# Install binary
log_info "Installing ZTHFS binary..."
cp target/release/zthfs /usr/local/bin/
chmod +x /usr/local/bin/zthfs

# Create directories
log_info "Creating directories..."
mkdir -p /etc/zthfs
mkdir -p /var/lib/zthfs/data
mkdir -p /var/log/zthfs
mkdir -p /mnt/zthfs

# Create zthfs user if it doesn't exist
if ! id -u zthfs &>/dev/null; then
    log_info "Creating zthfs user..."
    useradd -r -s /bin/false zthfs
fi

# Set permissions
log_info "Setting permissions..."
chown -R zthfs:zthfs /var/lib/zthfs
chown -R zthfs:zthfs /var/log/zthfs

# Add zthfs user to fuse group (if it exists)
if getent group fuse > /dev/null 2>&1; then
    usermod -a -G fuse zthfs
    log_info "Added zthfs user to fuse group"
else
    log_warn "fuse group does not exist. FUSE permissions will be handled via file permissions."
fi

# Generate configuration
log_info "Generating configuration..."
/usr/local/bin/zthfs init /etc/zthfs/config.json

# Install systemd service
log_info "Installing systemd service..."
cat > /etc/systemd/system/zthfs.service << EOF
[Unit]
Description=ZTHFS Medical Filesystem
After=network.target fuse.service
RequiresMountsFor=/var/lib/zthfs

[Service]
Type=simple
User=zthfs
Group=zthfs
ExecStart=/usr/local/bin/zthfs mount /mnt/zthfs /var/lib/zthfs/data --config /etc/zthfs/config.json
ExecStop=/usr/local/bin/zthfs unmount /mnt/zthfs
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

# Security settings
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/zthfs /var/log/zthfs /mnt/zthfs

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd and enable service
log_info "Enabling systemd service..."
systemctl daemon-reload
systemctl enable zthfs

log_success "ZTHFS deployment completed!"
log_info ""
log_info "Next steps:"
log_info "1. Edit configuration: vim /etc/zthfs/config.json"
log_info "2. Start service: systemctl start zthfs"
log_info "3. Check status: systemctl status zthfs"
log_info "4. View logs: journalctl -u zthfs -f"
log_info "5. Test mount: ls -la /mnt/zthfs/"
log_info ""
log_info "To uninstall ZTHFS later, run:"
log_info "curl -fsSL https://raw.githubusercontent.com/x-fri/zthfs/main/uninstall.sh | sudo bash"
log_info ""
log_warn "Remember to backup your encryption keys from /etc/zthfs/config.json"
