#!/bin/bash
# ZTHFS Automated Uninstallation Script
# This script removes ZTHFS from a Linux system

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

log_warn "Starting ZTHFS uninstallation..."
log_warn "This will remove ZTHFS completely from the system."
log_warn "Make sure to backup any important data before proceeding!"

# Ask for confirmation
read -p "Are you sure you want to uninstall ZTHFS? (yes/no): " confirm
if [[ "$confirm" != "yes" ]]; then
    log_info "Uninstallation cancelled."
    exit 0
fi

# Ask about data removal
read -p "Do you want to remove all ZTHFS data and configurations? (yes/no): " remove_data
if [[ "$remove_data" != "yes" ]]; then
    log_info "Data will be preserved."
    PRESERVE_DATA=true
else
    log_warn "All ZTHFS data and configurations will be removed!"
    PRESERVE_DATA=false
fi

# Detect OS (same as deploy.sh)
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

# Stop and disable systemd service
log_info "Stopping and disabling systemd service..."
if systemctl is-active --quiet zthfs 2>/dev/null; then
    systemctl stop zthfs
    log_info "ZTHFS service stopped"
fi

if systemctl is-enabled --quiet zthfs 2>/dev/null; then
    systemctl disable zthfs
    log_info "ZTHFS service disabled"
fi

# Remove systemd service file
if [[ -f /etc/systemd/system/zthfs.service ]]; then
    rm -f /etc/systemd/system/zthfs.service
    log_info "Systemd service file removed"
fi

# Reload systemd
systemctl daemon-reload

# Try to unmount any mounted ZTHFS filesystems
log_info "Checking for mounted ZTHFS filesystems..."
if mount | grep -q "zthfs"; then
    log_warn "Found mounted ZTHFS filesystems. Attempting to unmount..."
    # Try to unmount common mount points
    for mount_point in /mnt/zthfs /mnt/medical; do
        if mount | grep -q "$mount_point"; then
            log_info "Attempting to unmount $mount_point"
            umount "$mount_point" 2>/dev/null || fusermount -u "$mount_point" 2>/dev/null || true
        fi
    done
fi

# Remove binary
if [[ -f /usr/local/bin/zthfs ]]; then
    rm -f /usr/local/bin/zthfs
    log_info "ZTHFS binary removed from /usr/local/bin/"
fi

# Handle data and configuration removal based on user choice
if [[ "$PRESERVE_DATA" == "true" ]]; then
    log_info "Preserving data directories as requested."
    log_warn "You can manually remove these directories later:"
    log_warn "  - /var/lib/zthfs"
    log_warn "  - /var/log/zthfs"
    log_warn "  - /etc/zthfs"
    log_warn "  - /mnt/zthfs (if empty)"
else
    # Remove data directories
    log_info "Removing data directories..."
    if [[ -d /var/lib/zthfs ]]; then
        rm -rf /var/lib/zthfs
        log_info "Removed /var/lib/zthfs"
    fi

    if [[ -d /var/log/zthfs ]]; then
        rm -rf /var/log/zthfs
        log_info "Removed /var/log/zthfs"
    fi

    if [[ -d /etc/zthfs ]]; then
        rm -rf /etc/zthfs
        log_info "Removed /etc/zthfs"
    fi

# Reset mount point permissions (if it exists and we're not removing data)
if [[ -d /mnt/zthfs ]] && [[ "$PRESERVE_DATA" == "true" ]]; then
    # Reset permissions to allow access by other users
    chown root:root /mnt/zthfs 2>/dev/null || true
    chmod 755 /mnt/zthfs 2>/dev/null || true
    log_info "Reset permissions for mount point /mnt/zthfs"
fi

# Remove mount point directory (only if empty and not preserving data)
if [[ -d /mnt/zthfs ]] && [[ ! "$(ls -A /mnt/zthfs 2>/dev/null)" ]] && [[ "$PRESERVE_DATA" == "false" ]]; then
    rmdir /mnt/zthfs 2>/dev/null || true
    log_info "Removed empty mount point /mnt/zthfs"
elif [[ -d /mnt/zthfs ]] && [[ "$PRESERVE_DATA" == "false" ]]; then
    log_warn "Mount point /mnt/zthfs is not empty, preserving it"
fi
fi

# Remove zthfs user and group (only if they exist and are not used elsewhere)
log_info "Checking zthfs user and group..."
if id -u zthfs &>/dev/null; then
    # Check if user owns any files outside of ZTHFS directories
    if [[ "$PRESERVE_DATA" == "false" ]]; then
        # Safe to remove user since we've removed all ZTHFS directories
        userdel zthfs 2>/dev/null || true
        log_info "Removed zthfs user"
    else
        log_warn "Preserving zthfs user as data directories were kept"
    fi
fi

# Remove zthfs from fuse group if it exists
if getent group fuse > /dev/null 2>&1 && id -u zthfs &>/dev/null; then
    gpasswd -d zthfs fuse 2>/dev/null || true
    log_info "Removed zthfs from fuse group"
fi

# Ask about removing system dependencies
# read -p "Do you want to remove system dependencies (fuse, build tools)? (yes/no): " remove_deps
# if [[ "$remove_deps" == "yes" ]]; then
#     log_info "Removing system dependencies..."
#     case $OS in
#         debian)
#             $PACKAGE_MANAGER remove -y curl build-essential pkg-config libfuse-dev fuse
#             $PACKAGE_MANAGER autoremove -y
#             ;;
#         redhat|fedora)
#             $PACKAGE_MANAGER remove -y curl gcc make pkgconfig fuse-libs fuse-devel
#             ;;
#         opensuse)
#             $PACKAGE_MANAGER remove -y curl gcc make pkgconfig fuse fuse-devel
#             ;;
#     esac
#     log_info "System dependencies removed"
# else
#     log_info "System dependencies preserved"
# fi

# Ask about removing Rust (only if it was installed by the deploy script)
read -p "Do you want to remove Rust (if it was installed by ZTHFS)? (yes/no): " remove_rust
if [[ "$remove_rust" == "yes" ]]; then
    log_warn "Removing Rust installation..."
    if [[ -d $HOME/.cargo ]]; then
        rm -rf $HOME/.cargo
        rm -rf $HOME/.rustup
        log_info "Rust installation removed"
    else
        log_info "No Rust installation found in user home"
    fi
fi

# Clean up working directory
if [[ -d "zthfs" ]]; then
    read -p "Do you want to remove the ZTHFS source code directory? (yes/no): " remove_source
    if [[ "$remove_source" == "yes" ]]; then
        rm -rf zthfs
        log_info "ZTHFS source code directory removed"
    fi
fi

# Final cleanup - remove any remaining ZTHFS related files
log_info "Performing final cleanup..."

# Remove any systemd overrides
if [[ -d /etc/systemd/system/zthfs.service.d ]]; then
    rm -rf /etc/systemd/system/zthfs.service.d
    log_info "Removed systemd service overrides"
fi

# Remove from systemd user lingering (if applicable)
if loginctl show-user zthfs &>/dev/null; then
    loginctl disable-linger zthfs 2>/dev/null || true
fi

log_success "ZTHFS uninstallation completed!"
log_info ""
log_info "Summary of actions taken:"
if [[ "$PRESERVE_DATA" == "false" ]]; then
    log_info "✓ Removed all ZTHFS data and configurations"
else
    log_info "✓ Preserved ZTHFS data and configurations"
fi
log_info "✓ Stopped and disabled systemd service"
log_info "✓ Removed ZTHFS binary"
log_info "✓ Cleaned up system integration"

if [[ "$remove_deps" == "yes" ]]; then
    log_info "✓ Removed system dependencies"
fi

if [[ "$remove_rust" == "yes" ]]; then
    log_info "✓ Removed Rust installation"
fi

log_info ""
log_warn "Please restart your system to ensure all changes take effect."
log_info "If you encounter any issues, please check the system logs with: journalctl -u zthfs"
