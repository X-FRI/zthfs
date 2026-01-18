#!/bin/bash
# ZTHFS Uninstallation Script
# This script removes ZTHFS from the system while preserving data by default

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

# Configuration
CONFIG_FILE="${CONFIG_FILE:-/etc/zthfs/config.json}"
MOUNT_POINT="${MOUNT_POINT:-/mnt/zthfs}"
DATA_DIR="/var/lib/zthfs/data"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   log_error "This script must be run as root (sudo)"
   exit 1
fi

# Display warning banner
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${RED}ZTHFS Uninstallation${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo -e "${YELLOW}WARNING: This will remove ZTHFS from your system.${NC}"
echo ""
echo "Before proceeding, ensure you have:"
echo "  1. Backed up your encryption keys ($CONFIG_FILE)"
echo "  2. Backed up any important data in $MOUNT_POINT"
echo "  3. Unmounted the filesystem (or let this script do it)"
echo ""
read -p "Do you want to continue? (yes/no): " -r
echo ""

if [[ ! "$REPLY" =~ ^[Yy][Ee][Ss]$ ]]; then
    log_info "Uninstallation cancelled."
    exit 0
fi

# Get the invoking user
if [[ -n "$SUDO_USER" ]]; then
    REAL_USER="$SUDO_USER"
else
    REAL_USER="${USER:-root}"
fi

# Track what was preserved
PRESERVED_ITEMS=()

# ============================================================================
# Step 1: Stop and disable services
# ============================================================================
log_info "Step 1/7: Stopping ZTHFS services..."

if systemctl is-active --quiet zthfs.service 2>/dev/null; then
    systemctl stop zthfs.service
    log_success "Stopped zthfs.service"
elif systemctl is-active --quiet zthfs 2>/dev/null; then
    systemctl stop zthfs
    log_success "Stopped zthfs"
else
    log_info "Service not running"
fi

if systemctl is-enabled --quiet zthfs.service 2>/dev/null; then
    systemctl disable zthfs.service
    log_success "Disabled zthfs.service"
fi

if systemctl is-enabled --quiet zthfs-unmount.service 2>/dev/null; then
    systemctl disable zthfs-unmount.service
    log_success "Disabled zthfs-unmount.service"
fi

# ============================================================================
# Step 2: Unmount filesystem
# ============================================================================
log_info "Step 2/7: Unmounting ZTHFS..."

MOUNTED=false
if mountpoint -q "$MOUNT_POINT" 2>/dev/null; then
    MOUNTED=true
    /usr/local/bin/zthfs unmount "$MOUNT_POINT" 2>/dev/null || \
    fusermount -u "$MOUNT_POINT" 2>/dev/null || \
    umount "$MOUNT_POINT" 2>/dev/null || {
        log_warn "Could not unmount $MOUNT_POINT"
        log_info "You may need to manually: umount $MOUNT_POINT"
    }
    log_success "Filesystem unmounted"
else
    log_info "Filesystem not mounted at $MOUNT_POINT"
fi

# Check for any other ZTHFS mounts
for mp in $(mount | grep -E "type.*fuse.*zthfs|zthfs on" | awk '{print $3}'); do
    log_info "Unmounting $mp..."
    umount "$mp" 2>/dev/null || fusermount -u "$mp" 2>/dev/null || true
done

# ============================================================================
# Step 3: Remove systemd services
# ============================================================================
log_info "Step 3/7: Removing systemd service files..."

for svc in zthfs.service zthfs-unmount.service; do
    if [[ -f "/etc/systemd/system/$svc" ]]; then
        rm -f "/etc/systemd/system/$svc"
        log_success "Removed $svc"
    fi
done

# Remove override directories
for dir in /etc/systemd/system/zthfs.service.d /etc/systemd/system/zthfs-unmount.service.d; do
    if [[ -d "$dir" ]]; then
        rm -rf "$dir"
        log_success "Removed $dir"
    fi
done

systemctl daemon-reload
systemctl reset-failed 2>/dev/null || true

# ============================================================================
# Step 4: Remove binary
# ============================================================================
log_info "Step 4/7: Removing ZTHFS binary..."

if [[ -f "/usr/local/bin/zthfs" ]]; then
    rm -f /usr/local/bin/zthfs
    log_success "Binary removed"
else
    log_info "Binary not found"
fi

# ============================================================================
# Step 5: Handle data directory
# ============================================================================
log_info "Step 5/7: Handling data directory..."

echo ""
echo -ne "Remove data directory ($DATA_DIR)? "
echo -ne "${YELLOW}This will delete ALL encrypted data.${NC}"
echo -n " (yes/no): "
read -r
if [[ "$REPLY" =~ ^[Yy][Ee][Ss]$ ]]; then
    if [[ -d "/var/lib/zthfs" ]]; then
        rm -rf /var/lib/zthfs
        log_success "Data directory removed"
    fi
else
    log_info "Preserving data directory: /var/lib/zthfs"
    PRESERVED_ITEMS+=("Data directory: /var/lib/zthfs")
fi

# ============================================================================
# Step 6: Handle configuration
# ============================================================================
log_info "Step 6/7: Handling configuration..."

echo ""
echo -ne "Remove configuration file ($CONFIG_FILE)? "
echo -ne "${YELLOW}This contains your encryption keys!${NC}"
echo -n " (yes/no): "
read -r
if [[ "$REPLY" =~ ^[Yy][Ee][Ss]$ ]]; then
    if [[ -d "/etc/zthfs" ]]; then
        rm -rf /etc/zthfs
        log_success "Configuration removed"
    fi
else
    log_info "Preserving configuration: $CONFIG_FILE"
    PRESERVED_ITEMS+=("Configuration: $CONFIG_FILE")

    # Create a backup with timestamp
    if [[ -f "$CONFIG_FILE" ]]; then
        BACKUP_CONFIG="${CONFIG_FILE}.uninstalled_$(date +%Y%m%d_%H%M%S)"
        cp "$CONFIG_FILE" "$BACKUP_CONFIG"
        log_success "Configuration backed up to: $BACKUP_CONFIG"
    fi
fi

# ============================================================================
# Step 7: Clean up remaining items
# ============================================================================
log_info "Step 7/7: Cleaning up remaining items..."

# Remove log directory
if [[ -d "/var/log/zthfs" ]]; then
    echo ""
    echo -n "Remove log directory (/var/log/zthfs)? (yes/no): "
    read -r
    if [[ "$REPLY" =~ ^[Yy][Ee][Ss]$ ]]; then
        rm -rf /var/log/zthfs
        log_success "Log directory removed"
    else
        PRESERVED_ITEMS+=("Log directory: /var/log/zthfs")
    fi
fi

# Remove system user
echo ""
echo -n "Remove zthfs system user? (yes/no): "
read -r
if [[ "$REPLY" =~ ^[Yy][Ee][Ss]$ ]]; then
    if id -u zthfs &>/dev/null; then
        userdel zthfs 2>/dev/null || true
        log_success "System user removed"
    else
        log_info "System user does not exist"
    fi
else
    PRESERVED_ITEMS+=("System user: zthfs")
fi

# Remove mount point (only if empty)
if [[ -d "$MOUNT_POINT" ]]; then
    # Check if directory is empty (only lost+found or nothing)
    CONTENTS=$(ls -A "$MOUNT_POINT" 2>/dev/null)
    if [[ -z "$CONTENTS" ]] || [[ "$CONTENTS" == "lost+found" ]]; then
        echo ""
        echo -n "Remove empty mount point ($MOUNT_POINT)? (yes/no): "
        read -r
        if [[ "$REPLY" =~ ^[Yy][Ee][Ss]$ ]]; then
            rmdir "$MOUNT_POINT" 2>/dev/null || rm -rf "$MOUNT_POINT" 2>/dev/null || true
            log_success "Mount point removed"
        else
            PRESERVED_ITEMS+=("Mount point: $MOUNT_POINT")
        fi
    else
        log_info "Mount point not empty - preserving"
        PRESERVED_ITEMS+=("Mount point: $MOUNT_POINT (contains data)")
    fi
fi

# Remove from fuse group
if getent group fuse > /dev/null 2>&1; then
    if getent group fuse | grep -q "\bzthfs\b"; then
        gpasswd -d zthfs fuse 2>/dev/null || true
        log_info "Removed zthfs from fuse group"
    fi
fi

# ============================================================================
# Summary
# ============================================================================
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
log_success "ZTHFS uninstallation completed!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

if [[ ${#PRESERVED_ITEMS[@]} -gt 0 ]]; then
    echo -e "${YELLOW}Preserved items:${NC}"
    for item in "${PRESERVED_ITEMS[@]}"; do
        echo "  • $item"
    done
    echo ""
fi

echo -e "${BLUE}To completely remove all remaining items:${NC}"
echo "  sudo rm -rf /var/lib/zthfs /etc/zthfs /var/log/zthfs '$MOUNT_POINT'"
echo "  sudo userdel zthfs"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
