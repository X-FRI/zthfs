#!/bin/bash

# ZTHFS test demo
# This script demonstrates the core functionality of ZTHFS

echo "🩺 ZTHFS - test demo"
echo "=================================="

# Build project
echo "📦 Build ZTHFS..."
cargo build --release

if [ $? -ne 0 ]; then
    echo "❌ Build failed"
    exit 1
fi

echo "✅ Build successful"

# Run demo
echo ""
echo "🚀 Run feature demo..."
./target/release/zthfs demo

echo ""
echo "📊 Check generated files..."

# Check data directory
if [ -d "/tmp/zthfs_data" ]; then
    echo "✅ Data directory created: /tmp/zthfs_data"
    ls -la /tmp/zthfs_data/
else
    echo "❌ Data directory not found"
fi

# Check log file
if [ -f "/tmp/zthfs_demo.log" ]; then
    echo "✅ Log file created: /tmp/zthfs_demo.log"
    echo "📋 Log content preview:"
    head -3 /tmp/zthfs_demo.log
else
    echo "❌ Log file not found"
fi

# Check stored file
if [ -f "/tmp/zthfs_data/patient_record.txt" ]; then
    echo "✅ Encrypted file created: /tmp/zthfs_data/patient_record.txt"
    echo "🔒 File content (encrypted):"
    hexdump -C /tmp/zthfs_data/patient_record.txt | head -2
else
    echo "❌ Encrypted file not found"
fi

echo ""
echo "🧹 Cleaning up demo files..."
rm -rf /tmp/zthfs_data
rm -rf /tmp/zthfs_mount
rm -f /tmp/zthfs_demo.log
echo "✅ Demo cleanup completed"
