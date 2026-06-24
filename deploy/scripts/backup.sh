#!/bin/bash
BACKUP_DIR="/root/yunjing-backups/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"
cp -r /root/yunjing/deploy/data "$BACKUP_DIR/"
echo "备份完成: $BACKUP_DIR"
