#!/bin/bash
# ============================================================
# Worker 容器入口脚本
# 1. 检查/下载 nuclei 模板
# 2. 启动 Celery Worker
# ============================================================

set -e

echo "[worker] Starting entrypoint..."

# ─── nuclei 模板初始化 ──────────────────────────────────
NUCLEI_TEMPLATES_DIR="${NUCLEI_TEMPLATES_DIR:-/data/nuclei-templates}"
NUCLEI_OFFLINE_PACK="${NUCLEI_OFFLINE_PACK:-}"

if [ -d "$NUCLEI_TEMPLATES_DIR" ] && [ "$(ls -A "$NUCLEI_TEMPLATES_DIR" 2>/dev/null)" ]; then
    echo "[worker] Nuclei templates found at $NUCLEI_TEMPLATES_DIR"
else
    echo "[worker] Nuclei templates not found, downloading..."
    if [ -n "$NUCLEI_OFFLINE_PACK" ] && [ -f "$NUCLEI_OFFLINE_PACK" ]; then
        echo "[worker] Extracting offline pack: $NUCLEI_OFFLINE_PACK"
        tar -xzf "$NUCLEI_OFFLINE_PACK" -C "$NUCLEI_TEMPLATES_DIR"
    else
        # 自动从 GitHub 下载最新模板
        nuclei -update-directory "$NUCLEI_TEMPLATES_DIR" -update-templates 2>/dev/null || {
            echo "[worker] Auto-download failed. Using nuclei without templates for now."
            echo "[worker] Upload offline update pack to enable template-based scanning."
        }
    fi
fi

# ─── 启动 Celery Worker ─────────────────────────────────
echo "[worker] Starting Celery worker..."
exec celery -A app.tasks.scan_tasks worker \
    --loglevel=info \
    --concurrency="${WORKER_CONCURRENCY:-4}" \
    --max-tasks-per-child="${WORKER_MAX_TASKS:-50}" \
    --time-limit="${WORKER_TASK_TIMEOUT:-3600}" \
    -Q "${WORKER_QUEUE:-scan}"
