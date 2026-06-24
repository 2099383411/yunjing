#!/bin/bash
set -e
echo '[worker] Starting entrypoint (fixed)...'
NUCLEI_TEMPLATES_DIR="${NUCLEI_TEMPLATES_DIR:-/data/nuclei-templates}"
if [ -d "$NUCLEI_TEMPLATES_DIR" ] && [ "$(ls -A "$NUCLEI_TEMPLATES_DIR" 2>/dev/null)" ]; then
    echo '[worker] Nuclei templates found at '$NUCLEI_TEMPLATES_DIR
else
    echo '[worker] Nuclei templates not found, skipping download.'
fi
echo '[worker] Starting Celery worker...'
exec celery -A tasks.scan_tasks worker --loglevel=info --concurrency=${WORKER_CONCURRENCY:-4} --max-tasks-per-child=${WORKER_MAX_TASKS:-50} --time-limit=${WORKER_TASK_TIMEOUT:-3600} -Q ${WORKER_QUEUE:-scan}
