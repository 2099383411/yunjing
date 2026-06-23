#!/bin/bash
# ============================================================
# 云镜 — 一键构建 + 部署脚本
# 用法:
#   chmod +x build.sh
#   ./build.sh              # 构建所有镜像
#   ./build.sh --no-cache   # 强制重新构建
#   ./build.sh worker       # 仅构建 worker
#   ./build.sh agent        # 仅构建 agent
# ============================================================

set -e

CACHE_FLAG=""
TARGET="${1:-all}"

if [ "$1" = "--no-cache" ]; then
    CACHE_FLAG="--no-cache"
    TARGET="${2:-all}"
fi

echo "============================================"
echo "  云镜 — Docker 镜像构建"
echo "  目标: $TARGET"
echo "  $(date '+%Y-%m-%d %H:%M:%S')"
echo "============================================"

build_service() {
    local name="$1"
    local context="$2"
    local dockerfile="${3:-Dockerfile}"

    echo ""
    echo "━━━ 构建 $name ━━━"
    docker compose build $CACHE_FLAG "$name" 2>&1 | tail -5

    if [ $? -eq 0 ]; then
        echo "✅ $name 构建成功"
    else
        echo "❌ $name 构建失败"
        exit 1
    fi
}

case "$TARGET" in
    all)
        build_service "worker"  "./worker"  "Dockerfile.worker"
        build_service "agent"   "./agent"   "Dockerfile.agent"
        build_service "backend" "./backend" "Dockerfile"
        build_service "frontend" "./frontend" "Dockerfile"
        ;;
    worker)
        build_service "worker"  "./worker"  "Dockerfile.worker"
        ;;
    agent)
        build_service "agent"   "./agent"   "Dockerfile.agent"
        ;;
    *)
        echo "Unknown target: $TARGET"
        echo "Usage: $0 [all|worker|agent|backend|frontend] [--no-cache]"
        exit 1
        ;;
esac

echo ""
echo "============================================"
echo "  构建完成！"
echo ""
echo "  启动全部服务:"
echo "    docker compose up -d"
echo ""
echo "  查看状态:"
echo "    docker compose ps"
echo ""
echo "  查看 Worker 日志:"
echo "    docker compose logs -f worker"
echo ""
echo "  验证工具链:"
echo "    docker compose exec worker /verify-tools.sh"
echo "============================================"
