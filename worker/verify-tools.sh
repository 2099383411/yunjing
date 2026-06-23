#!/bin/bash
# ============================================================
# 云镜 — 工具安装验证脚本
# 在 Worker 容器内运行: docker compose exec worker /verify-tools.sh
# ============================================================

set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "============================================"
echo "  云镜 Worker — 渗透工具链验证"
echo "  $(date '+%Y-%m-%d %H:%M:%S')"
echo "============================================"
echo ""

check_tool() {
    local name="$1"
    local cmd="$2"
    local version_flag="${3:---version}"

    printf "  %-20s " "$name"
    if command -v "$cmd" &>/dev/null; then
        local ver
        ver=$($cmd $version_flag 2>&1 | head -1 | cut -c1-60)
        printf "${GREEN}✅${NC}  %s\n" "$ver"
    else
        printf "${RED}❌ NOT FOUND${NC}\n"
    fi
}

# ─── apt 安装的工具 ───
check_tool "nmap"            "nmap"          "--version"
check_tool "whatweb"         "whatweb"       "--version"
check_tool "hydra"           "hydra"         "-h"
check_tool "john"            "john"          ""
check_tool "nikto"           "nikto"         "-Version"

echo ""

# ─── Go 安装的工具 ───
check_tool "nuclei"          "nuclei"        "-version"
check_tool "gobuster"        "gobuster"      "--help"
check_tool "subfinder"       "subfinder"     "-version"

echo ""

# ─── 手动安装的工具 ───
check_tool "sqlmap"          "sqlmap"        "--version"
check_tool "xray"            "xray"          "version"

echo ""

# ─── Python ───
printf "  %-20s " "python3.12"
python_version=$(python3.12 --version 2>&1)
echo -e "${GREEN}✅${NC}  $python_version"

printf "  %-20s " "celery"
celery_version=$(python3.12 -m celery --version 2>&1)
echo -e "${GREEN}✅${NC}  $celery_version"

echo ""
echo "============================================"
echo "  Go 工具路径: /go/bin/"
echo "  nuclei 模板: /data/nuclei-templates/"
echo "  sqlmap:     /opt/sqlmap/"
echo "  xray:       /opt/xray/"
echo "============================================"
