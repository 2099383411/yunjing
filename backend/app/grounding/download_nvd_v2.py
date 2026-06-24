"""NVD CVE 数据下载脚本 (API 2.0)
使用 NVD API 2.0 获取 CVE 数据并存入本地 JSON 文件

支持在线/离线更新：
- 在线: NVD API 2.0 (需要 API Key)
- 离线: ZIP 包导入 (全量/增量)

用法:
    python -m app.grounding.download_nvd_v2                          # 最近30天
    python -m app.grounding.download_nvd_v2 --days 90 --api-key KEY  # 最近90天
    python -m app.grounding.download_nvd_v2 --all --api-key KEY      # 全部
"""
import argparse
import json
import os
import sys
import time
import urllib.request
import urllib.parse
from datetime import datetime, timezone, timedelta
from pathlib import Path

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OUTPUT_DIR = Path(__file__).parent / "nvd_data"

# NVD API Key
NVD_API_KEY = "72a2582f-5cc3-4b10-ba0a-c493732f91b6"


def fetch_cves_page(params: dict, api_key: str = "") -> dict:
    """调用 NVD API 2.0 获取一页数据"""
    url = f"{API_URL}?{urllib.parse.urlencode(params)}"
    headers = {"User-Agent": "Yunjing/1.0 (Security Scanner; +https://yunjing.security)"}
    if api_key:
        headers["apiKey"] = api_key

    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=120) as resp:
        return json.loads(resp.read().decode("utf-8"))


def download_recent(days: int = 30, api_key: str = "", rate_limit: float = 0.6) -> Path:
    """下载最近N天的 CVE 数据"""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    fname = f"nvdcve-recent-{days}d.json"
    output_path = OUTPUT_DIR / fname
    if output_path.exists():
        print(f"文件已存在: {output_path}")
        return output_path

    now = datetime.now(timezone.utc)
    start_date = (now - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S.000")

    all_vulnerabilities = []
    start_index = 0
    total_results = None

    while True:
        params = {
            "pubStartDate": start_date,
            "pubEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "startIndex": start_index,
            "resultsPerPage": 100,
        }

        print(f"  请求 startIndex={start_index}...", end=" ", flush=True)
        try:
            data = fetch_cves_page(params, api_key)
        except Exception as e:
            print(f"失败: {e}")
            break

        vulns = data.get("vulnerabilities", [])
        all_vulnerabilities.extend(vulns)
        print(f"获取 {len(vulns)} 条")

        if total_results is None:
            total_results = data.get("totalResults", 0)
            print(f"  总计: {total_results} 条")

        start_index += 100
        if start_index >= total_results:
            break

        time.sleep(rate_limit)

    # 写入文件
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump({
            "format": "NVD_API_2.0",
            "download_date": now.isoformat(),
            "total_results": len(all_vulnerabilities),
            "vulnerabilities": all_vulnerabilities,
        }, f, ensure_ascii=False, indent=2)

    print(f"\n✅ 完成! {len(all_vulnerabilities)} 条 CVE 写入 {output_path}")
    return output_path


def download_year_batch(year: int, api_key: str = "", rate_limit: float = 0.6) -> Path:
    """下载指定年份的所有 CVE"""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    output_path = OUTPUT_DIR / f"nvdcve-1.1-{year}.json"
    if output_path.exists():
        print(f"  [{year}] 已存在，跳过")
        return output_path

    all_vulnerabilities = []
    start_index = 0
    total_results = None

    while True:
        params = {
            "pubStartDate": f"{year}-01-01T00:00:00.000",
            "pubEndDate": f"{year}-12-31T23:59:59.999",
            "startIndex": start_index,
            "resultsPerPage": 100,
        }

        print(f"  [{year}] startIndex={start_index}...", end=" ", flush=True)
        try:
            data = fetch_cves_page(params, api_key)
        except Exception as e:
            print(f"失败: {e}")
            break

        vulns = data.get("vulnerabilities", [])
        all_vulnerabilities.extend(vulns)
        print(f"{len(vulns)} 条")

        if total_results is None:
            total_results = data.get("totalResults", 0)
            print(f"  [{year}] 总计: {total_results} 条")

        start_index += 100
        if start_index >= total_results:
            break

        time.sleep(rate_limit)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump({
            "format": "NVD_API_2.0",
            "download_date": datetime.now(timezone.utc).isoformat(),
            "total_results": len(all_vulnerabilities),
            "vulnerabilities": all_vulnerabilities,
        }, f, ensure_ascii=False, indent=2)

    print(f"  [{year}] ✅ 完成: {len(all_vulnerabilities)} 条")
    return output_path


def main():
    parser = argparse.ArgumentParser(description="下载 NVD CVE 数据 (API 2.0)")
    parser.add_argument("--days", type=int, default=30, help="下载最近N天数据")
    parser.add_argument("--all", action="store_true", help="下载全部CVE (2002-2026)")
    parser.add_argument("--api-key", default=NVD_API_KEY, help="NVD API Key (默认使用内置Key)")
    parser.add_argument("--years", nargs="+", help="指定年份，如 2025 2024")
    parser.add_argument("--rate-limit", type=float, default=0.6, help="请求间隔(秒)")
    args = parser.parse_args()

    print(f"🚀 NVD CVE 下载器")
    print(f"  速率: {args.rate_limit}s/请求 ({'有API Key' if args.api_key else '无API Key'})")

    if args.all:
        current_year = datetime.now(timezone.utc).year
        for year in range(2002, current_year + 1):
            print(f"\n--- {year} ---")
            download_year_batch(year, args.api_key, args.rate_limit)
    elif args.years:
        for year in args.years:
            print(f"\n--- {year} ---")
            download_year_batch(int(year), args.api_key, args.rate_limit)
    else:
        path = download_recent(args.days, args.api_key, args.rate_limit)
        print(f"\n接下来导入:")
        print(f"  docker cp {path} yunjing-backend:/app/app/grounding/nvd_data/")
        print(f"  docker exec yunjing-backend python3 -m app.grounding.import_nvd /app/app/grounding/nvd_data/{path.name}")


if __name__ == "__main__":
    main()
