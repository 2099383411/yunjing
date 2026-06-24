"""扫描任务 - Worker 执行（纯同步版）"""
import traceback
from app.celery_app import celery_app
from app.tasks.db import update_task, insert_vuln


@celery_app.task(bind=True, queue="scan", max_retries=2, default_retry_delay=30)
def execute_scan(self, task_id: str, target: str, scan_type: str = "full"):
    """执行扫描：nmap -> nuclei，所有操作同步"""
    try:
        update_task(task_id, status="RUNNING", progress=0)

        # Phase 1: nmap
        update_task(task_id, progress=5)
        from app.scanner.nmap_scanner import NmapScanner
        nmap = NmapScanner()
        result = nmap.execute(target, ports="1-1000", timing="T4")
        findings = result.findings or []

        web_targets = []
        for f in findings:
            port = f.get("port", 0)
            service = f.get("service", "")
            if port in (80, 443) or service in ("http", "https"):
                scheme = "https" if port == 443 else "http"
                web_targets.append(f"{scheme}://{f.get('ip', target)}:{port}")

        update_task(task_id, progress=30, result={
            "stage": "nmap_complete",
            "ports": list(set(f.get("port") for f in findings)),
        })

        # Phase 2: nuclei
        vulns_found = []
        targets_scanned = []
        if web_targets:
            update_task(task_id, progress=50, result={"stage": "nuclei"})
            from app.scanner.nuclei_scanner import NucleiScanner
            nuclei = NucleiScanner()
            for wt in web_targets:
                targets_scanned.append(wt)
                nr = nuclei.execute(wt)
                for fv in nr.findings or []:
                    insert_vuln(task_id, fv, "nuclei", target)
                    vulns_found.append(fv)

        # Complete
        update_task(
            task_id, status="COMPLETED", progress=100,
            completed_at=__import__("datetime").datetime.utcnow(),
            result={
                "scan_type": scan_type,
                "web_targets_found": len(web_targets),
                "vulnerabilities_found": len(vulns_found),
                "targets_scanned": targets_scanned,
            },
        )
        return {
            "scan_type": scan_type,
            "web_targets_found": len(web_targets),
            "vulnerabilities_found": len(vulns_found),
            "targets_scanned": targets_scanned,
        }

    except Exception as e:
        tb = traceback.format_exc()
        try:
            update_task(
                task_id, status="FAILED", progress=0,
                error=f"{type(e).__name__}: {str(e)}",
                result={"error": str(e), "traceback": tb[-500:]},
            )
        except Exception:
            pass
        raise
