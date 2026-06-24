class ScanService:
    async def create_scan(self, target: str, scan_type: str = "full") -> dict:
        return {"task_id": "placeholder", "target": target, "scan_type": scan_type, "status": "pending"}
    async def cancel_scan(self, task_id: str) -> bool: return True
    async def get_progress(self, task_id: str) -> dict: return {"task_id": task_id, "progress": 0, "stage": "idle"}

scan_service = ScanService()
