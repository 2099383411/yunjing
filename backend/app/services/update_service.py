class UpdateService:
    async def check(self) -> dict:
        return {"current_version": "0.1.0", "latest_version": "0.1.0", "update_available": False}
    async def import_package(self, file_path: str) -> bool: return True

update_service = UpdateService()
