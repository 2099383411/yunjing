from app.celery_app import celery_app

@celery_app.task(bind=True)
def generate_report(self, task_id: str, format: str = "pdf"):
    return {"task_id": task_id, "format": format, "file_path": f"/data/reports/{task_id}.{format}"}
