from celery import Celery
from app.config import settings

celery_app = Celery("yunjing", broker=settings.REDIS_URL, backend=settings.REDIS_URL,
    include=["app.tasks.scan_tasks", "app.tasks.report_tasks"])

celery_app.conf.update(
    task_serializer="json", accept_content=["json"], result_serializer="json",
    timezone="Asia/Shanghai", enable_utc=True, task_track_started=True,
    task_time_limit=settings.SCAN_TIMEOUT, task_soft_time_limit=settings.SCAN_TIMEOUT - 60,
    worker_prefetch_multiplier=1, worker_max_tasks_per_child=100,
)
