from celery import Celery

app = Celery(
    "yunjing",
    broker="redis://redis:6379/1",
    backend="redis://redis:6379/2",
)

app.conf.update(
    imports=['tasks.scan_tasks'],
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="Asia/Shanghai",
    enable_utc=True,
)
