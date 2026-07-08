import asyncio
from celery import Celery
from celery.schedules import crontab
from app.core.config import settings

celery = Celery(
    "securescope",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=["app.workers.tasks"],
)

celery.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="America/Sao_Paulo",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    result_expires=86400,
    beat_schedule={
        "check-scheduled-scans": {
            "task": "app.workers.tasks.run_scheduled_scans",
            "schedule": crontab(minute=0),  # every hour check for due scans
        }
    },
)
