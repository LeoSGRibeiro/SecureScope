import asyncio
import uuid
from datetime import datetime, timezone, timedelta
from celery import shared_task
from sqlalchemy import select, update
from app.workers.celery_app import celery
from app.core.database import AsyncSessionLocal
from app.models.scan import Scan, Vulnerability, Evidence, ScanStatus, Severity as DBSeverity
from app.services.scanners.orchestrator import run_scan


def _sev_to_db(sev_str: str) -> DBSeverity:
    try:
        return DBSeverity(sev_str)
    except ValueError:
        return DBSeverity.informational


@celery.task(bind=True, max_retries=2, soft_time_limit=360, time_limit=420)
def execute_scan_task(self, scan_id: str):
    """Run all scanner modules for a scan and persist results."""
    asyncio.get_event_loop().run_until_complete(_run_async(scan_id))


async def _run_async(scan_id: str):
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(Scan).where(Scan.id == uuid.UUID(scan_id))
        )
        scan = result.scalar_one_or_none()
        if not scan:
            return

        # Mark as running
        scan.status = ScanStatus.running
        scan.started_at = datetime.now(timezone.utc)
        await db.commit()

        target_result = await db.execute(
            __import__("sqlalchemy", fromlist=["select"]).select(
                __import__("app.models.target", fromlist=["Target"]).Target
            ).where(
                __import__("app.models.target", fromlist=["Target"]).Target.id == scan.target_id
            )
        )
        target = target_result.scalar_one_or_none()
        if not target:
            scan.status = ScanStatus.failed
            scan.error_message = "Target not found"
            await db.commit()
            return

        try:
            modules = scan.modules if scan.modules else None
            scan_output = await run_scan(target.value, modules)

            # Persist findings as vulnerabilities
            for finding_dict in scan_output.get("findings", []):
                vuln = Vulnerability(
                    scan_id=scan.id,
                    title=finding_dict["title"],
                    description=finding_dict["description"],
                    severity=_sev_to_db(finding_dict["severity"]),
                    category=finding_dict["category"],
                    module=finding_dict["module"],
                    cvss_score=finding_dict.get("cvss_score"),
                    cve=finding_dict.get("cve") or None,
                    owasp_category=finding_dict.get("owasp_category"),
                    affected_url=finding_dict.get("affected_url"),
                    evidence=finding_dict.get("evidence"),
                    recommendation=finding_dict.get("recommendation"),
                    references=finding_dict.get("references"),
                )
                db.add(vuln)

            # Persist raw module results as evidence
            for module_name, module_data in scan_output.get("module_results", {}).items():
                ev = Evidence(
                    scan_id=scan.id,
                    type="raw_module",
                    title=f"Raw data: {module_name}",
                    content=module_data.get("raw_data", {}),
                )
                db.add(ev)

            scan.status = ScanStatus.completed
            scan.completed_at = datetime.now(timezone.utc)
            scan.risk_score = scan_output.get("risk_score")
            scan.findings_count = len(scan_output.get("findings", []))

        except Exception as e:
            scan.status = ScanStatus.failed
            scan.error_message = str(e)[:1000]
            scan.completed_at = datetime.now(timezone.utc)

        await db.commit()


# ---------------------------------------------------------------------------
# Scheduled scan tasks
# ---------------------------------------------------------------------------

@celery.task(name="app.workers.tasks.run_scheduled_scans")
def run_scheduled_scans():
    """Hourly beat task: find due scheduled scans and dispatch them."""
    asyncio.get_event_loop().run_until_complete(_check_scheduled_scans())


async def _check_scheduled_scans():
    from app.models.scheduled_scan import ScheduledScan

    now = datetime.now(timezone.utc)
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(ScheduledScan).where(
                ScheduledScan.is_active == True,
                ScheduledScan.next_run_at <= now,
            )
        )
        due = result.scalars().all()
        for sched in due:
            # Update next_run_at immediately to prevent double-dispatch
            sched.next_run_at = now + timedelta(days=sched.interval_days)
            await db.commit()
            execute_scheduled_scan_task.delay(str(sched.id))


@celery.task(bind=True, max_retries=1, soft_time_limit=600, time_limit=660,
             name="app.workers.tasks.execute_scheduled_scan_task")
def execute_scheduled_scan_task(self, scheduled_scan_id: str):
    asyncio.get_event_loop().run_until_complete(_run_scheduled_async(scheduled_scan_id))


async def _run_scheduled_async(scheduled_scan_id: str):
    from app.models.scheduled_scan import ScheduledScan
    from app.models.target import Target
    from app.services.scan_diff import compute_diff
    from app.services.email_service import send_scan_diff_email

    async with AsyncSessionLocal() as db:
        sched_result = await db.execute(
            select(ScheduledScan).where(ScheduledScan.id == uuid.UUID(scheduled_scan_id))
        )
        sched = sched_result.scalar_one_or_none()
        if not sched:
            return

        # Ensure a Target row exists for this URL (create if needed)
        target_result = await db.execute(
            select(Target).where(Target.value == sched.url, Target.owner_id == sched.owner_id)
        )
        target = target_result.scalar_one_or_none()
        if not target:
            target = Target(
                name=sched.url,
                value=sched.url,
                owner_id=sched.owner_id,
                authorization_confirmed=True,
            )
            db.add(target)
            await db.flush()

        # Find the previous completed scan for this target (to diff against)
        prev_result = await db.execute(
            select(Scan)
            .where(Scan.target_id == target.id, Scan.status == ScanStatus.completed)
            .order_by(Scan.completed_at.desc())
            .limit(1)
        )
        previous_scan = prev_result.scalar_one_or_none()

        previous_findings: list[dict] = []
        if previous_scan:
            prev_vulns = await db.execute(
                select(Vulnerability).where(Vulnerability.scan_id == previous_scan.id)
            )
            previous_findings = [
                {
                    "title": v.title,
                    "module": v.module,
                    "severity": v.severity.value if v.severity else "informational",
                    "recommendation": v.recommendation or "",
                }
                for v in prev_vulns.scalars().all()
            ]

        # Create a new Scan row
        new_scan = Scan(
            target_id=target.id,
            owner_id=sched.owner_id,
            status=ScanStatus.running,
            modules=sched.modules,
            started_at=datetime.now(timezone.utc),
        )
        db.add(new_scan)
        await db.flush()

        try:
            scan_output = await run_scan(sched.url, sched.modules)
            scan_time = datetime.now(timezone.utc)
            current_findings_raw = scan_output.get("findings", [])

            for finding_dict in current_findings_raw:
                vuln = Vulnerability(
                    scan_id=new_scan.id,
                    title=finding_dict["title"],
                    description=finding_dict["description"],
                    severity=_sev_to_db(finding_dict["severity"]),
                    category=finding_dict["category"],
                    module=finding_dict["module"],
                    cvss_score=finding_dict.get("cvss_score"),
                    cve=finding_dict.get("cve") or None,
                    owasp_category=finding_dict.get("owasp_category"),
                    affected_url=finding_dict.get("affected_url"),
                    evidence=finding_dict.get("evidence"),
                    recommendation=finding_dict.get("recommendation"),
                    references=finding_dict.get("references"),
                )
                db.add(vuln)

            new_scan.status = ScanStatus.completed
            new_scan.completed_at = scan_time
            new_scan.risk_score = scan_output.get("risk_score")
            new_scan.findings_count = len(current_findings_raw)

            # Diff against previous scan
            current_simple = [
                {
                    "title": f["title"],
                    "module": f["module"],
                    "severity": f.get("severity", "informational"),
                    "recommendation": f.get("recommendation", "") or "",
                }
                for f in current_findings_raw
            ]
            diff = compute_diff(current_simple, previous_findings)
            sched.last_run_at = scan_time
            await db.commit()

            # Send email on first scan or when there is a delta
            if not previous_scan or diff["new"] or diff["resolved"]:
                send_scan_diff_email(
                    to=sched.email_to,
                    url=sched.url,
                    diff=diff,
                    scan_time=scan_time,
                    risk_score=scan_output.get("risk_score", 0),
                )

        except Exception as e:
            new_scan.status = ScanStatus.failed
            new_scan.error_message = str(e)[:1000]
            new_scan.completed_at = datetime.now(timezone.utc)
            sched.last_run_at = datetime.now(timezone.utc)
            await db.commit()
