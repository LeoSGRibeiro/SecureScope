import asyncio
import uuid
from datetime import datetime, timezone
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
