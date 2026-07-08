from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from uuid import UUID
from app.core.database import get_db
from app.models.user import User
from app.models.target import Target
from app.models.scan import Scan, Vulnerability, ScanStatus
from app.schemas.scan import ScanCreate, ScanUpdate, ScanOut, ScanDetail, ScanStats, VulnerabilityOut
from app.api.deps import get_current_user, log_audit
from app.workers.tasks import execute_scan_task
from app.core.intrusive import INTRUSIVE_MODULES
from app.services.export_service import generate_pdf, generate_pdf_gerencial, generate_csv

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post("/", response_model=ScanOut, status_code=201)
async def create_scan(
    payload: ScanCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # Verify target ownership
    target_result = await db.execute(
        select(Target).where(
            Target.id == payload.target_id,
            Target.owner_id == current_user.id,
            Target.is_active == True,
        )
    )
    target = target_result.scalar_one_or_none()
    if not target:
        raise HTTPException(404, detail="Target not found or not authorized")

    requested_intrusive = set(payload.modules or []) & INTRUSIVE_MODULES
    if requested_intrusive and not target.intrusive_testing_confirmed:
        raise HTTPException(
            403,
            detail=f"Intrusive modules {sorted(requested_intrusive)} require Target.intrusive_testing_confirmed=true",
        )

    # Prevent duplicate running scans
    running = await db.execute(
        select(Scan).where(
            Scan.target_id == payload.target_id,
            Scan.status.in_([ScanStatus.pending, ScanStatus.running]),
        )
    )
    if running.scalar_one_or_none():
        raise HTTPException(409, detail="A scan is already running for this target")

    scan = Scan(
        target_id=payload.target_id,
        owner_id=current_user.id,
        scan_type=payload.scan_type,
        modules=payload.modules or [],
        name=payload.name,
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    # Dispatch to Celery
    task = execute_scan_task.delay(str(scan.id))
    scan.celery_task_id = task.id
    await db.commit()

    await log_audit(
        db, current_user.id, "scan_created",
        resource="scan", resource_id=str(scan.id),
        ip_address=request.client.host if request.client else None,
    )
    return scan


@router.get("/", response_model=list[ScanOut])
async def list_scans(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, le=200),
    status: ScanStatus | None = None,
    target_id: UUID | None = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    q = select(Scan).where(Scan.owner_id == current_user.id)
    if status:
        q = q.where(Scan.status == status)
    if target_id:
        q = q.where(Scan.target_id == target_id)
    q = q.offset(skip).limit(limit).order_by(Scan.created_at.desc())
    result = await db.execute(q)
    return result.scalars().all()


@router.get("/stats", response_model=ScanStats)
async def scan_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    total = await db.scalar(select(func.count(Scan.id)).where(Scan.owner_id == current_user.id))

    status_rows = await db.execute(
        select(Scan.status, func.count(Scan.id))
        .where(Scan.owner_id == current_user.id)
        .group_by(Scan.status)
    )
    by_status = {row[0].value: row[1] for row in status_rows}

    sev_rows = await db.execute(
        select(Vulnerability.severity, func.count(Vulnerability.id))
        .join(Scan, Scan.id == Vulnerability.scan_id)
        .where(Scan.owner_id == current_user.id, Vulnerability.is_false_positive == False)
        .group_by(Vulnerability.severity)
    )
    by_severity = {row[0].value: row[1] for row in sev_rows}

    avg_score = await db.scalar(
        select(func.avg(Scan.risk_score)).where(
            Scan.owner_id == current_user.id,
            Scan.status == ScanStatus.completed,
            Scan.risk_score.isnot(None),
        )
    )

    recent_result = await db.execute(
        select(Scan)
        .where(Scan.owner_id == current_user.id)
        .order_by(Scan.created_at.desc())
        .limit(5)
    )

    return ScanStats(
        total_scans=total or 0,
        scans_by_status=by_status,
        vulnerabilities_by_severity=by_severity,
        average_risk_score=round(float(avg_score or 0), 1),
        recent_scans=recent_result.scalars().all(),
    )


@router.get("/{scan_id}", response_model=ScanDetail)
async def get_scan(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.owner_id == current_user.id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(404, detail="Scan not found")

    vuln_result = await db.execute(
        select(Vulnerability).where(Vulnerability.scan_id == scan.id)
        .order_by(Vulnerability.cvss_score.desc().nullslast())
    )
    vulns = vuln_result.scalars().all()
    return ScanDetail.model_validate({**scan.__dict__, "vulnerabilities": vulns})


@router.delete("/{scan_id}", status_code=204)
async def cancel_scan(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.owner_id == current_user.id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(404, detail="Scan not found")
    if scan.status not in (ScanStatus.pending, ScanStatus.running):
        raise HTTPException(400, detail="Only pending/running scans can be cancelled")
    scan.status = ScanStatus.cancelled
    await db.commit()


@router.patch("/{scan_id}", response_model=ScanOut)
async def rename_scan(
    scan_id: UUID,
    payload: ScanUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.owner_id == current_user.id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(404, detail="Scan not found")
    if payload.name is not None:
        scan.name = payload.name.strip() or None
    await db.commit()
    await db.refresh(scan)
    return scan


@router.get("/{scan_id}/export/pdf")
async def export_pdf_report(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    scan, target = await _get_scan_with_target(scan_id, current_user.id, db)
    result, scan_time = _build_result(scan)
    pdf_bytes = generate_pdf(result, target.value, scan_time)
    filename = f"{target.value.replace('https://','').replace('http://','').rstrip('/')}_{scan_time.strftime('%Y%m%d_%H%M')}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{scan_id}/export/pdf-gerencial")
async def export_pdf_gerencial_report(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    scan, target = await _get_scan_with_target(scan_id, current_user.id, db)
    result, scan_time = _build_result(scan)
    pdf_bytes = generate_pdf_gerencial(result, target.value, scan_time)
    filename = f"{target.value.replace('https://','').replace('http://','').rstrip('/')}_{scan_time.strftime('%Y%m%d_%H%M')}_gerencial.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{scan_id}/export/csv")
async def export_csv_report(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    scan, target = await _get_scan_with_target(scan_id, current_user.id, db)
    result, scan_time = _build_result(scan)
    csv_bytes = generate_csv(result, scan_time)
    filename = f"{target.value.replace('https://','').replace('http://','').rstrip('/')}_{scan_time.strftime('%Y%m%d_%H%M')}.csv"
    return Response(
        content=csv_bytes,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


async def _get_scan_with_target(scan_id: UUID, user_id, db: AsyncSession):
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.owner_id == user_id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(404, detail="Scan not found")
    if scan.status != ScanStatus.completed:
        raise HTTPException(400, detail="Export only available for completed scans")

    target_result = await db.execute(select(Target).where(Target.id == scan.target_id))
    target = target_result.scalar_one_or_none()
    if not target:
        raise HTTPException(404, detail="Target not found")

    vuln_result = await db.execute(
        select(Vulnerability).where(Vulnerability.scan_id == scan.id)
    )
    scan._vulns = vuln_result.scalars().all()
    return scan, target


def _build_result(scan) -> tuple[dict, object]:
    from datetime import datetime, timezone
    vulns = getattr(scan, "_vulns", [])
    findings = [
        {
            "title": v.title,
            "severity": v.severity.value if hasattr(v.severity, "value") else v.severity,
            "cve": v.cve or "",
            "description": v.description or "",
            "recommendation": v.recommendation or "",
            "category": v.category or "",
            "module": v.module or "",
            "affected_url": v.affected_url or "",
            "cvss_score": v.cvss_score,
            "owasp_category": v.owasp_category or "",
        }
        for v in vulns
        if not v.is_false_positive
    ]
    modules_run = scan.modules or []
    scan_time = scan.completed_at or scan.created_at
    if scan_time and hasattr(scan_time, "tzinfo") and scan_time.tzinfo:
        scan_time = scan_time.replace(tzinfo=None)
    result = {
        "findings": findings,
        "risk_score": scan.risk_score or 0,
        "duration_ms": getattr(scan, "duration_ms", None) or 0,
        "modules_run": modules_run,
    }
    return result, scan_time or datetime.now()


@router.patch("/{scan_id}/vulnerabilities/{vuln_id}/false-positive")
async def mark_false_positive(
    scan_id: UUID,
    vuln_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    scan_result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.owner_id == current_user.id)
    )
    if not scan_result.scalar_one_or_none():
        raise HTTPException(404, detail="Scan not found")

    vuln_result = await db.execute(
        select(Vulnerability).where(Vulnerability.id == vuln_id, Vulnerability.scan_id == scan_id)
    )
    vuln = vuln_result.scalar_one_or_none()
    if not vuln:
        raise HTTPException(404, detail="Vulnerability not found")

    vuln.is_false_positive = not vuln.is_false_positive
    await db.commit()
    return {"is_false_positive": vuln.is_false_positive}
