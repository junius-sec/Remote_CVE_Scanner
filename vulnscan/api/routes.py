from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_, Integer
from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime
import csv
import io

from ..models.database import get_db
from ..models.schemas import Host, Package, CVE, Finding, ScanHistory
from ..core.nvd_client import NVDClient
from ..core.matcher import VulnerabilityMatcher
from ..core.pdf_generator import VulnerabilityPDFGenerator

router = APIRouter()


@router.get("/api/dashboard")
async def get_dashboard(
    scan_id: Optional[int] = Query(None),
    session: AsyncSession = Depends(get_db)
):
    """Get dashboard statistics (특정 스캔 또는 최신 스캔)"""
    host_count = await session.execute(select(func.count(Host.id)))
    total_hosts = host_count.scalar()

    # scan_id가 없으면 최신 완료된 스캔 사용
    if scan_id is None:
        latest_scan = await session.execute(
            select(ScanHistory)
            .where(ScanHistory.status == "completed")
            .order_by(ScanHistory.scan_started.desc())
            .limit(1)
        )
        latest = latest_scan.scalar_one_or_none()
        if latest:
            scan_id = latest.id

    # 기본 쿼리 조건
    scan_filter = Finding.scan_id == scan_id if scan_id else True

    high_risk = await session.execute(
        select(func.count(Finding.id))
        .join(CVE)
        .where(and_(
            scan_filter,
            CVE.cvss_v3_score.is_not(None),
            CVE.cvss_v3_score >= 7.0
        ))
    )
    high_risk_count = high_risk.scalar()

    unauthorized = await session.execute(
        select(func.count(Finding.id))
        .where(and_(scan_filter, Finding.is_unauthorized_access == True))
    )
    unauthorized_count = unauthorized.scalar()

    total_findings = await session.execute(
        select(func.count(Finding.id)).where(scan_filter)
    )
    total_findings_count = total_findings.scalar()

    # KEV 등재 CVE 수
    kev_count = await session.execute(
        select(func.count(Finding.id))
        .join(CVE)
        .where(and_(scan_filter, CVE.is_kev == True))
    )
    kev_findings_count = kev_count.scalar()

    # 활성 사용 중인 취약 패키지 수
    active_pkg = await session.execute(
        select(func.count(Finding.id))
        .where(and_(scan_filter, Finding.pkg_usage_level == "active"))
    )
    active_pkg_count = active_pkg.scalar()

    # 패치 가능한 취약점 수
    patchable = await session.execute(
        select(func.count(Finding.id))
        .where(and_(scan_filter, Finding.has_patch_available == True))
    )
    patchable_count = patchable.scalar()

    # CRITICAL 우선순위 수
    critical_priority = await session.execute(
        select(func.count(Finding.id))
        .where(and_(scan_filter, Finding.priority_level == "CRITICAL"))
    )
    critical_count = critical_priority.scalar()

    # 실행 중인 서비스 취약점 수
    running_services = await session.execute(
        select(func.count(Finding.id))
        .where(and_(
            scan_filter,
            or_(
                Finding.pkg_is_running == True,
                Finding.pkg_is_service == True,
                Finding.pkg_usage_level == "active"
            )
        ))
    )
    running_count = running_services.scalar()

    # 권한 상승 CVE 수
    privesc = await session.execute(
        select(func.count(Finding.id))
        .where(and_(scan_filter, Finding.is_privilege_escalation == True))
    )
    privesc_count = privesc.scalar()

    # 커널 CVE 수
    kernel_cves = await session.execute(
        select(func.count(Finding.id))
        .where(and_(scan_filter, Finding.is_kernel_cve == True))
    )
    kernel_count = kernel_cves.scalar()

    # 네트워크 리스닝 패키지 취약점 수
    listening = await session.execute(
        select(func.count(Finding.id))
        .where(and_(scan_filter, Finding.pkg_is_listening == True))
    )
    listening_count = listening.scalar()

    return {
        "total_hosts": total_hosts,
        "high_risk_count": high_risk_count,
        "unauthorized_count": unauthorized_count,
        "total_findings": total_findings_count,
        "scan_id": scan_id,
        # 새로운 통계
        "kev_count": kev_findings_count or 0,
        "active_package_count": active_pkg_count or 0,
        "patchable_count": patchable_count or 0,
        "critical_priority_count": critical_count or 0,
        # 추가 통계
        "running_service_count": running_count or 0,
        "privesc_count": privesc_count or 0,
        "kernel_cve_count": kernel_count or 0,
        "listening_count": listening_count or 0
    }


@router.get("/api/bubble")
async def get_bubble_data(
    scan_id: Optional[int] = Query(None),
    cvss_min: Optional[float] = Query(None),
    epss_min: Optional[float] = Query(None),
    zone: Optional[str] = Query(None),
    unauthorized_only: bool = Query(False),
    session: AsyncSession = Depends(get_db)
):
    """Get bubble chart data - grouped by package"""
    query = select(Finding).join(CVE).join(Package).join(Host)

    # scan_id가 없으면 최신 완료된 스캔 사용
    if scan_id is None:
        latest_scan = await session.execute(
            select(ScanHistory)
            .where(ScanHistory.status == "completed")
            .order_by(ScanHistory.scan_started.desc())
            .limit(1)
        )
        latest = latest_scan.scalar_one_or_none()
        if latest:
            scan_id = latest.id

    # scan_id 필터 적용
    if scan_id:
        query = query.where(Finding.scan_id == scan_id)

    if cvss_min:
        query = query.where(and_(CVE.cvss_v3_score.is_not(None), CVE.cvss_v3_score >= cvss_min))

    if epss_min is not None:
        epss_filter = epss_min / 100 if epss_min > 1 else epss_min
        query = query.where(and_(CVE.epss_score.is_not(None), CVE.epss_score >= epss_filter))

    if zone:
        query = query.where(Host.zone == zone)

    if unauthorized_only:
        query = query.where(Finding.is_unauthorized_access == True)

    findings_result = await session.execute(query)
    findings = findings_result.scalars().all()

    if not findings:
        return {"points": []}

    packages_dict = {}

    for finding in findings:
        await session.refresh(finding, ["cve", "package"])

        pkg_name = finding.package.name

        if pkg_name not in packages_dict:
            packages_dict[pkg_name] = {
                "package": pkg_name,
                "cve_count": 0,
                "cvss_scores": [],
                "epss_scores": [],
                "kev_count": 0,
                "running_count": 0,
                "listening_count": 0
            }

        pkg_entry = packages_dict[pkg_name]
        pkg_entry["cve_count"] += 1

        if finding.cve.cvss_v3_score is not None:
            pkg_entry["cvss_scores"].append(finding.cve.cvss_v3_score)
        if finding.cve.epss_score is not None:
            pkg_entry["epss_scores"].append(finding.cve.epss_score)
        if finding.cve.is_kev:
            pkg_entry["kev_count"] += 1
        if finding.pkg_is_running or finding.pkg_usage_level == "active":
            pkg_entry["running_count"] += 1
        if finding.pkg_is_listening:
            pkg_entry["listening_count"] += 1

    points = []
    for data in packages_dict.values():
        max_cvss = max(data["cvss_scores"]) if data["cvss_scores"] else 0
        max_epss = max(data["epss_scores"]) if data["epss_scores"] else 0

        points.append({
            "package": data["package"],
            "cve_count": data["cve_count"],
            "cvss_max": max_cvss,
            "epss_max": max_epss,
            "kev_count": data["kev_count"],
            "running_count": data["running_count"],
            "listening_count": data["listening_count"]
        })

    points.sort(key=lambda x: (x["cve_count"], x["cvss_max"]), reverse=True)

    return {"points": points[:60]}


@router.get("/api/findings")
async def get_findings(
    scan_id: Optional[int] = Query(None),
    cvss_min: Optional[float] = Query(None),
    epss_min: Optional[float] = Query(None),
    zone: Optional[str] = Query(None),
    host_id: Optional[int] = Query(None),
    attack_vector: Optional[str] = Query(None),
    unauthorized_only: bool = Query(False),
    no_user_interaction: bool = Query(False),
    impact_filter: Optional[str] = Query(None),
    package_name: Optional[str] = Query(None),
    cve_id: Optional[str] = Query(None),
    limit: Optional[int] = Query(None),
    sort_by: Optional[str] = Query(None),  # cvss, epss, priority, discovered_at
    sort_order: Optional[str] = Query("desc"),  # asc, desc
    # 새로운 필터 옵션
    kev_only: bool = Query(False),  # KEV 등재 CVE만
    active_only: bool = Query(False),  # 활성 사용 패키지만
    patchable_only: bool = Query(False),  # 패치 가능한 것만
    priority_level: Optional[str] = Query(None),  # CRITICAL, HIGH, MEDIUM, LOW
    confidence_level: Optional[str] = Query(None),  # confirmed, potential
    listening_only: bool = Query(False),  # 네트워크 리스닝 패키지만
    running_only: bool = Query(False),  # 실행 중인 서비스만
    privesc_only: bool = Query(False),  # 권한 상승 CVE만
    kernel_only: bool = Query(False),  # 커널 CVE만
    risk_mode: Optional[str] = Query(None),  # privesc, unauthorized
    risk_category: Optional[str] = Query(None),  # kernel, suid, service, container, network, local, etc.
    cve_ids: Optional[str] = Query(None),  # 쉼표로 구분된 CVE ID 목록
    session: AsyncSession = Depends(get_db),
    response: Response = None
):
    """Get filtered findings"""
    query = select(Finding).join(CVE).join(Package).join(Host)

    # scan_id가 없으면 최신 완료된 스캔 사용
    if scan_id is None:
        latest_scan = await session.execute(
            select(ScanHistory)
            .where(ScanHistory.status == "completed")
            .order_by(ScanHistory.scan_started.desc())
            .limit(1)
        )
        latest = latest_scan.scalar_one_or_none()
        if latest:
            scan_id = latest.id

    # scan_id 필터 적용
    base_conditions = []
    if scan_id:
        base_conditions.append(Finding.scan_id == scan_id)
        query = query.where(Finding.scan_id == scan_id)

    if cvss_min:
        query = query.where(and_(CVE.cvss_v3_score.is_not(None), CVE.cvss_v3_score >= cvss_min))

    if epss_min is not None:
        epss_filter = epss_min / 100 if epss_min > 1 else epss_min
        query = query.where(and_(CVE.epss_score.is_not(None), CVE.epss_score >= epss_filter))

    if zone:
        base_conditions.append(Host.zone == zone)
        query = query.where(Host.zone == zone)

    if host_id:
        base_conditions.append(Finding.host_id == host_id)
        query = query.where(Finding.host_id == host_id)

    if attack_vector:
        query = query.where(CVE.attack_vector == attack_vector)

    if unauthorized_only:
        query = query.where(Finding.is_unauthorized_access == True)

    if no_user_interaction:
        query = query.where(CVE.user_interaction == "NONE")

    if impact_filter == "HIGH":
        # High impact: High confidentiality, integrity, or availability impact
        query = query.where(
            or_(
                CVE.confidentiality_impact == "HIGH",
                CVE.integrity_impact == "HIGH",
                CVE.availability_impact == "HIGH"
            )
        )
    elif impact_filter == "CRITICAL_SYSTEM":
        # Critical system packages (kernel, libc, bash, sudo, etc.)
        critical_packages = [
            'linux-image', 'linux-headers', 'kernel',
            'libc6', 'glibc', 'bash', 'sudo', 'systemd',
            'openssh-server', 'openssh-client', 'openssl', 'libssl'
        ]
        package_conditions = [Package.name.like(f"{pkg}%") for pkg in critical_packages]
        query = query.where(or_(*package_conditions))

    if package_name:
        query = query.where(Package.name == package_name)
    if cve_id:
        query = query.where(CVE.cve_id == cve_id)

    # 새로운 필터 적용
    if kev_only:
        query = query.where(CVE.is_kev == True)

    if active_only:
        query = query.where(Finding.pkg_usage_level == "active")

    if patchable_only:
        query = query.where(Finding.has_patch_available == True)

    if priority_level:
        query = query.where(Finding.priority_level == priority_level.upper())

    if confidence_level:
        query = query.where(Finding.confidence_level == confidence_level.lower())

    if listening_only:
        query = query.where(Finding.pkg_is_listening == True)

    if running_only:
        query = query.where(or_(
            Finding.pkg_is_running == True,
            Finding.pkg_is_service == True,
            Finding.pkg_usage_level == "active"
        ))

    if privesc_only:
        query = query.where(Finding.is_privilege_escalation == True)

    if kernel_only:
        query = query.where(Finding.is_kernel_cve == True)

    # CVE ID 목록 필터 (Sankey 카테고리 클릭)
    if cve_ids:
        cve_id_list = [cid.strip() for cid in cve_ids.split(',') if cid.strip()]
        if cve_id_list:
            query = query.where(CVE.cve_id.in_(cve_id_list))

    total_query = (
        select(func.count(Finding.id))
        .select_from(Finding)
        .join(CVE)
        .join(Package)
        .join(Host)
    )
    if base_conditions:
        total_query = total_query.where(and_(*base_conditions))
    total_count_result = await session.execute(total_query)
    total_count = total_count_result.scalar() or 0

    filtered_query = (
        select(func.count(Finding.id))
        .select_from(Finding)
        .join(CVE)
        .join(Package)
        .join(Host)
    )
    filtered_conditions = list(base_conditions)

    if cvss_min:
        filtered_conditions.append(and_(CVE.cvss_v3_score.is_not(None), CVE.cvss_v3_score >= cvss_min))

    if epss_min is not None:
        epss_filter = epss_min / 100 if epss_min > 1 else epss_min
        filtered_conditions.append(and_(CVE.epss_score.is_not(None), CVE.epss_score >= epss_filter))

    if attack_vector:
        filtered_conditions.append(CVE.attack_vector == attack_vector)

    if unauthorized_only:
        filtered_conditions.append(Finding.is_unauthorized_access == True)

    if no_user_interaction:
        filtered_conditions.append(CVE.user_interaction == "NONE")

    if impact_filter == "HIGH":
        filtered_conditions.append(
            or_(
                CVE.confidentiality_impact == "HIGH",
                CVE.integrity_impact == "HIGH",
                CVE.availability_impact == "HIGH"
            )
        )
    elif impact_filter == "CRITICAL_SYSTEM":
        critical_packages = [
            'linux-image', 'linux-headers', 'kernel',
            'libc6', 'glibc', 'bash', 'sudo', 'systemd',
            'openssh-server', 'openssh-client', 'openssl', 'libssl'
        ]
        package_conditions = [Package.name.like(f"{pkg}%") for pkg in critical_packages]
        filtered_conditions.append(or_(*package_conditions))

    if package_name:
        filtered_conditions.append(Package.name == package_name)

    if kev_only:
        filtered_conditions.append(CVE.is_kev == True)

    if active_only:
        filtered_conditions.append(Finding.pkg_usage_level == "active")

    if patchable_only:
        filtered_conditions.append(Finding.has_patch_available == True)

    if priority_level:
        filtered_conditions.append(Finding.priority_level == priority_level.upper())

    if confidence_level:
        filtered_conditions.append(Finding.confidence_level == confidence_level.lower())

    if listening_only:
        filtered_conditions.append(Finding.pkg_is_listening == True)

    if running_only:
        filtered_conditions.append(or_(
            Finding.pkg_is_running == True,
            Finding.pkg_is_service == True,
            Finding.pkg_usage_level == "active"
        ))

    if privesc_only:
        filtered_conditions.append(Finding.is_privilege_escalation == True)

    if kernel_only:
        filtered_conditions.append(Finding.is_kernel_cve == True)

    if cve_ids:
        cve_id_list = [cid.strip() for cid in cve_ids.split(',') if cid.strip()]
        if cve_id_list:
            filtered_conditions.append(CVE.cve_id.in_(cve_id_list))

    if filtered_conditions:
        filtered_query = filtered_query.where(and_(*filtered_conditions))
    filtered_count_result = await session.execute(filtered_query)
    filtered_count = filtered_count_result.scalar() or 0

    # Apply sorting
    if sort_by:
        sort_column = None
        
        if sort_by == "cvss":
            if sort_order == "asc":
                query = query.order_by(CVE.cvss_v3_score.asc().nulls_last())
            else:
                query = query.order_by(CVE.cvss_v3_score.desc().nulls_last())
        elif sort_by == "epss":
            if sort_order == "asc":
                query = query.order_by(CVE.epss_score.asc().nulls_last())
            else:
                query = query.order_by(CVE.epss_score.desc().nulls_last())
        elif sort_by == "package":
            if sort_order == "asc":
                query = query.order_by(Package.name.asc())
            else:
                query = query.order_by(Package.name.desc())
        elif sort_by == "cve":
            cve_year = func.substr(CVE.cve_id, 5, 4).cast(Integer)
            cve_number = func.substr(CVE.cve_id, 10).cast(Integer)
            if sort_order == "asc":
                query = query.order_by(cve_year.asc().nulls_last(), cve_number.asc().nulls_last())
            else:
                query = query.order_by(cve_year.desc().nulls_last(), cve_number.desc().nulls_last())
        elif sort_by == "priority":
            sort_column = Finding.priority_score
        elif sort_by == "discovered_at":
            sort_column = Finding.discovered_at
        elif sort_by == "last_used":
            # 실행 중/활성 패키지 우선 정렬
            from sqlalchemy import case
            active_score = case(
                (Finding.pkg_usage_level == 'active', 2),
                (Finding.pkg_is_running == True, 1),
                else_=0
            )
            if sort_order == "asc":
                query = query.order_by(active_score.asc(), Finding.pkg_last_used.asc())
            else:
                query = query.order_by(active_score.desc(), Finding.pkg_last_used.desc().nulls_last())
        else:
            sort_column = Finding.priority_score  # default to priority

        if sort_column is not None:
            if sort_order == "asc":
                query = query.order_by(sort_column.asc())
            else:
                query = query.order_by(sort_column.desc())
    else:
        # 기본 정렬: 우선순위 점수 내림차순 (가장 위험한 것 먼저)
        query = query.order_by(Finding.priority_score.desc().nulls_last())

    # Apply limit if specified, otherwise default to 1000
    query_limit = limit if limit is not None else 1000
    result = await session.execute(query.limit(query_limit))
    findings = result.scalars().all()

    findings_data = []
    for finding in findings:
        await session.refresh(finding, ["host", "package", "cve"])

        findings_data.append({
            "id": finding.id,
            "list_index": finding.id,
            "hostname": finding.host.hostname,
            "zone": finding.host.zone,
            "package_name": finding.package.name,
            "package_version": finding.package.version,
            "cve_id": finding.cve.cve_id,
            "cvss_score": finding.cve.cvss_v3_score,
            "severity": finding.cve.cvss_v3_severity,
            "attack_vector": finding.cve.attack_vector,
            "user_interaction": finding.cve.user_interaction,
            "description": finding.cve.description,
            "is_unauthorized_access": finding.is_unauthorized_access,
            "risk_level": finding.risk_level,
            "discovered_at": finding.discovered_at,
            # EPSS 점수
            "epss_score": finding.cve.epss_score,
            "epss_percentile": finding.cve.epss_percentile,
            # KEV 정보
            "is_kev": finding.cve.is_kev or False,
            "kev_date_added": finding.cve.kev_date_added,
            "kev_ransomware": finding.cve.kev_ransomware or False,
            # 패키지 사용 상태
            "pkg_is_running": finding.pkg_is_running or False,
            "pkg_is_service": finding.pkg_is_service or False,
            "pkg_is_listening": finding.pkg_is_listening or False,
            "pkg_listening_ports": finding.pkg_listening_ports,
            "pkg_usage_level": finding.pkg_usage_level,
            "pkg_last_used": finding.pkg_last_used,
            # 패치 정보
            "has_patch_available": finding.has_patch_available or False,
            "patch_version": finding.patch_version,
            "confidence_level": finding.confidence_level or "confirmed",
            # 우선순위
            "priority_score": finding.priority_score,
            "priority_level": finding.priority_level,
            # 권한 상승 및 커널
            "is_privilege_escalation": finding.is_privilege_escalation or False,
            "privesc_reason": finding.privesc_reason,
            "is_kernel_cve": finding.is_kernel_cve or False
        })

    if response is not None:
        response.headers["X-Total-Count"] = str(total_count)
        response.headers["X-Filtered-Count"] = str(filtered_count)

    return findings_data


@router.get("/api/finding/{finding_id}")
async def get_finding_detail(finding_id: int, session: AsyncSession = Depends(get_db)):
    """Get detailed information about a specific finding with patch commands"""
    result = await session.execute(
        select(Finding).where(Finding.id == finding_id)
    )
    finding = result.scalar_one_or_none()

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    await session.refresh(finding, ["host", "package", "cve"])

    # Generate patch commands based on OS type
    patch_commands = _generate_patch_commands(
        finding.package.name,
        finding.package.version,
        finding.host.os_type
    )

    return {
        "id": finding.id,
        "host": {
            "id": finding.host.id,
            "hostname": finding.host.hostname,
            "ip_address": finding.host.ip_address,
            "zone": finding.host.zone,
            "os_type": finding.host.os_type,
            "os_version": finding.host.os_version
        },
        "package": {
            "id": finding.package.id,
            "name": finding.package.name,
            "version": finding.package.version,
            "architecture": finding.package.architecture,
            "package_manager": finding.package.package_manager
        },
        "cve": {
            "cve_id": finding.cve.cve_id,
            "description": finding.cve.description,
            "published_date": finding.cve.published_date,
            "last_modified": finding.cve.last_modified,
            "cvss_v3_score": finding.cve.cvss_v3_score,
            "cvss_v3_vector": finding.cve.cvss_v3_vector,
            "cvss_v3_severity": finding.cve.cvss_v3_severity,
            "attack_vector": finding.cve.attack_vector,
            "attack_complexity": finding.cve.attack_complexity,
            "privileges_required": finding.cve.privileges_required,
            "user_interaction": finding.cve.user_interaction,
            "scope": finding.cve.scope,
            "confidentiality_impact": finding.cve.confidentiality_impact,
            "integrity_impact": finding.cve.integrity_impact,
            "availability_impact": finding.cve.availability_impact,
            "references": finding.cve.references.split("|") if finding.cve.references else [],
            # EPSS 점수
            "epss_score": finding.cve.epss_score,
            "epss_percentile": finding.cve.epss_percentile,
            # KEV 정보
            "is_kev": finding.cve.is_kev or False,
            "kev_date_added": finding.cve.kev_date_added,
            "kev_due_date": finding.cve.kev_due_date,
            "kev_ransomware": finding.cve.kev_ransomware or False
        },
        "risk_level": finding.risk_level,
        "is_unauthorized_access": finding.is_unauthorized_access,
        "status": finding.status,
        "discovered_at": finding.discovered_at,
        # 패키지 사용 상태
        "package_usage": {
            "is_running": finding.pkg_is_running or False,
            "is_service": finding.pkg_is_service or False,
            "is_listening": finding.pkg_is_listening or False,
            "listening_ports": finding.pkg_listening_ports.split(",") if finding.pkg_listening_ports else [],
            "usage_level": finding.pkg_usage_level,
            "last_used": finding.pkg_last_used
        },
        # 패치 정보
        "patch_info": {
            "has_patch_available": finding.has_patch_available or False,
            "patch_version": finding.patch_version,
            "confidence_level": finding.confidence_level or "confirmed"
        },
        # 우선순위
        "priority": {
            "score": finding.priority_score,
            "level": finding.priority_level
        },
        # 권한 상승 및 커널
        "privilege_escalation": {
            "is_privesc": finding.is_privilege_escalation or False,
            "reason": finding.privesc_reason
        },
        "is_kernel_cve": finding.is_kernel_cve or False,
        # 패치 명령어
        "patch_commands": patch_commands
    }


def _generate_patch_commands(pkg_name: str, current_version: str, os_type: str) -> dict:
    """Generate patch and rollback commands for a package"""
    os_type = os_type.lower() if os_type else "ubuntu"

    if os_type in ["ubuntu", "debian"]:
        return {
            "update": {
                "title": "패키지 업데이트",
                "commands": [
                    {
                        "cmd": "sudo apt update",
                        "desc": "패키지 목록 업데이트"
                    },
                    {
                        "cmd": f"sudo apt install --only-upgrade {pkg_name}",
                        "desc": f"{pkg_name} 최신 버전으로 업그레이드"
                    }
                ]
            },
            "verify": {
                "title": "업데이트 확인",
                "commands": [
                    {
                        "cmd": f"apt-cache policy {pkg_name}",
                        "desc": "설치된 버전 및 사용 가능한 버전 확인"
                    },
                    {
                        "cmd": f"dpkg -l {pkg_name}",
                        "desc": "패키지 상태 확인"
                    }
                ]
            },
            "rollback": {
                "title": f"이전 버전({current_version})으로 롤백",
                "warning": "롤백은 의존성 문제를 일으킬 수 있습니다. 신중히 진행하세요.",
                "commands": [
                    {
                        "cmd": f"sudo apt install {pkg_name}={current_version}",
                        "desc": f"현재 버전({current_version})으로 다운그레이드"
                    },
                    {
                        "cmd": f"sudo apt-mark hold {pkg_name}",
                        "desc": "패키지 자동 업데이트 방지 (hold 설정)"
                    }
                ]
            },
            "unhold": {
                "title": "Hold 해제",
                "commands": [
                    {
                        "cmd": f"sudo apt-mark unhold {pkg_name}",
                        "desc": "패키지 hold 상태 해제"
                    }
                ]
            }
        }
    elif os_type in ["centos", "rhel", "fedora"]:
        return {
            "update": {
                "title": "패키지 업데이트",
                "commands": [
                    {
                        "cmd": f"sudo yum update {pkg_name}",
                        "desc": f"{pkg_name} 최신 버전으로 업그레이드"
                    }
                ]
            },
            "verify": {
                "title": "업데이트 확인",
                "commands": [
                    {
                        "cmd": f"yum info {pkg_name}",
                        "desc": "패키지 정보 확인"
                    },
                    {
                        "cmd": f"rpm -q {pkg_name}",
                        "desc": "설치된 버전 확인"
                    }
                ]
            },
            "rollback": {
                "title": f"이전 버전({current_version})으로 롤백",
                "warning": "롤백은 의존성 문제를 일으킬 수 있습니다. 신중히 진행하세요.",
                "commands": [
                    {
                        "cmd": f"sudo yum downgrade {pkg_name}-{current_version}",
                        "desc": f"현재 버전({current_version})으로 다운그레이드"
                    },
                    {
                        "cmd": f"sudo yum versionlock add {pkg_name}",
                        "desc": "패키지 버전 고정 (versionlock 필요)"
                    }
                ]
            },
            "unhold": {
                "title": "버전 잠금 해제",
                "commands": [
                    {
                        "cmd": f"sudo yum versionlock delete {pkg_name}",
                        "desc": "패키지 버전 잠금 해제"
                    }
                ]
            }
        }
    else:
        return {
            "message": f"지원되지 않는 OS 타입: {os_type}"
        }


@router.get("/api/report/csv")
async def export_csv(session: AsyncSession = Depends(get_db)):
    """Export findings to CSV"""
    from fastapi.responses import StreamingResponse

    result = await session.execute(
        select(Finding).join(CVE).join(Package).join(Host).limit(10000)
    )
    findings = result.scalars().all()

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "Hostname", "Zone", "IP Address", "Package", "Version",
        "CVE ID", "CVSS Score", "Severity", "Risk Level",
        "Attack Vector", "Unauthorized Access", "Discovered At"
    ])

    for finding in findings:
        await session.refresh(finding, ["host", "package", "cve"])

        writer.writerow([
            finding.host.hostname,
            finding.host.zone,
            finding.host.ip_address,
            finding.package.name,
            finding.package.version,
            finding.cve.cve_id,
            finding.cve.cvss_v3_score or "N/A",
            finding.cve.cvss_v3_severity or "N/A",
            finding.risk_level,
            finding.cve.attack_vector or "N/A",
            "Yes" if finding.is_unauthorized_access else "No",
            finding.discovered_at.strftime("%Y-%m-%d %H:%M:%S")
        ])

    output.seek(0)

    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=vulnerability_report.csv"}
    )


@router.get("/api/report/pdf")
async def export_pdf(session: AsyncSession = Depends(get_db)):
    """Export findings to PDF report"""
    from fastapi.responses import Response

    # Get host information
    host_result = await session.execute(select(Host).limit(1))
    host = host_result.scalar_one_or_none()

    if not host:
        raise HTTPException(status_code=404, detail="No host found")

    host_info = {
        "hostname": host.hostname,
        "ip_address": host.ip_address,
        "os_type": host.os_type,
        "os_version": host.os_version or "Unknown",
        "zone": host.zone
    }

    # Get dashboard statistics
    high_risk = await session.execute(
        select(func.count(Finding.id))
        .join(CVE)
        .where(and_(CVE.cvss_v3_score.is_not(None), CVE.cvss_v3_score >= 7.0))
    )
    high_risk_count = high_risk.scalar()

    unauthorized = await session.execute(
        select(func.count(Finding.id))
        .where(Finding.is_unauthorized_access == True)
    )
    unauthorized_count = unauthorized.scalar()

    total_findings_result = await session.execute(select(func.count(Finding.id)))
    total_findings_count = total_findings_result.scalar()

    dashboard_stats = {
        "total_findings": total_findings_count,
        "high_risk_count": high_risk_count,
        "unauthorized_count": unauthorized_count
    }

    # Get all findings
    findings_result = await session.execute(
        select(Finding).join(CVE).join(Package).join(Host).limit(1000)
    )
    findings = findings_result.scalars().all()

    findings_data = []
    for finding in findings:
        await session.refresh(finding, ["host", "package", "cve"])

        findings_data.append({
            "hostname": finding.host.hostname,
            "package_name": finding.package.name,
            "package_version": finding.package.version,
            "cve_id": finding.cve.cve_id,
            "cvss_score": finding.cve.cvss_v3_score,
            "severity": finding.cve.cvss_v3_severity,
            "risk_level": finding.risk_level,
            "is_unauthorized_access": finding.is_unauthorized_access
        })

    # Get package summary
    package_count_result = await session.execute(
        select(func.count(func.distinct(Package.id)))
        .join(Finding)
        .where(Finding.package_id == Package.id)
    )
    package_count = package_count_result.scalar()

    package_summary = {
        "total_packages": package_count
    }

    # Generate PDF
    pdf_generator = VulnerabilityPDFGenerator()
    pdf_bytes = pdf_generator.generate_report(
        host_info=host_info,
        dashboard_stats=dashboard_stats,
        findings=findings_data,
        package_summary=package_summary
    )

    # Return PDF
    filename = f"vulnerability_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@router.get("/api/cve/{cve_id}")
async def get_cve_detail(cve_id: str, session: AsyncSession = Depends(get_db)):
    """Get CVE detail information"""
    # DB에서 먼저 조회
    result = await session.execute(
        select(CVE).where(CVE.cve_id == cve_id)
    )
    cve = result.scalar_one_or_none()
    
    if cve:
        # references를 '\n'과 '|' 모두로 split하고 중복 제거
        refs = []
        if cve.references:
            # 먼저 '\n'으로 split
            for line in cve.references.split('\n'):
                # 각 라인을 '|'로 다시 split
                for ref in line.split('|'):
                    ref = ref.strip().rstrip('|').strip()  # 양쪽 공백 및 | 제거
                    if ref and ref not in refs:
                        refs.append(ref)
        
        return {
            "cve_id": cve.cve_id,
            "cvss": cve.cvss_v3_score,
            "severity": cve.cvss_v3_severity,
            "description": cve.description,
            "published_date": cve.published_date.isoformat() if cve.published_date else None,
            "last_modified": cve.last_modified.isoformat() if cve.last_modified else None,
            "epss": cve.epss_score,
            "is_kev": cve.is_kev,
            "attack_vector": cve.attack_vector,
            "attack_complexity": cve.attack_complexity,
            "references": refs,
        }
    
    # DB에 없으면 NVD API로 조회
    nvd = NVDClient()
    cve_data = await nvd.get_cve_details(cve_id)
    
    if cve_data:
        return {
            "cve_id": cve_id,
            "cvss": cve_data.get('cvss', 0),
            "description": cve_data.get('description', ''),
            "published_date": cve_data.get('published_date'),
            "last_modified": cve_data.get('last_modified'),
            "epss": cve_data.get('epss', 0),
            "is_kev": cve_data.get('is_kev', False),
            "references": cve_data.get('references', []),
        }
    
    raise HTTPException(status_code=404, detail="CVE not found")


@router.get("/api/system/kernel")
async def get_kernel_info():
    """Get kernel version and security info"""
    from ..core.kernel_analyzer import KernelAnalyzer, NetworkExposureAnalyzer

    kernel_analyzer = KernelAnalyzer()
    network_analyzer = NetworkExposureAnalyzer()

    kernel_info = await kernel_analyzer.get_kernel_info()
    security_info = await kernel_analyzer.analyze_kernel_security()
    modules = await kernel_analyzer.get_loaded_modules()

    return {
        "kernel": kernel_info,
        "security": security_info,
        "loaded_modules": {
            "total": len(modules),
            "list": modules[:50]  # 상위 50개만
        }
    }


@router.get("/api/system/services")
async def get_running_services():
    """Get running services and listening ports"""
    from ..core.kernel_analyzer import NetworkExposureAnalyzer

    analyzer = NetworkExposureAnalyzer()

    services = await analyzer.get_listening_services()
    daemons = await analyzer.get_running_daemons()

    # 외부 노출 서비스 분리
    external_services = [s for s in services if s.get("is_external")]
    internal_services = [s for s in services if not s.get("is_external")]

    return {
        "listening_services": {
            "total": len(services),
            "external": external_services,
            "internal": internal_services
        },
        "running_daemons": {
            "total": len(daemons),
            "list": daemons[:100]  # 상위 100개만
        }
    }



@router.get("/api/scan-history")
async def get_scan_history(session: AsyncSession = Depends(get_db)):
    """Get all scan history records"""
    result = await session.execute(
        select(ScanHistory)
        .order_by(ScanHistory.scan_started.desc())
        .limit(100)
    )
    scans = result.scalars().all()

    return [
        {
            "id": scan.id,
            "scan_started": scan.scan_started,
            "scan_completed": scan.scan_completed,
            "status": scan.status,
            "packages_found": scan.packages_found,
            "cves_found": scan.cves_found,
            "high_risk_count": scan.high_risk_count,
            "duration_seconds": int((scan.scan_completed - scan.scan_started).total_seconds()) if scan.scan_completed else None
        }
        for scan in scans
    ]


@router.get("/api/scan-history/{scan_id}")
async def get_scan_history_detail(scan_id: int, session: AsyncSession = Depends(get_db)):
    """Get specific scan history with vulnerabilities"""
    result = await session.execute(
        select(ScanHistory).where(ScanHistory.id == scan_id)
    )
    scan = result.scalar_one_or_none()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan history not found")
    
    # Get findings for this scan
    findings_result = await session.execute(
        select(Finding, Package, CVE)
        .join(Package, Finding.package_id == Package.id)
        .join(CVE, Finding.cve_id == CVE.id)
        .where(Finding.scan_id == scan_id)
        .order_by(CVE.cvss_v3_score.desc().nullslast())
    )
    rows = findings_result.all()
    
    vulnerabilities = []
    for finding, package, cve in rows:
        vulnerabilities.append({
            "cve_id": cve.cve_id,
            "package_name": package.name,
            "package_version": package.version,
            "cvss": cve.cvss_v3_score,
            "epss": cve.epss_score,
            "is_kev": cve.is_kev,
            "description": cve.description[:200] if cve.description else "",
        })
    
    return {
        "id": scan.id,
        "scan_started": scan.scan_started,
        "scan_completed": scan.scan_completed,
        "status": scan.status,
        "packages_found": scan.packages_found,
        "cves_found": scan.cves_found,
        "high_risk_count": scan.high_risk_count,
        "vulnerabilities": vulnerabilities,
    }


@router.delete("/api/scan-history/{scan_id}")
async def delete_scan_history(scan_id: int, session: AsyncSession = Depends(get_db)):
    """Delete a specific scan history and its associated data"""
    # Note: This only deletes the scan history record
    # Findings and packages from this scan will remain unless manually cleaned
    result = await session.execute(
        select(ScanHistory).where(ScanHistory.id == scan_id)
    )
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan history not found")

    await session.delete(scan)
    await session.commit()

    return {"message": "Scan history deleted successfully"}


@router.get("/api/scan-history/compare")
async def compare_scans(
    scan_id_1: int = Query(...),
    scan_id_2: int = Query(...),
    session: AsyncSession = Depends(get_db)
):
    """Compare two scan results"""
    # Get both scan records
    scan1_result = await session.execute(
        select(ScanHistory).where(ScanHistory.id == scan_id_1)
    )
    scan1 = scan1_result.scalar_one_or_none()

    scan2_result = await session.execute(
        select(ScanHistory).where(ScanHistory.id == scan_id_2)
    )
    scan2 = scan2_result.scalar_one_or_none()

    if not scan1 or not scan2:
        raise HTTPException(status_code=404, detail="One or both scans not found")

    # Get findings for scan 1 (직접 scan_id로 조회)
    findings1_result = await session.execute(
        select(Finding)
        .join(CVE)
        .join(Package)
        .where(Finding.scan_id == scan_id_1)
    )
    findings1 = findings1_result.scalars().all()

    # Get findings for scan 2 (직접 scan_id로 조회)
    findings2_result = await session.execute(
        select(Finding)
        .join(CVE)
        .join(Package)
        .where(Finding.scan_id == scan_id_2)
    )
    findings2 = findings2_result.scalars().all()

    # Create CVE maps for comparison
    cves1 = {}
    for f in findings1:
        await session.refresh(f, ["cve", "package"])
        key = (f.package.name, f.cve.cve_id)
        cves1[key] = f.id

    cves2 = {}
    for f in findings2:
        await session.refresh(f, ["cve", "package"])
        key = (f.package.name, f.cve.cve_id)
        cves2[key] = f.id

    # Determine time order (older -> newer)
    scan1_time = scan1.scan_started or scan1.scan_completed
    scan2_time = scan2.scan_started or scan2.scan_completed

    if scan1_time and scan2_time:
        older_scan, newer_scan = (scan1, scan2) if scan1_time <= scan2_time else (scan2, scan1)
        older_cves, newer_cves = (cves1, cves2) if older_scan.id == scan1.id else (cves2, cves1)
    else:
        older_scan, newer_scan = (scan1, scan2) if scan1.id <= scan2.id else (scan2, scan1)
        older_cves, newer_cves = (cves1, cves2) if older_scan.id == scan1.id else (cves2, cves1)

    # Calculate differences (newer - older)
    older_keys = set(older_cves.keys())
    newer_keys = set(newer_cves.keys())
    new_vulnerabilities = newer_keys - older_keys
    resolved_vulnerabilities = older_keys - newer_keys
    common_vulnerabilities = older_keys & newer_keys

    return {
        "scan_old": {
            "id": older_scan.id,
            "date": older_scan.scan_started,
            "total_cves": len(older_cves),
            "cves_found": older_scan.cves_found
        },
        "scan_new": {
            "id": newer_scan.id,
            "date": newer_scan.scan_started,
            "total_cves": len(newer_cves),
            "cves_found": newer_scan.cves_found
        },
        "comparison": {
            "new_vulnerabilities": [
                {"package": pkg, "cve_id": cve, "finding_id": newer_cves.get((pkg, cve))}
                for pkg, cve in new_vulnerabilities
            ],
            "resolved_vulnerabilities": [
                {"package": pkg, "cve_id": cve, "finding_id": older_cves.get((pkg, cve))}
                for pkg, cve in resolved_vulnerabilities
            ],
            "common_vulnerabilities_count": len(common_vulnerabilities),
            "new_count": len(new_vulnerabilities),
            "resolved_count": len(resolved_vulnerabilities)
        }
    }


@router.get("/api/findings/lookup")
async def lookup_finding(
    scan_id: int = Query(...),
    package_name: str = Query(...),
    cve_id: str = Query(...),
    session: AsyncSession = Depends(get_db)
):
    """Lookup a finding id by scan/package/cve"""
    result = await session.execute(
        select(Finding.id)
        .join(CVE)
        .join(Package)
        .where(
            and_(
                Finding.scan_id == scan_id,
                Package.name == package_name,
                CVE.cve_id == cve_id
            )
        )
        .limit(1)
    )
    finding_id = result.scalar_one_or_none()
    if not finding_id:
        raise HTTPException(status_code=404, detail="Finding not found")
    return {"finding_id": finding_id}


@router.get("/api/privesc-paths")
async def get_privesc_paths(
    scan_id: Optional[int] = Query(None),
    mode: Optional[str] = Query("privesc"),
    session: AsyncSession = Depends(get_db)
):
    """Get privilege escalation / unauthorized CVE data for visualization"""
    mode = (mode or "privesc").lower()
    if mode not in {"privesc", "unauthorized"}:
        mode = "privesc"
    mode_label = "권한 상승" if mode == "privesc" else "비인가"
    root_label = "권한 상승 취약점" if mode == "privesc" else "비인가 접근 취약점"
    # scan_id가 없으면 최신 완료된 스캔 사용
    if scan_id is None:
        latest_scan = await session.execute(
            select(ScanHistory)
            .where(ScanHistory.status == "completed")
            .order_by(ScanHistory.scan_started.desc())
            .limit(1)
        )
        latest = latest_scan.scalar_one_or_none()
        if latest:
            scan_id = latest.id

    if not scan_id:
        return {
            "categories": [],
            "top_cves": [],
            "packages": [],
            "summary": {},
            "mode": mode,
            "mode_label": mode_label,
            "root_label": root_label
        }

    # 권한 상승/비인가 CVE만 조회
    filter_condition = Finding.is_privilege_escalation == True
    if mode == "unauthorized":
        filter_condition = Finding.is_unauthorized_access == True

    query = (
        select(Finding)
        .join(CVE)
        .join(Package)
        .where(
            and_(
                Finding.scan_id == scan_id,
                filter_condition
            )
        )
        .order_by(CVE.cvss_v3_score.desc().nulls_last())
    )

    result = await session.execute(query)
    findings = result.scalars().all()

    if not findings:
        return {
            "categories": [],
            "top_cves": [],
            "packages": [],
            "summary": {},
            "mode": mode,
            "mode_label": mode_label,
            "root_label": root_label
        }

    # 카테고리별 분류
    if mode == "privesc":
        categories = {
            "kernel": {"label": "Kernel", "count": 0, "critical": 0, "high": 0},
            "suid": {"label": "SUID/Sudo", "count": 0, "critical": 0, "high": 0},
            "service": {"label": "Service", "count": 0, "critical": 0, "high": 0},
            "container": {"label": "Container", "count": 0, "critical": 0, "high": 0},
            "local": {"label": "Local", "count": 0, "critical": 0, "high": 0},
            "adjacent": {"label": "Adjacent", "count": 0, "critical": 0, "high": 0},
            "network": {"label": "Network", "count": 0, "critical": 0, "high": 0},
            "physical": {"label": "Physical", "count": 0, "critical": 0, "high": 0},
            "other": {"label": "Other", "count": 0, "critical": 0, "high": 0}
        }
    else:
        categories = {
            "network": {"label": "Network", "count": 0, "critical": 0, "high": 0},
            "adjacent": {"label": "Adjacent", "count": 0, "critical": 0, "high": 0},
            "local": {"label": "Local", "count": 0, "critical": 0, "high": 0},
            "physical": {"label": "Physical", "count": 0, "critical": 0, "high": 0},
            "other": {"label": "Other", "count": 0, "critical": 0, "high": 0}
        }

    # 패키지별 집계
    packages_map = {}
    top_cves = []

    for finding in findings:
        await session.refresh(finding, ["cve", "package"])

        cvss = finding.cve.cvss_v3_score or 0
        pkg_name = finding.package.name

        # 카테고리 분류
        if mode == "privesc":
            if finding.is_kernel_cve:
                cat = "kernel"
            elif "sudo" in pkg_name.lower() or "polkit" in pkg_name.lower() or "pkexec" in pkg_name.lower():
                cat = "suid"
            elif finding.pkg_is_service or finding.pkg_is_running:
                cat = "service"
            elif "docker" in pkg_name.lower() or "container" in pkg_name.lower() or "lxc" in pkg_name.lower():
                cat = "container"
            else:
                attack_vector = (finding.cve.attack_vector or "").upper()
                if attack_vector == "NETWORK":
                    cat = "network"
                elif attack_vector == "ADJACENT":
                    cat = "adjacent"
                elif attack_vector == "LOCAL":
                    cat = "local"
                elif attack_vector == "PHYSICAL":
                    cat = "physical"
                else:
                    cat = "other"
        else:
            attack_vector = (finding.cve.attack_vector or "").upper()
            if attack_vector == "NETWORK":
                cat = "network"
            elif attack_vector == "ADJACENT":
                cat = "adjacent"
            elif attack_vector == "LOCAL":
                cat = "local"
            elif attack_vector == "PHYSICAL":
                cat = "physical"
            else:
                cat = "other"

        categories[cat]["count"] += 1
        if cvss >= 9.0:
            categories[cat]["critical"] += 1
        elif cvss >= 7.0:
            categories[cat]["high"] += 1

        # 패키지별 집계
        if pkg_name not in packages_map:
            packages_map[pkg_name] = {
                "name": pkg_name,
                "count": 0,
                "max_cvss": 0,
                "has_kev": False,
                "is_running": finding.pkg_is_running or False,
                "category_counts": {}
            }
        packages_map[pkg_name]["count"] += 1
        packages_map[pkg_name]["max_cvss"] = max(packages_map[pkg_name]["max_cvss"], cvss)
        if finding.cve.is_kev:
            packages_map[pkg_name]["has_kev"] = True
        packages_map[pkg_name]["category_counts"][cat] = packages_map[pkg_name]["category_counts"].get(cat, 0) + 1

        # 상위 CVE 목록
        top_cves.append({
            "cve_id": finding.cve.cve_id,
            "package": pkg_name,
            "cvss": cvss,
            "epss": finding.cve.epss_score,
            "is_kev": finding.cve.is_kev or False,
            "is_running": finding.pkg_is_running or False,
            "reason": finding.privesc_reason,
            "category": cat
        })

    # 카테고리 결과 정리 (count > 0인 것만)
    categories_result = [
        {"id": k, **v} for k, v in categories.items() if v["count"] > 0
    ]
    categories_result.sort(key=lambda x: x["count"], reverse=True)

    # 패키지 결과 정리 (상위 10개)
    for pkg in packages_map.values():
        if pkg["category_counts"]:
            pkg["category"] = max(pkg["category_counts"], key=pkg["category_counts"].get)
        else:
            pkg["category"] = "other"
        pkg.pop("category_counts", None)

    packages_result = sorted(packages_map.values(), key=lambda x: (x["max_cvss"], x["count"]), reverse=True)[:10]
    package_names = {pkg["name"] for pkg in packages_result}
    for cve in top_cves:
        pkg_name = cve["package"]
        if pkg_name in packages_map and pkg_name not in package_names:
            packages_result.append(packages_map[pkg_name])
            package_names.add(pkg_name)

    # CVE 목록은 전체 반환 (프론트에서 정렬/필터링)

    # 요약 통계
    summary = {
        "total": len(findings),
        "critical": sum(1 for f in findings if (f.cve.cvss_v3_score or 0) >= 9.0),
        "high": sum(1 for f in findings if 7.0 <= (f.cve.cvss_v3_score or 0) < 9.0),
        "medium": sum(1 for f in findings if 4.0 <= (f.cve.cvss_v3_score or 0) < 7.0),
        "kev_count": sum(1 for f in findings if f.cve.is_kev),
        "running_count": sum(1 for f in findings if f.pkg_is_running or f.pkg_is_service)
    }

    return {
        "categories": categories_result,
        "top_cves": top_cves,
        "packages": packages_result,
        "summary": summary,
        "mode": mode,
        "mode_label": mode_label,
        "root_label": root_label
    }


@router.get("/api/hosts/{host_id}/packages")
async def get_host_packages(host_id: int, session: AsyncSession = Depends(get_db)):
    """Get packages for a specific host"""
    result = await session.execute(
        select(Package).where(Package.host_id == host_id)
    )
    packages = result.scalars().all()

    return [
        {
            "id": pkg.id,
            "name": pkg.name,
            "version": pkg.version,
            "architecture": pkg.architecture
        }
        for pkg in packages
    ]


@router.get("/api/package/{package_id}/patch-recommendation")
async def get_patch_recommendation(package_id: int, session: AsyncSession = Depends(get_db)):
    """Get patch recommendation for a vulnerable package"""
    # Get package
    pkg_result = await session.execute(
        select(Package).where(Package.id == package_id)
    )
    package = pkg_result.scalar_one_or_none()

    if not package:
        raise HTTPException(status_code=404, detail="Package not found")

    # Get host
    host_result = await session.execute(
        select(Host).where(Host.id == package.host_id)
    )
    host = host_result.scalar_one_or_none()

    # Get patch commands directly
    return _generate_patch_commands(package.name, package.version, host.os_type)
