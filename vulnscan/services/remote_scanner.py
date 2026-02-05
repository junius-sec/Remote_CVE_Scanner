"""
Remote Scanner - 원격 호스트 스캔 오케스트레이션

Discovery → DeepScan → CVE Pipeline을 연결하는 메인 스캐너
"""

import json
import hashlib
from typing import Dict, List, Optional, Callable, Any, Tuple
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass

# KST timezone
KST = timezone(timedelta(hours=9))
import logging

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from ..collectors.ssh_exec import SSHExecutor, create_ssh_executor_from_host
from ..collectors.discovery import DiscoveryCollector, DiscoveryResult
from ..collectors.deepscan import DeepScanCollector, DeepScanResult
from ..parsers import get_parser_for_pkg_manager, PackageData
from .job_runner import ScanConfig, ScanPreset

logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    """스캔 결과"""
    success: bool
    host_id: int
    
    # Discovery 결과
    discovery: Optional[DiscoveryResult] = None
    
    # DeepScan 결과
    deepscan: Optional[DeepScanResult] = None
    
    # CVE 분석 결과
    packages_scanned: int = 0
    cves_found: int = 0
    high_risk_count: int = 0
    
    # PoC 스캔 결과
    poc_scanned: int = 0
    poc_found: int = 0
    
    # 메타데이터
    scan_history_id: Optional[int] = None
    snapshot_id: Optional[int] = None
    duration_sec: float = 0.0
    
    # 에러
    errors: List[str] = None
    
    def __post_init__(self):
        if self.errors is None:
            self.errors = []
    
    def to_dict(self) -> Dict:
        return {
            "success": self.success,
            "host_id": self.host_id,
            "discovery": self.discovery.to_dict() if self.discovery else None,
            "packages_scanned": self.packages_scanned,
            "cves_found": self.cves_found,
            "high_risk_count": self.high_risk_count,
            "poc_scanned": self.poc_scanned,
            "poc_found": self.poc_found,
            "scan_history_id": self.scan_history_id,
            "snapshot_id": self.snapshot_id,
            "duration_sec": self.duration_sec,
            "errors": self.errors,
        }


class RemoteScanner:
    """
    원격 호스트 스캔 오케스트레이터
    
    실행 흐름:
    1. SSH 연결 및 Discovery 실행
    2. DeepScan 실행 (프리셋에 따라)
    3. Asset Snapshot 저장
    4. 기존 CVE Pipeline 실행
    5. 결과 저장 및 반환
    """
    
    def __init__(
        self,
        host_id: int,
        config: ScanConfig,
        session: AsyncSession,
        job_id: Optional[int] = None
    ):
        self.host_id = host_id
        self.config = config
        self.session = session
        self.job_id = job_id

        self._host = None
        self._ssh: Optional[SSHExecutor] = None
        self._progress_callback: Optional[Callable] = None

        self._result = ScanResult(success=False, host_id=host_id)
    
    def set_progress_callback(self, callback: Callable[[str, int, str], None]):
        """진행상황 콜백 설정 (phase, progress, message)"""
        self._progress_callback = callback

    async def _check_cancelled(self):
        """스캔 취소 여부 확인"""
        if self.job_id is None:
            return

        from ..models.schemas import ScanJob

        result = await self.session.execute(
            select(ScanJob).where(ScanJob.id == self.job_id)
        )
        job = result.scalar_one_or_none()

        if job and job.status == "cancelled":
            raise Exception(f"Scan job {self.job_id} was cancelled by user")

    async def _report_progress(self, phase: str, progress: int, message: str):
        """진행상황 보고 (논블로킹)"""
        if self._progress_callback:
            try:
                import asyncio
                # Callback이 async 함수면 백그라운드 태스크로 실행
                if asyncio.iscoroutinefunction(self._progress_callback):
                    asyncio.create_task(self._progress_callback(phase, progress, message))
                else:
                    self._progress_callback(phase, progress, message)
            except Exception as e:
                print(f"[Progress Callback Error] {e}")
    
    async def run(self) -> Dict:
        """스캔 실행"""
        start_time = datetime.now(KST)

        try:
            # 1. 호스트 정보 로드 및 allowlist 검증
            await self._check_cancelled()
            await self._load_and_validate_host()

            # 2. SSH 연결 설정
            await self._check_cancelled()
            self._setup_ssh()

            # 3. Discovery 실행
            await self._check_cancelled()
            await self._report_progress("discovery", 10, "Starting discovery...")
            await self._run_discovery()

            if not self._result.discovery or not self._result.discovery.ssh_connected:
                raise Exception("Discovery failed: SSH connection failed")

            # 4. DeepScan 실행
            await self._check_cancelled()
            await self._report_progress("deepscan", 25, "Running deep scan...")
            await self._run_deepscan()

            # 5. Asset Snapshot 저장
            await self._check_cancelled()
            await self._report_progress("snapshot", 40, "Saving asset snapshot...")
            logger.info("[Snapshot] Starting snapshot save...")
            await self._save_snapshot()
            logger.info("[Snapshot] Snapshot saved successfully")

            # 6. CVE Pipeline 실행
            await self._check_cancelled()
            await self._report_progress("cve_analysis", 50, "Running CVE analysis...")
            logger.info("[CVE] Starting CVE pipeline...")
            await self._run_cve_pipeline()
            logger.info("[CVE] CVE pipeline completed")
            
            # 7. 결과 정리 - 직접 DB 업데이트로 확실히 100% 반영
            # (PoC 스캔은 별도 버튼으로 수동 실행)
            logger.info("[Scan] Finalizing scan, setting progress to 100%")
            await self._finalize_progress()
            self._result.success = True
            
        except Exception as e:
            self._result.success = False
            self._result.errors.append(str(e))
            logger.exception(f"Scan failed for host {self.host_id}: {e}")
        
        # 소요 시간
        self._result.duration_sec = (datetime.now(KST) - start_time).total_seconds()
        
        return self._result.to_dict()
    
    async def _load_and_validate_host(self):
        """호스트 로드 및 allowlist 검증"""
        from ..models.schemas import Host
        
        result = await self.session.execute(
            select(Host).where(Host.id == self.host_id)
        )
        self._host = result.scalar_one_or_none()
        
        if not self._host:
            raise ValueError(f"Host {self.host_id} not found")
        
        # Allowlist 검증
        if hasattr(self._host, 'is_allowed') and not self._host.is_allowed:
            raise PermissionError(
                f"Host {self._host.hostname} is not in allowlist. "
                "스캔 대상은 반드시 allowlist에 등록되어야 합니다."
            )
        
        logger.info(f"Host validated: {self._host.hostname} ({self._host.ip_address})")
    
    def _setup_ssh(self):
        """SSH 연결 설정"""
        self._ssh = create_ssh_executor_from_host(self._host)
        logger.info(f"SSH executor created for {self._host.ip_address}")
    
    async def _run_discovery(self):
        """Discovery 실행"""
        collector = DiscoveryCollector(self._ssh)
        self._result.discovery = await collector.collect()
        
        # 호스트 정보 업데이트
        if self._result.discovery.ssh_connected:
            self._host.last_discovery = datetime.now(KST)
            self._host.distro_id = self._result.discovery.distro_id
            self._host.pkg_manager = self._result.discovery.pkg_manager
            self._host.arch = self._result.discovery.arch
            self._host.kernel_version = self._result.discovery.kernel
            self._host.is_busybox = self._result.discovery.is_busybox
            self._host.has_systemd = self._result.discovery.has_systemd
            
            # OS 타입/버전 업데이트
            if self._result.discovery.distro_id != "unknown":
                self._host.os_type = self._result.discovery.distro_id
            if self._result.discovery.distro_version:
                self._host.os_version = self._result.discovery.distro_version
            
            await self.session.commit()
        
        logger.info(
            f"Discovery completed: {self._result.discovery.distro_id} "
            f"({self._result.discovery.pkg_manager})"
        )
    
    async def _run_deepscan(self):
        """DeepScan 실행"""
        collector = DeepScanCollector(self._ssh, self._result.discovery)
        self._result.deepscan = await collector.collect(
            preset=self.config.preset.value
        )
        
        logger.info(
            f"DeepScan completed: {self._result.deepscan.packages_count} packages, "
            f"{self._result.deepscan.binaries_count} binaries"
        )
    
    async def _save_snapshot(self):
        """Asset Snapshot 저장"""
        from ..models.schemas import AssetSnapshot
        
        discovery = self._result.discovery
        deepscan = self._result.deepscan
        
        snapshot = AssetSnapshot(
            host_id=self.host_id,
            os_family=discovery.os_family,
            distro_id=discovery.distro_id,
            distro_version=discovery.distro_version,
            pkg_manager=discovery.pkg_manager,
            arch=discovery.arch,
            kernel_version=discovery.kernel,
            is_busybox=discovery.is_busybox,
            has_systemd=discovery.has_systemd,
            capabilities=json.dumps(discovery.capabilities),
            confidence_discovery=discovery.confidence,
            raw_os_release=discovery.raw_os_release[:4000] if discovery.raw_os_release else None,
            
            packages_hash=deepscan.packages_hash if deepscan else None,
            binaries_hash=deepscan.binaries_hash if deepscan else None,
            
            packages_json=json.dumps([p.to_dict() for p in deepscan.packages]) if deepscan and deepscan.packages else None,
            binaries_json=json.dumps([b.to_dict() for b in deepscan.binaries]) if deepscan and deepscan.binaries else None,
            
            collector_mode=deepscan.collector_mode if deepscan else None,
            collection_duration_sec=(discovery.collection_duration_ms + (deepscan.collection_duration_ms if deepscan else 0)) / 1000,
            evidence_summary=deepscan.evidence[:500] if deepscan and deepscan.evidence else None,
        )
        
        self.session.add(snapshot)
        await self.session.flush()
        self._result.snapshot_id = snapshot.id
        
        logger.info(f"Snapshot saved: ID={snapshot.id}")
    
    async def _run_cve_pipeline(self):
        """기존 CVE Pipeline 실행"""
        from ..models.schemas import ScanHistory
        from ..core.matcher import VulnerabilityMatcher
        from ..core.nvd_client import NVDClient
        
        deepscan = self._result.deepscan
        if not deepscan:
            logger.warning("No deepscan data for CVE pipeline")
            return
        
        # 패키지 데이터를 기존 파이프라인 형식으로 변환
        packages = self._convert_to_pipeline_format(deepscan)
        
        if not packages:
            logger.warning("No packages to analyze")
            return
        
        # ScanHistory 레코드 생성
        scan_history = ScanHistory(
            host_id=self.host_id,
            status="running"
        )
        self.session.add(scan_history)
        await self.session.flush()
        self._result.scan_history_id = scan_history.id
        
        # VulnerabilityMatcher 실행
        nvd_client = NVDClient()
        matcher = VulnerabilityMatcher(nvd_client)
        
        # SSH executor를 usage_analyzer에 전달 (원격 스캔용)
        matcher.usage_analyzer.set_ssh_executor(self._ssh)
        
        # 스캔 옵션 설정
        matcher.set_scan_options({
            "filter_patched": self.config.filter_patched,
            "filter_old_cve": self.config.filter_old_cve,
            "filter_other_os": self.config.filter_other_os,
            "cve_years": self.config.cve_years,
        })
        
        # 카테고리 필터링
        from ..core.scanner import PackageScanner
        scanner = PackageScanner()
        filtered_packages = scanner.filter_critical_packages(
            packages, 
            self.config.categories
        )
        
        # CVE 매칭 실행 (패키지 기반)
        stats = await matcher.match_package_vulnerabilities(
            self.session,
            self.host_id,
            filtered_packages,
            scan_history.id,
            fast_mode=(self.config.preset == ScanPreset.FAST)
        )
        
        # 결과 업데이트
        self._result.packages_scanned = len(filtered_packages)
        self._result.cves_found = stats.get("total_cves", 0)
        self._result.high_risk_count = stats.get("high_risk_count", 0)
        
        # === OS/Kernel CVE 수집 (경량 배포판 대응) ===
        try:
            from ..core.os_cve_matcher import collect_os_vulnerabilities
            
            os_info = {
                'distro_id': self._host.distro_id,
                'distro_version': self._result.discovery.distro_version,  # Discovery에서 가져오기
                'kernel_version': self._result.discovery.kernel,  # Discovery에서 가져오기
                'arch': self._result.discovery.arch  # Discovery에서 가져오기
            }
            
            logger.info(f"OS CVE 수집 시작: {os_info}, cve_years={self.config.cve_years}")
            
            os_cves = await collect_os_vulnerabilities(
                nvd_client, 
                os_info, 
                package_count=len(filtered_packages),
                cve_years=self.config.cve_years
            )
            
            logger.info(f"OS CVE 수집 완료: {len(os_cves) if os_cves else 0}개")
            
            if os_cves:
                # OS CVE를 Finding으로 저장
                os_stats = await self._save_os_cves(os_cves, scan_history.id, matcher)
                
                self._result.cves_found += os_stats.get("os_cves", 0)
                self._result.high_risk_count += os_stats.get("os_high_risk", 0)
                
                logger.info(f"OS CVE: {os_stats.get('os_cves', 0)} additional CVEs from OS/Kernel")
            else:
                logger.info("OS CVE: 발견된 OS/Kernel CVE 없음")
                
        except Exception as e:
            logger.exception(f"OS CVE collection failed: {e}")
        
        # ScanHistory 업데이트
        scan_history.status = "completed"
        scan_history.scan_completed = datetime.now(KST)
        scan_history.packages_found = len(filtered_packages)
        scan_history.cves_found = self._result.cves_found
        scan_history.high_risk_count = self._result.high_risk_count
        
        # 호스트 last_scan 업데이트
        self._host.last_scan = datetime.now(KST)
        
        await self.session.commit()
        
        logger.info(
            f"CVE Pipeline completed: {self._result.cves_found} CVEs found, "
            f"{self._result.high_risk_count} high risk"
        )
    
    async def _save_os_cves(self, os_cves: List[Dict], scan_id: int, matcher) -> Dict:
        """
        OS/Kernel CVE를 Finding으로 저장
        
        시스템 패키지를 생성하여 기존 Finding 구조 활용
        """
        from ..models.schemas import Package, CVE, Finding
        from sqlalchemy import select
        
        stats = {"os_cves": 0, "os_high_risk": 0}
        
        for os_cve in os_cves:
            try:
                cve_id_str = os_cve.get('cve_id')
                if not cve_id_str:
                    continue
                
                # 시스템 패키지 생성/조회 (OS 또는 Kernel)
                pkg_name = f"__{os_cve['type'].upper()}__"  # "__OS__" or "__KERNEL__"
                pkg_version = os_cve.get('target', 'unknown')
                
                result = await self.session.execute(
                    select(Package).where(
                        Package.host_id == self.host_id,
                        Package.name == pkg_name,
                        Package.version == pkg_version
                    )
                )
                package = result.scalar_one_or_none()
                
                if not package:
                    package = Package(
                        host_id=self.host_id,
                        scan_id=scan_id,  # 스캔별 독립 저장
                        name=pkg_name,
                        version=pkg_version,
                        package_manager="system",
                        architecture=self._result.discovery.arch if self._result.discovery else None
                    )
                    self.session.add(package)
                    await self.session.flush()
                
                # CVE 생성/업데이트
                cve = await matcher._get_or_create_cve(self.session, os_cve)
                
                # Finding 중복 체크
                result = await self.session.execute(
                    select(Finding).where(
                        Finding.host_id == self.host_id,
                        Finding.package_id == package.id,
                        Finding.cve_id == cve.id,
                        Finding.scan_id == scan_id
                    )
                )
                existing = result.scalar_one_or_none()
                
                if existing:
                    continue
                
                # Finding 생성
                cvss_score = os_cve.get('cvss_score') or 0.0
                risk_level = 'high' if cvss_score >= 7.0 else 'medium' if cvss_score >= 4.0 else 'low'
                is_kernel = (os_cve['type'] == 'kernel')
                
                finding = Finding(
                    host_id=self.host_id,
                    package_id=package.id,
                    cve_id=cve.id,
                    scan_id=scan_id,
                    risk_level=risk_level,
                    status="open",
                    collector_mode="kernel" if is_kernel else "os",  # 커널/OS 분리
                    evidence=f"CPE: {os_cve.get('cpe', 'N/A')}, Target: {os_cve.get('target', '')}",
                    data_confidence="high",
                    is_kernel_cve=is_kernel,
                    priority_score=cvss_score * 10,
                    priority_level='HIGH' if cvss_score >= 7.0 else 'MEDIUM'
                )
                self.session.add(finding)
                
                stats["os_cves"] += 1
                if cvss_score >= 7.0:
                    stats["os_high_risk"] += 1
                    
            except Exception as e:
                logger.error(f"Failed to save OS CVE {os_cve.get('cve_id')}: {e}")
                continue
        
        await self.session.flush()
        return stats
    
    async def _finalize_progress(self):
        """스캔 완료 시 진행률을 확실히 100%로 설정"""
        from ..models.schemas import ScanJob
        
        if self.job_id:
            try:
                result = await self.session.execute(
                    select(ScanJob).where(ScanJob.id == self.job_id)
                )
                job = result.scalar_one_or_none()
                if job:
                    job.current_phase = "complete"
                    job.progress_percent = 100
                    job.progress_message = "Scan completed"
                    await self.session.commit()
                    logger.info(f"[Scan] Progress finalized to 100% for job {self.job_id}")
            except Exception as e:
                logger.error(f"[Scan] Failed to finalize progress: {e}")
        
        # callback도 호출 (호환성)
        await self._report_progress("complete", 100, "Scan completed")
    
    async def _run_poc_scan(self) -> Tuple[int, int]:
        """
        PoC/Exploit 정보 스캔
        
        최종 필터링된 CVE에 대해서만 PoC 검색 수행 (스캔 속도 저하 최소화)
        
        Returns:
            Tuple[int, int]: (검색한 CVE 수, exploit이 발견된 CVE 수)
        """
        from ..models.schemas import Finding, CVE
        from ..core.exploit_client import get_exploit_client
        
        if not self._result.scan_history_id:
            logger.warning("[PoC] No scan history ID, skipping PoC scan")
            return (0, 0)
        
        logger.info(f"[PoC] scan_history_id={self._result.scan_history_id}")
        
        # 현재 스캔의 Finding에서 CVE 정보 JOIN하여 CVE ID 문자열 직접 조회
        result = await self.session.execute(
            select(CVE.cve_id).distinct()
            .join(Finding, Finding.cve_id == CVE.id)
            .where(Finding.scan_id == self._result.scan_history_id)
        )
        cve_ids_to_search = [r[0] for r in result.fetchall()]
        
        if not cve_ids_to_search:
            logger.info("[PoC] No CVE IDs to search PoC for")
            await self._report_progress("poc_scan", 95, "No CVEs to search PoC")
            return (0, 0)
        
        logger.info(f"[PoC] Starting PoC scan for {len(cve_ids_to_search)} CVEs")
        await self._report_progress("poc_scan", 87, f"Searching PoC for {len(cve_ids_to_search)} CVEs...")
        
        # ExploitClient로 배치 검색
        client = get_exploit_client()
        
        # 50개씩 배치 처리
        batch_size = 50
        total_found = 0
        
        for i in range(0, len(cve_ids_to_search), batch_size):
            batch = cve_ids_to_search[i:i + batch_size]
            
            try:
                logger.info(f"[PoC] Processing batch {i//batch_size + 1}/{(len(cve_ids_to_search)-1)//batch_size + 1}")
                results = await client.batch_search(batch)
                
                # DB 업데이트
                for cve_id_str, poc_data in results.items():
                    if poc_data.get('has_exploit'):
                        total_found += 1
                        
                        # CVE 테이블 업데이트
                        cve_result = await self.session.execute(
                            select(CVE).where(CVE.cve_id == cve_id_str)
                        )
                        cve = cve_result.scalar_one_or_none()
                        
                        if cve:
                            cve.has_exploit = True
                            cve.exploit_count = poc_data.get('exploit_count', 0)
                            
                            sources = []
                            if poc_data.get('github_pocs'):
                                sources.append('github')
                            if poc_data.get('exploitdb'):
                                sources.append('exploitdb')
                            cve.exploit_sources = ','.join(sources)
                            
                            # URL 목록 저장 (최대 5개씩)
                            import json
                            urls = []
                            for poc in poc_data.get('github_pocs', [])[:5]:
                                urls.append({'source': 'github', 'url': poc.get('url', '')})
                            for exp in poc_data.get('exploitdb', [])[:5]:
                                urls.append({'source': 'exploitdb', 'url': exp.get('url', '')})
                            cve.exploit_urls = json.dumps(urls)
                            cve.exploit_last_checked = datetime.now(KST)
                
                # 진행률 업데이트
                progress = 87 + int((i + len(batch)) / len(cve_ids_to_search) * 8)  # 87% ~ 95%
                await self._report_progress("poc_scan", min(progress, 95), 
                    f"PoC 검색 중... ({i + len(batch)}/{len(cve_ids_to_search)})")
                
            except Exception as e:
                logger.error(f"[PoC] Batch search error: {e}")
                continue
        
        await self.session.commit()
        logger.info(f"[PoC] PoC scan completed: {total_found} exploits found for {len(cve_ids_to_search)} CVEs")
        return (len(cve_ids_to_search), total_found)
    
    def _convert_to_pipeline_format(self, deepscan: DeepScanResult) -> List[Dict]:
        """DeepScan 결과를 기존 파이프라인 형식으로 변환"""
        packages = []
        
        # 패키지 목록 변환
        for pkg in deepscan.packages:
            packages.append({
                "name": pkg.name,
                "version": pkg.version,
                "architecture": pkg.architecture,
                "package_manager": pkg.package_manager,
                # 신뢰도/증거 메타데이터
                "_confidence": pkg.confidence,
                "_evidence": pkg.evidence,
                "_raw_version": pkg.raw_version,
            })
        
        # 바이너리 기반 패키지 추가 (패키지 매니저 없을 때)
        if deepscan.collector_mode == "binary":
            for binary in deepscan.binaries:
                packages.append({
                    "name": binary.name,
                    "version": binary.version,
                    "architecture": self._result.discovery.arch if self._result.discovery else "",
                    "package_manager": "binary",
                    "_confidence": binary.confidence,
                    "_evidence": binary.raw_output[:100],
                    "_collector_mode": "binary",
                })
        
        return packages


async def run_remote_scan(
    host_id: int,
    preset: str = "standard",
    session: AsyncSession = None
) -> Dict:
    """원격 스캔 실행 헬퍼 함수"""
    preset_enum = ScanPreset(preset)
    config = ScanConfig.from_preset(preset_enum)
    
    scanner = RemoteScanner(host_id, config, session)
    return await scanner.run()
