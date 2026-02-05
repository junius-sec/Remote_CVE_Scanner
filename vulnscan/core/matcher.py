from typing import List, Dict, Optional, Tuple
import asyncio
import time
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from ..models.schemas import Host, Package, CVE, Finding
from .nvd_client import NVDClient
from .epss_client import EPSSClient
from .debian_security_client import DebianSecurityClient
from .kev_client import KEVClient, VulnerabilityPrioritizer
from .package_usage_analyzer import PackageUsageAnalyzer, AptPatchChecker
from .kernel_analyzer import KernelAnalyzer


class VulnerabilityMatcher:
    """패키지와 CVE를 매칭하고 Finding을 생성"""

    def __init__(
        self,
        nvd_client: NVDClient,
        epss_client: Optional[EPSSClient] = None,
        debian_security_client: Optional[DebianSecurityClient] = None,
        kev_client: Optional[KEVClient] = None
    ):
        self.nvd_client = nvd_client
        self.epss_client = epss_client or EPSSClient()
        self.debian_security = debian_security_client or DebianSecurityClient()
        self.kev_client = kev_client or KEVClient()
        self.usage_analyzer = PackageUsageAnalyzer()
        self.patch_checker = AptPatchChecker()
        self.prioritizer = VulnerabilityPrioritizer()
        self.kernel_analyzer = KernelAnalyzer()

        self._debian_initialized = False
        self._kev_initialized = False
        self._current_scan_id: Optional[int] = None

        # 스캔 옵션 기본값
        self._scan_options = {
            "filter_patched": True,
            "filter_old_cve": True,
            "filter_other_os": True
        }

        # 통계 기본값
        self._stats = {
            "total_checked": 0,
            "filtered_by_patch": 0,
            "filtered_by_apt_patched": 0,
            "actual_vulnerable": 0,
            "kev_count": 0,
            "active_packages": 0,
            "privesc_count": 0,
            "kernel_cve_count": 0
        }

    def set_scan_options(self, options: dict):
        """스캔 옵션 설정"""
        if options:
            self._scan_options.update(options)

    async def match_package_vulnerabilities(
        self,
        session: AsyncSession,
        host_id: int,
        packages: List[Dict],
        scan_id: Optional[int] = None,
        fast_mode: bool = False
    ) -> Dict[str, int]:
        """패키지 리스트를 CVE와 매칭하여 Finding 생성"""
        from ..models.schemas import ScanHistory
        from sqlalchemy import select, func

        # Debian Security 데이터 초기화 (최초 1회)
        if not self._debian_initialized:
            print("[보안] Debian Security Tracker 로딩 중...")
            await self.debian_security.initialize()
            self._debian_initialized = True
            stats = self.debian_security.get_stats()
            if stats.get("loaded"):
                print(f"[보안] {stats['total_packages']}개 패키지 정보 로드 완료")

        # KEV 데이터 초기화 (최초 1회)
        if not self._kev_initialized:
            print("[보안] CISA KEV 데이터 로딩 중...")
            await self.kev_client.initialize()
            self._kev_initialized = True
            kev_stats = self.kev_client.get_stats()
            if kev_stats.get("loaded"):
                print(f"[보안] KEV {kev_stats['total_cves']}개 로드 완료")

        # 통계 초기화
        self._stats = {
            "total_checked": 0,
            "filtered_by_patch": 0,
            "filtered_by_apt_patched": 0,
            "actual_vulnerable": 0,
            "kev_count": 0,
            "active_packages": 0,
            "privesc_count": 0,
            "kernel_cve_count": 0
        }

        # 현재 스캔 ID 저장 (findings에 연결용)
        self._current_scan_id = scan_id
        
        # 스캔 시작 전 NVD 클라이언트 상태 초기화
        self.nvd_client.reset_scan_state()

        total_cves = 0
        high_risk = 0
        total_packages = len(packages)
        start_time = time.time()

        # 로컬 데이터가 있으면 배치 병렬 처리 (빠름)
        local_records = self.nvd_client.get_download_records()
        has_local_data = len(local_records) > 0

        if has_local_data or fast_mode:
            if has_local_data:
                print(f"[스캔] 로컬 NVD 데이터 사용 ({len(local_records)}년)")
                
                # CPE 인덱스 빌드 (최초 1회 - 스캔 속도 10배 이상 향상)
                if not self.nvd_client.is_index_loaded():
                    print("[인덱스] CPE 인덱스 구축 중...")
                    index_stats = await self.nvd_client.build_cpe_index()
                    print(f"[인덱스] 구축 완료 - {index_stats['packages']}개 패키지, {index_stats['cves']}개 CVE")
                else:
                    index_stats = self.nvd_client.get_index_stats()
                    print(f"[인덱스] 기존 인덱스 사용 - {index_stats['packages']}개 패키지")
                
            return await self._match_packages_fast(
                session, host_id, packages, scan_id, start_time
            )

        # 순차 처리 (로컬 데이터 없을 때)
        print("[스캔] 순차 모드 - NVD API 사용")
        await self.usage_analyzer.preload_process_cache()

        for idx, pkg_data in enumerate(packages, 1):
            # 진행률 업데이트
            if scan_id:
                scan_result = await session.execute(
                    select(ScanHistory).where(ScanHistory.id == scan_id)
                )
                scan_record = scan_result.scalar_one_or_none()

                if scan_record:
                    progress = int((idx / total_packages) * 100)
                    elapsed = time.time() - start_time
                    avg_time_per_pkg = elapsed / idx if idx > 0 else 0
                    remaining_pkgs = total_packages - idx
                    estimated_remaining = int(avg_time_per_pkg * remaining_pkgs)

                    scan_record.current_package = pkg_data["name"]
                    scan_record.progress_percent = progress
                    scan_record.estimated_time_remaining = estimated_remaining
                    scan_record.packages_found = total_packages
                    scan_record.high_risk_count = high_risk
                    await session.commit()

            package = await self._get_or_create_package(session, host_id, pkg_data, scan_id)

            cve_years_option = self._scan_options.get("cve_years")
            cves = await self.nvd_client.search_cve_by_keyword(
                pkg_data["name"],
                cve_years=cve_years_option
            )

            if idx < 3:
                print(f"[CVE 검색 #{idx}] 패키지: {pkg_data['name']}, cve_years: {cve_years_option}, 결과: {len(cves)}개")

            # 관련 CVE 선별
            relevant_cves = []
            for cve_data in cves:
                if await self._is_relevant_cve(cve_data, pkg_data):
                    relevant_cves.append(cve_data)

            if idx < 3 and relevant_cves:
                print(f"[관련 CVE #{idx}] {pkg_data['name']}: {len(relevant_cves)}개 관련 CVE")

            # Usage/패치 정보는 관련 CVE 있을 때만 조회
            usage_info = None
            patch_info = None
            if relevant_cves:
                try:
                    # 타임아웃 10초 설정 (hang 방지)
                    usage_info = await asyncio.wait_for(
                        self.usage_analyzer.analyze_package(pkg_data["name"]),
                        timeout=10.0
                    )
                    if usage_info and usage_info.get("is_running"):
                        print(f"  [NORMAL] {pkg_data['name']}: is_running=True")
                except asyncio.TimeoutError:
                    print(f"  [타임아웃] {pkg_data['name']} usage 분석 10초 초과 - 스킵")
                except Exception as e:
                    print(f"  [WARN] {pkg_data['name']} usage analysis failed: {e}")

                try:
                    patch_info = await self.patch_checker.check_available_update(pkg_data["name"])
                except Exception:
                    pass

            # Finding 생성
            for cve_data in relevant_cves:
                cve = await self._get_or_create_cve(session, cve_data)
                await self._create_finding(
                    session, host_id, package.id, cve.id, cve_data,
                    usage_info=usage_info,
                    patch_info=patch_info,
                    pkg_name=pkg_data.get("name"),
                    package_manager=pkg_data.get("package_manager")
                )
                total_cves += 1

                # CVSS 점수: cvss_score (통합) > cvss_v3_score > cvss_v2_score
                cvss_score = cve_data.get("cvss_score") or cve_data.get("cvss_v3_score") or cve_data.get("cvss_v2_score")
                if cvss_score is not None and cvss_score >= 7.0:
                    high_risk += 1

            await session.commit()

        # 커널 CVE 별도 스캔
        kernel_result = await self._scan_kernel_cves(session, host_id, scan_id)
        if kernel_result:
            total_cves += kernel_result.get("cve_count", 0)
            high_risk += kernel_result.get("high_risk_count", 0)
            print(f"[커널] Linux Kernel CVE {kernel_result.get('cve_count', 0)}개 추가됨")

        # 패치 필터링 통계 출력
        self._print_patch_stats()

        # EPSS/KEV 배치 업데이트 (현재 스캔의 모든 CVE)
        await self._batch_update_epss_kev(session, scan_id)

        # 최종 Finding 개수 업데이트 (DB에 실제로 저장된 개수)
        if scan_id:
            scan_result = await session.execute(
                select(ScanHistory).where(ScanHistory.id == scan_id)
            )
            scan_record = scan_result.scalar_one_or_none()

            if scan_record:
                count_result = await session.execute(
                    select(func.count(Finding.id)).where(Finding.scan_id == scan_id)
                )
                actual_cve_count = count_result.scalar()
                scan_record.cves_found = actual_cve_count
                scan_record.high_risk_count = high_risk
                await session.commit()
                print(f"[최종] 스캔 {scan_id}: Finding {actual_cve_count}개 저장됨")

        return {
            "total_cves": total_cves,
            "high_risk_count": high_risk,
            "filtered_by_patch": self._stats["filtered_by_patch"]
        }

    async def _scan_kernel_cves(
        self,
        session: AsyncSession,
        host_id: int,
        scan_id: Optional[int]
    ) -> Optional[Dict]:
        """커널 버전 기반 CVE 검색 (패키지와 별도로) - 엄격한 버전 매칭"""
        from ..models.schemas import Host, Package
        from datetime import datetime

        host_result = await session.execute(select(Host).where(Host.id == host_id))
        host = host_result.scalar_one_or_none()

        if not host or not host.kernel_version:
            print("[커널] 커널 버전 정보 없음 - 스킵")
            return None

        kernel_version = host.kernel_version
        distro_id = host.distro_id or ""
        distro_version = host.os_version or ""
        print(f"\n[커널] Linux Kernel CVE 검색 중... (버전: {kernel_version}, OS: {distro_id})")

        # 커널 버전 파싱 (예: 6.6.31+rpt-rpi-v8 -> 6.6.31, 6.8.0-90-generic -> 6.8.0)
        kernel_clean = self._parse_kernel_version(kernel_version)
        kernel_major_minor = '.'.join(kernel_clean.split('.')[:2])
        kernel_major = kernel_clean.split('.')[0]
        
        print(f"[커널] 정규화 버전: {kernel_clean} (major.minor: {kernel_major_minor})")

        cves = await self.nvd_client.search_cve_by_keyword(
            "linux kernel",
            cve_years=self._scan_options.get("cve_years")
        )

        if not cves:
            print("[커널] CVE 없음")
            return None

        print(f"[커널] 전체 {len(cves)}개 중 엄격한 필터링 시작...")

        # CVSS 점수 정규화
        for cve in cves:
            self._normalize_cvss_score(cve)

        kernel_pkg_data = {
            "name": "linux-kernel",
            "version": kernel_clean,
            "architecture": host.arch or "unknown",
            "package_manager": "kernel"
        }

        package = await self._get_or_create_package(session, host_id, kernel_pkg_data, scan_id)

        cve_count = 0
        high_risk_count = 0
        
        # 필터링 통계
        stats = {
            "not_kernel_cpe": 0,
            "no_version_range": 0,
            "version_not_affected": 0,
            "patched": 0,
        }

        for cve_data in cves:
            cve_id = cve_data.get("cve_id", "")
            cpe_list = cve_data.get("cpe_list", "")
            version_ranges = cve_data.get("version_ranges", [])
            
            # === 필터 1: CPE에 linux:linux_kernel이 있어야 함 ===
            if not self._is_kernel_cve(cpe_list, ""):
                stats["not_kernel_cpe"] += 1
                continue

            # === 필터 2: 버전 범위 기반 엄격한 매칭 ===
            if not version_ranges:
                stats["no_version_range"] += 1
                continue
            
            is_affected = self._check_kernel_version_affected(
                kernel_clean, kernel_major_minor, version_ranges
            )
            
            if not is_affected:
                stats["version_not_affected"] += 1
                continue

            # === 필터 3: OS별 패치 상태 확인 ===
            patch_status = await self._check_kernel_patch_status(
                cve_id, distro_id, distro_version, kernel_version
            )
            
            if patch_status == "patched":
                stats["patched"] += 1
                continue

            # 모든 필터 통과 - 취약점으로 확정
            cve = await self._get_or_create_cve(session, cve_data)

            await self._create_finding(
                session, host_id, package.id, cve.id, cve_data,
                pkg_name="linux-kernel",
                package_manager="system"
            )
            cve_count += 1

            cvss_score = cve_data.get("cvss_score") or cve_data.get("cvss_v3_score")
            if cvss_score and cvss_score >= 7.0:
                high_risk_count += 1

            if cve_count <= 10:
                print(f"  [커널 CVE] {cve_id}: CVSS={cvss_score}")

        await session.commit()
        
        print(f"[커널] 필터링 통계:")
        print(f"  - CPE 불일치 (linux_kernel 아님): {stats['not_kernel_cpe']}개")
        print(f"  - 버전 범위 없음: {stats['no_version_range']}개")
        print(f"  - 버전 범위 불일치: {stats['version_not_affected']}개")
        print(f"  - 패치됨: {stats['patched']}개")
        print(f"[커널] 최종 결과: {cve_count}개 취약점 (고위험: {high_risk_count})")
        
        return {
            "cve_count": cve_count,
            "high_risk_count": high_risk_count
        }

    def _parse_kernel_version(self, kernel_version: str) -> str:
        """커널 버전 문자열에서 순수 버전 번호 추출
        
        Examples:
            6.6.31+rpt-rpi-v8 -> 6.6.31
            6.8.0-90-generic -> 6.8.0
            5.15.0-1074-raspi -> 5.15.0
            6.18.5-0-lts -> 6.18.5
        """
        import re
        # 버전 번호만 추출 (숫자.숫자.숫자 패턴)
        match = re.match(r'^(\d+\.\d+\.\d+)', kernel_version)
        if match:
            return match.group(1)
        # 그래도 안 되면 첫 번째 '-' 또는 '+' 전까지
        return kernel_version.split('-')[0].split('+')[0]

    def _is_kernel_cve(self, cpe_list: str, description: str) -> bool:
        """CVE가 실제 Linux 커널 취약점인지 엄격하게 확인
        
        CPE에 linux:linux_kernel이 명시적으로 있어야만 True 반환.
        description 기반 매칭은 완전히 제거 (오탐 방지)
        """
        if not cpe_list:
            return False
        
        cpe_lower = cpe_list.lower()
        
        # CPE에 linux:linux_kernel 또는 linux_kernel이 명시적으로 있어야 함
        # 단순히 "linux"만 있으면 안 됨 (다른 linux 관련 제품과 구분)
        kernel_cpe_patterns = [
            "cpe:2.3:o:linux:linux_kernel:",
            "cpe:/o:linux:linux_kernel:",
            ":linux:linux_kernel:",
        ]
        
        for pattern in kernel_cpe_patterns:
            if pattern in cpe_lower:
                return True
        
        return False

    def _check_kernel_version_affected(
        self, 
        kernel_clean: str, 
        kernel_major_minor: str,
        version_ranges: list
    ) -> bool:
        """커널 버전이 취약한 범위에 포함되는지 엄격하게 확인
        
        커널은 브랜치별로 독립적으로 패치됨 (예: 6.1.x, 6.6.x, 6.12.x)
        따라서 버전 범위가 현재 커널 브랜치를 포함하는지 확인해야 함
        """
        if not version_ranges:
            return False
        
        kernel_major = int(kernel_clean.split('.')[0])
        kernel_minor = int(kernel_clean.split('.')[1]) if len(kernel_clean.split('.')) > 1 else 0
        
        found_matching_branch = False
        
        for vr in version_ranges:
            criteria = vr.get("criteria", "").lower()
            
            # linux_kernel CPE인지 확인 (필수)
            if "linux_kernel" not in criteria and "linux:linux_kernel" not in criteria:
                continue

            start_incl = vr.get("versionStartIncluding")
            start_excl = vr.get("versionStartExcluding")
            end_incl = vr.get("versionEndIncluding")
            end_excl = vr.get("versionEndExcluding")

            # 버전 범위가 하나도 없으면 스킵
            if not any([start_incl, start_excl, end_incl, end_excl]):
                # CPE에서 특정 버전 추출 시도
                cpe_version = self._extract_cpe_version(criteria)
                if cpe_version and cpe_version != "*":
                    # 정확히 해당 버전만 취약 (major.minor 브랜치도 확인)
                    cpe_parts = cpe_version.split('.')
                    if len(cpe_parts) >= 2:
                        cpe_major = int(cpe_parts[0])
                        cpe_minor = int(cpe_parts[1])
                        # 같은 브랜치인지 확인
                        if cpe_major == kernel_major and cpe_minor == kernel_minor:
                            if self._compare_versions(kernel_clean, cpe_version) == 0:
                                return True
                continue

            # 버전 범위가 현재 커널 브랜치를 포함하는지 확인
            # 예: 6.12.62 커널에서 6.1.x~6.6.x 취약점은 해당 없음
            range_covers_branch = self._version_range_covers_branch(
                kernel_major, kernel_minor,
                start_incl or start_excl,
                end_incl or end_excl
            )
            
            if not range_covers_branch:
                continue
            
            found_matching_branch = True
            
            # 버전 범위 체크
            in_range = True
            
            # 하한 체크
            if start_incl:
                if self._compare_versions(kernel_clean, start_incl) < 0:
                    in_range = False
            if start_excl:
                if self._compare_versions(kernel_clean, start_excl) <= 0:
                    in_range = False
            
            # 상한 체크
            if end_excl:
                if self._compare_versions(kernel_clean, end_excl) >= 0:
                    in_range = False
            if end_incl:
                if self._compare_versions(kernel_clean, end_incl) > 0:
                    in_range = False

            if in_range:
                return True

        return False
    
    def _version_range_covers_branch(
        self, 
        kernel_major: int, 
        kernel_minor: int,
        range_start: Optional[str],
        range_end: Optional[str]
    ) -> bool:
        """버전 범위가 현재 커널의 major.minor 브랜치를 포함하는지 확인"""
        if not range_start and not range_end:
            return False
        
        try:
            # 시작 버전의 major.minor
            start_major, start_minor = 0, 0
            if range_start:
                parts = range_start.split('.')
                start_major = int(parts[0])
                start_minor = int(parts[1]) if len(parts) > 1 else 0
            
            # 끝 버전의 major.minor
            end_major, end_minor = 999, 999
            if range_end:
                parts = range_end.split('.')
                end_major = int(parts[0])
                end_minor = int(parts[1]) if len(parts) > 1 else 999
            
            # 현재 커널 브랜치가 범위 안에 있는지 확인
            kernel_branch = (kernel_major, kernel_minor)
            start_branch = (start_major, start_minor)
            end_branch = (end_major, end_minor)
            
            return start_branch <= kernel_branch <= end_branch
            
        except (ValueError, IndexError):
            return False

    def _extract_cpe_version(self, cpe_criteria: str) -> Optional[str]:
        """CPE 문자열에서 버전 추출"""
        # cpe:2.3:o:linux:linux_kernel:6.5.0:*:*:*:*:*:*:*
        parts = cpe_criteria.split(":")
        if len(parts) > 5:
            version = parts[5]
            if version and version != "*" and version != "-":
                return version
        return None

    async def _check_kernel_patch_status(
        self, 
        cve_id: str, 
        distro_id: str, 
        distro_version: str,
        kernel_version: str
    ) -> str:
        """OS별 커널 패치 상태 확인
        
        Returns:
            'patched' | 'vulnerable' | 'unknown'
        """
        distro_lower = distro_id.lower()
        
        # Raspbian은 Debian 기반
        if "raspbian" in distro_lower or "raspberry" in distro_lower:
            distro_lower = "debian"
        
        # Ubuntu/Debian 계열
        if distro_lower in ["ubuntu", "debian"]:
            # Debian Security Tracker 확인
            patch_status, _ = await self.debian_security.get_patch_status(
                "linux", cve_id, kernel_version
            )
            if patch_status == "not_affected":
                return "patched"
            elif patch_status == "vulnerable_confirmed":
                return "vulnerable"
        
        # Alpine Linux
        elif distro_lower == "alpine":
            # Alpine은 롤링 릴리스라서 최신 버전이면 대부분 패치됨
            # 별도의 Alpine Security DB 체크 (구현 필요시 확장)
            pass
        
        return "unknown"

    def _normalize_cvss_score(self, cve: dict):
        """CVE의 CVSS 점수 정규화"""
        cvss_score = cve.get("cvss_score")
        cvss_v3_score = cve.get("cvss_v3_score")
        cvss_v2_score = cve.get("cvss_v2_score")
        
        if not cvss_score:
            if cvss_v3_score:
                cve["cvss_score"] = cvss_v3_score
                cve["cvss_severity"] = cve.get("cvss_v3_severity", "UNKNOWN")
                cve["cvss_version"] = "3.x"
            elif cvss_v2_score:
                cve["cvss_score"] = cvss_v2_score
                cve["cvss_severity"] = cve.get("cvss_v2_severity", "UNKNOWN")
                cve["cvss_version"] = "2.0"
                cve["cvss_v3_score"] = cvss_v2_score
                if not cve.get("cvss_v3_severity"):
                    cve["cvss_v3_severity"] = cve.get("cvss_v2_severity", "UNKNOWN")
            else:
                # CVSS 점수가 없으면 MEDIUM으로 설정 (HIGH 기본값은 오탐 유발)
                cve["cvss_score"] = 5.0
                cve["cvss_severity"] = "MEDIUM"
                cve["cvss_version"] = "default"
                cve["cvss_v3_score"] = 5.0
                cve["cvss_v3_severity"] = "MEDIUM"

        return {
            "cve_count": cve_count,
            "high_risk_count": high_risk_count
        }

    def _print_patch_stats(self):
        """패치 필터링 통계 출력"""
        stats = self._stats
        if stats["total_checked"] > 0:
            filtered_pct = (stats["filtered_by_patch"] / max(1, stats["total_checked"])) * 100
            apt_filtered_pct = (stats.get("filtered_by_apt_patched", 0) / max(1, stats["total_checked"])) * 100
            
            print(f"\n[취약점 분석 통계]")
            print(f"  - 총 CVE 체크: {stats['total_checked']}개")
            print(f"  - Security Tracker 패치됨: {stats['filtered_by_patch']}개 ({filtered_pct:.1f}%)")
            print(f"  - apt-cache 패치됨: {stats.get('filtered_by_apt_patched', 0)}개 ({apt_filtered_pct:.1f}%)")
            print(f"  - 실제 취약: {stats['actual_vulnerable']}개")
            print(f"  - KEV 등재: {stats.get('kev_count', 0)}개")
            print(f"  - 활성 사용 패키지: {stats.get('active_packages', 0)}개")

    async def _batch_update_epss_kev(self, session: AsyncSession, scan_id: Optional[int] = None):
        """EPSS/KEV 정보 배치 업데이트 (현재 스캔의 모든 CVE)"""
        if not scan_id:
            print("[EPSS] 스캔 ID 없음, EPSS 업데이트 건너뜀")
            return
        
        # 현재 스캔에서 발견된 모든 CVE 조회
        result = await session.execute(
            select(CVE)
            .join(Finding, Finding.cve_id == CVE.id)
            .where(Finding.scan_id == scan_id)
            .distinct()
        )
        scan_cves = result.scalars().all()
        
        if not scan_cves:
            print("[EPSS] 스캔에서 발견된 CVE 없음")
            return
        
        print(f"[EPSS] 스캔에서 발견된 {len(scan_cves)}개 CVE의 최신 EPSS 점수 조회 중...")
        
        # 배치로 EPSS 조회 (100개씩)
        cve_ids = [cve.cve_id for cve in scan_cves]
        batch_size = 100
        updated_count = 0
        
        for i in range(0, len(cve_ids), batch_size):
            batch = cve_ids[i:i + batch_size]
            
            try:
                epss_results = await self.epss_client.get_epss_scores_batch(batch)
                
                for cve in scan_cves[i:i + batch_size]:
                    epss_data = epss_results.get(cve.cve_id)
                    if epss_data:
                        cve.epss_score = epss_data.get("epss_score")
                        cve.epss_percentile = epss_data.get("epss_percentile")
                        updated_count += 1
                
                # 배치마다 커밋
                await session.commit()
                
            except Exception as e:
                print(f"[EPSS] 배치 {i}-{i+batch_size} 오류: {e}")
                continue
        
        print(f"[EPSS]  {updated_count}/{len(scan_cves)}개 CVE 업데이트 완료")
        
        # KEV 정보 업데이트 (현재 스캔의 CVE만)
        print(f"[KEV] {len(scan_cves)}개 CVE 체크 중...")
        kev_updated = 0
        
        for cve in scan_cves:
            is_kev = self.kev_client.is_known_exploited(cve.cve_id)
            if is_kev:
                kev_info = self.kev_client.get_kev_info(cve.cve_id)
                cve.is_kev = True
                cve.kev_date_added = kev_info.get("date_added") if kev_info else None
                cve.kev_due_date = kev_info.get("due_date") if kev_info else None
                cve.kev_ransomware = kev_info.get("known_ransomware", False) if kev_info else False
                kev_updated += 1
            elif cve.is_kev is None:
                # KEV가 아닌 경우도 명시적으로 False로 설정
                cve.is_kev = False
        
        await session.commit()
        print(f"[KEV]  {kev_updated}개 KEV CVE 발견")

    async def _get_or_create_package(
        self,
        session: AsyncSession,
        host_id: int,
        pkg_data: Dict,
        scan_id: int = None
    ) -> Package:
        """Get existing package or create new one (scan-specific)"""
        # 스캔별로 패키지를 독립적으로 저장
        query = select(Package).where(
            Package.host_id == host_id,
            Package.name == pkg_data["name"],
            Package.version == pkg_data["version"]
        )
        
        # scan_id가 있으면 해당 스캔의 패키지만 조회
        if scan_id is not None:
            query = query.where(Package.scan_id == scan_id)
        
        result = await session.execute(query)
        package = result.scalar_one_or_none()

        if not package:
            package = Package(
                host_id=host_id,
                scan_id=scan_id,  # 스캔별 독립 저장
                name=pkg_data["name"],
                version=pkg_data["version"],
                architecture=pkg_data.get("architecture", "unknown"),
                package_manager=pkg_data.get("package_manager", "unknown")
            )
            session.add(package)
            await session.flush()

        return package

    async def _get_or_create_cve(
        self,
        session: AsyncSession,
        cve_data: Dict
    ) -> CVE:
        """Get existing CVE or create new one with EPSS and KEV data"""
        result = await session.execute(
            select(CVE).where(CVE.cve_id == cve_data["cve_id"])
        )
        cve = result.scalar_one_or_none()

        if not cve:
            # EPSS/KEV는 스캔 완료 후 배치로 처리 (속도 향상)
            cve = CVE(
                cve_id=cve_data["cve_id"],
                description=cve_data.get("description"),
                published_date=cve_data.get("published_date"),
                last_modified=cve_data.get("last_modified"),
                # === 통합 CVSS (우선순위 적용됨: v4 > v3.1 > v3.0 > v2) ===
                cvss_score=cve_data.get("cvss_score") or cve_data.get("cvss_v3_score") or cve_data.get("cvss_v2_score"),
                cvss_severity=cve_data.get("cvss_severity") or cve_data.get("cvss_v3_severity") or cve_data.get("cvss_v2_severity"),
                cvss_vector=cve_data.get("cvss_vector") or cve_data.get("cvss_v3_vector") or cve_data.get("cvss_v2_vector"),
                cvss_version=cve_data.get("cvss_version"),
                # === CVSS v4 ===
                cvss_v4_score=cve_data.get("cvss_v4_score"),
                cvss_v4_vector=cve_data.get("cvss_v4_vector"),
                cvss_v4_severity=cve_data.get("cvss_v4_severity"),
                # === CVSS v3 ===
                cvss_v3_score=cve_data.get("cvss_v3_score"),
                cvss_v3_vector=cve_data.get("cvss_v3_vector"),
                cvss_v3_severity=cve_data.get("cvss_v3_severity"),
                # === CVSS v2 (오래된 CVE 대응) ===
                cvss_v2_score=cve_data.get("cvss_v2_score"),
                cvss_v2_vector=cve_data.get("cvss_v2_vector"),
                cvss_v2_severity=cve_data.get("cvss_v2_severity"),
                attack_vector=cve_data.get("attack_vector"),
                attack_complexity=cve_data.get("attack_complexity"),
                privileges_required=cve_data.get("privileges_required"),
                user_interaction=cve_data.get("user_interaction"),
                scope=cve_data.get("scope"),
                confidentiality_impact=cve_data.get("confidentiality_impact"),
                integrity_impact=cve_data.get("integrity_impact"),
                availability_impact=cve_data.get("availability_impact"),
                cpe_list=cve_data.get("cpe_list"),
                references=cve_data.get("references"),
                # EPSS/KEV는 배치 처리에서 설정됨
                epss_score=None,
                epss_percentile=None,
                is_kev=None,
                kev_date_added=None,
                kev_due_date=None,
                kev_ransomware=False
            )
            session.add(cve)
            await session.flush()
        else:
            # Update existing CVE with missing data
            updated = False
            
            # 통합 CVSS 점수 업데이트 (없으면 새 데이터로)
            if not cve.cvss_score:
                new_score = cve_data.get("cvss_score") or cve_data.get("cvss_v3_score") or cve_data.get("cvss_v2_score")
                if new_score:
                    cve.cvss_score = new_score
                    cve.cvss_severity = cve_data.get("cvss_severity") or cve_data.get("cvss_v3_severity") or cve_data.get("cvss_v2_severity")
                    cve.cvss_vector = cve_data.get("cvss_vector") or cve_data.get("cvss_v3_vector") or cve_data.get("cvss_v2_vector")
                    cve.cvss_version = cve_data.get("cvss_version")
                    updated = True
            
            # CVSS v4 업데이트
            if not cve.cvss_v4_score and cve_data.get("cvss_v4_score"):
                cve.cvss_v4_score = cve_data.get("cvss_v4_score")
                cve.cvss_v4_severity = cve_data.get("cvss_v4_severity")
                cve.cvss_v4_vector = cve_data.get("cvss_v4_vector")
                updated = True
            
            # CVSS v3 업데이트
            if not cve.cvss_v3_score and cve_data.get("cvss_v3_score"):
                cve.cvss_v3_score = cve_data.get("cvss_v3_score")
                cve.cvss_v3_severity = cve_data.get("cvss_v3_severity")
                cve.cvss_v3_vector = cve_data.get("cvss_v3_vector")
                updated = True
            
            # CVSS v2 업데이트
            if not cve.cvss_v2_score and cve_data.get("cvss_v2_score"):
                cve.cvss_v2_score = cve_data.get("cvss_v2_score")
                cve.cvss_v2_severity = cve_data.get("cvss_v2_severity")
                cve.cvss_v2_vector = cve_data.get("cvss_v2_vector")
                updated = True
            
            # EPSS/KEV는 배치 처리에서 업데이트 (개별 조회 제거)

            if updated:
                await session.flush()

        return cve

    async def _create_finding(
        self,
        session: AsyncSession,
        host_id: int,
        package_id: int,
        cve_id: int,
        cve_data: Dict,
        usage_info: Optional[Dict] = None,
        patch_info: Optional[Dict] = None,
        pkg_name: Optional[str] = None,
        package_manager: Optional[str] = None
    ):
        """Create a vulnerability finding with extended info"""
        # 같은 스캔 내에서만 중복 체크 (scan_id 포함)
        result = await session.execute(
            select(Finding).where(
                Finding.host_id == host_id,
                Finding.package_id == package_id,
                Finding.cve_id == cve_id,
                Finding.scan_id == self._current_scan_id
            )
        )
        existing = result.scalar_one_or_none()

        if existing:
            return

        cvss_score = cve_data.get("cvss_v3_score", 0)
        risk_level = self._calculate_risk_level(cvss_score)

        # KEV 확인
        is_kev = self.kev_client.is_known_exploited(cve_data.get("cve_id", ""))

        # 권한 상승 CVE 확인
        is_privesc, privesc_reason = self.kernel_analyzer.is_privilege_escalation_cve(cve_data)

        # 커널 관련 CVE 확인
        is_kernel_cve = self.kernel_analyzer.is_kernel_package(pkg_name) if pkg_name else False

        # package_manager가 없으면 Package 테이블에서 조회
        if not package_manager and package_id:
            from vulnscan.models.schemas import Package
            pkg_result = await session.execute(
                select(Package).where(Package.id == package_id)
            )
            pkg = pkg_result.scalar_one_or_none()
            if pkg:
                package_manager = pkg.package_manager

        # collector_mode 결정
        # 시스템 패키지 (__OS__, __KERNEL__)만 os/kernel로 분류
        # 일반 패키지는 모두 local로 분류
        if pkg_name and pkg_name.startswith('__'):
            # 시스템 패키지
            if 'KERNEL' in pkg_name:
                collector_mode = "kernel"
            else:
                collector_mode = "os"
        elif is_kernel_cve:
            # linux-kernel 패키지
            collector_mode = "kernel"
        elif package_manager == "binary":
            collector_mode = "binary"
        else:
            # 일반 패키지 (apk, dpkg로 설치된 zlib, musl 등 포함)
            collector_mode = "local"

        # 우선순위 계산
        epss_score = cve_data.get("epss_score")
        has_patch = patch_info.get("has_update", False) if patch_info else False

        # CVE 연령 계산
        cve_age_days = None
        if cve_data.get("published_date"):
            try:
                pub_date = cve_data["published_date"]
                if isinstance(pub_date, datetime):
                    cve_age_days = (datetime.now() - pub_date).days
            except Exception:
                pass

        priority_result = self.prioritizer.calculate_priority_score(
            cvss_score=cvss_score,
            epss_score=epss_score,
            is_kev=is_kev,
            usage_info=usage_info,
            has_patch_available=has_patch,
            cve_age_days=cve_age_days
        )

        finding = Finding(
            host_id=host_id,
            package_id=package_id,
            cve_id=cve_id,
            scan_id=self._current_scan_id,
            risk_level=risk_level,
            is_unauthorized_access=cve_data.get("is_unauthorized_access", False),
            status="open",
            # 패키지 사용 상태
            pkg_is_running=usage_info.get("is_running", False) if usage_info else False,
            pkg_is_service=usage_info.get("is_service", False) if usage_info else False,
            pkg_is_listening=usage_info.get("is_listening", False) if usage_info else False,
            pkg_listening_ports=",".join(map(str, usage_info.get("listening_ports", []))) if usage_info else None,
            pkg_usage_level=usage_info.get("usage_level") if usage_info else None,
            pkg_last_used=usage_info.get("last_used") if usage_info else None,
            # 패치 정보
            has_patch_available=has_patch,
            patch_version=patch_info.get("candidate_version") if patch_info else None,
            confidence_level=cve_data.get("confidence_level", "confirmed"),
            # 우선순위
            priority_score=priority_result["priority_score"],
            priority_level=priority_result["priority_level"],
            # 권한 상승 및 커널
            is_privilege_escalation=is_privesc,
            privesc_reason=privesc_reason[:255] if privesc_reason else None,
            is_kernel_cve=is_kernel_cve,
            collector_mode=collector_mode
        )
        session.add(finding)

        # 통계 업데이트
        if is_kev:
            self._stats["kev_count"] = self._stats.get("kev_count", 0) + 1
        if is_privesc:
            self._stats["privesc_count"] = self._stats.get("privesc_count", 0) + 1
        if is_kernel_cve:
            self._stats["kernel_cve_count"] = self._stats.get("kernel_cve_count", 0) + 1

    def _calculate_risk_level(self, cvss_score: Optional[float]) -> str:
        """Calculate risk level from CVSS score"""
        if not cvss_score:
            return "unknown"

        if cvss_score >= 9.0:
            return "critical"
        elif cvss_score >= 7.0:
            return "high"
        elif cvss_score >= 4.0:
            return "medium"
        else:
            return "low"

    async def _is_relevant_cve(self, cve_data: Dict, pkg_data: Dict) -> bool:
        """Check if CVE is relevant to the package - 엄격한 매칭"""
        cpe_list = cve_data.get("cpe_list", "")
        pkg_name = pkg_data["name"].lower()
        pkg_version = pkg_data.get("version", "")
        package_manager = pkg_data.get("package_manager", "")

        self._stats["total_checked"] += 1

        # If no CPE list, it's too ambiguous
        if not cpe_list:
            return False

        # CPE 매칭 최적화 - 빠른 문자열 검색 먼저
        cpe_list_lower = cpe_list.lower()
        pkg_name_variants = [pkg_name, pkg_name.replace("-", "_"), pkg_name.replace("_", "-")]
        
        # 빠른 체크: 패키지명이 CPE에 없으면 바로 제외
        found_any = False
        for variant in pkg_name_variants:
            if variant in cpe_list_lower:
                found_any = True
                break
        
        if not found_any:
            return False
        
        # 정확한 매칭 확인 - 더 엄격한 CPE 파싱
        cpe_parts = cpe_list_lower.split("|")
        found_in_cpe = False
        matched_cpe_index = -1
        matched_cpe_product = None

        for idx, cpe in enumerate(cpe_parts):
            # CPE format: cpe:2.3:a:vendor:product:version
            parts = cpe.split(":")
            if len(parts) <= 4:
                continue
                
            product = parts[4]
            vendor = parts[3] if len(parts) > 3 else ""
            
            # 정확한 매칭 (product가 패키지명과 일치)
            if product == pkg_name or product == pkg_name.replace("-", "_"):
                found_in_cpe = True
                matched_cpe_index = idx
                matched_cpe_product = product
                break
            
            # 부분 매칭 (예: openssl-dev → openssl) - 더 엄격하게
            base_pkg_name = self._get_base_package_name_for_cpe(pkg_name)
            if base_pkg_name and (product == base_pkg_name or product == base_pkg_name.replace("-", "_")):
                found_in_cpe = True
                matched_cpe_index = idx
                matched_cpe_product = product
                break

        if not found_in_cpe:
            return False

        # ========================================
        # 커널 CVE는 별도 처리 (_scan_kernel_cves에서 처리)
        # 패키지 스캔에서는 커널 CVE 완전 제외 (중복 및 오탐 방지)
        # ========================================
        if matched_cpe_product and "linux_kernel" in matched_cpe_product:
            # 모든 linux_kernel CVE는 _scan_kernel_cves에서 처리
            # 패키지 스캔에서는 무조건 제외
            return False

        # ========================================
        # PATCH STATUS CHECK (OS별 Security Tracker)
        # ========================================
        cve_id = cve_data.get("cve_id", "")
        patch_status, fixed_version = await self.debian_security.get_patch_status(
            pkg_name, cve_id, pkg_version
        )

        # 패치된 CVE 제외 옵션
        if self._scan_options.get("filter_patched", True):
            if patch_status == "not_affected":
                self._stats["filtered_by_patch"] += 1
                # 디버깅: 패치 정보 로그 (처음 5개만)
                if self._stats["filtered_by_patch"] <= 5:
                    print(f"    [패치됨] {pkg_name} {cve_id}")
                return False  # 이미 패치됨 - 취약하지 않음

        # ========================================
        # CVE 연령 체크 - 오래된 CVE 필터링 강화
        # ========================================
        if self._scan_options.get("filter_old_cve", True):
            published_date = cve_data.get("published_date")
            if published_date:
                try:
                    from datetime import datetime
                    if isinstance(published_date, str):
                        pub_date = datetime.fromisoformat(published_date.replace("Z", "+00:00"))
                    else:
                        pub_date = published_date

                    now = datetime.now(pub_date.tzinfo) if pub_date.tzinfo else datetime.now()
                    cve_age_days = (now - pub_date).days

                    # 7년(2555일) 이상 된 CVE는 트래커 정보 없으면 패치된 것으로 간주
                    # 현대 배포판(Ubuntu 22.04+, Debian 12+)은 이미 패치됨
                    if cve_age_days > 2555 and fixed_version is None and patch_status != "vulnerable_confirmed":
                        self._stats["filtered_by_patch"] += 1
                        return False
                except Exception:
                    pass

        # ========================================
        # NVD VERSION RANGE CHECK - 엄격한 버전 검증
        # ========================================
        version_ranges = cve_data.get("version_ranges", [])
        
        # 버전 범위가 있으면 반드시 체크
        if version_ranges:
            # 매칭된 CPE 인덱스의 버전 범위 확인
            if matched_cpe_index >= 0 and matched_cpe_index < len(version_ranges):
                version_range = version_ranges[matched_cpe_index]
                
                # 설치된 버전 파싱 (ubuntu/debian suffixes 제거)
                installed_version = self._parse_version(pkg_version.lower())
                
                if not self._is_version_vulnerable(installed_version, version_range):
                    # 버전이 취약 범위에 없음 - 스킵
                    return False
            elif patch_status != "vulnerable_confirmed":
                # 버전 범위가 매칭 안 되고 트래커에서도 확인 안 됨
                return False
        else:
            # 버전 범위가 없으면 트래커 정보로만 판단
            if patch_status != "vulnerable_confirmed":
                return False

        # ========================================
        # 타 OS 관련 CVE 제외
        # ========================================
        if self._scan_options.get("filter_other_os", True):
            description = cve_data.get("description", "").lower()

            # Exclude common false positives (타 OS 전용)
            false_positive_indicators = [
                "microsoft", "windows", "apple", "macos", "android",
                "chrome os", "safari", "internet explorer", "edge browser"
            ]

            for indicator in false_positive_indicators:
                if indicator in description and pkg_name not in ["chrome", "firefox", "chromium"]:
                    return False

        cve_data["confidence_level"] = "confirmed" if patch_status == "vulnerable_confirmed" else "potential"
        self._stats["actual_vulnerable"] += 1
        return True

    def _get_base_package_name_for_cpe(self, pkg_name: str) -> Optional[str]:
        """CPE 매칭용 기본 패키지명 추출 (라이브러리 접두사/접미사 제거)"""
        base = pkg_name.lower()
        
        # 개발/디버그 패키지 접미사 제거
        suffixes = ['-dev', '-dbg', '-dbgsym', '-doc', '-common', '-bin', 
                    '-data', '-tools', '-utils', '-libs', '-devel']
        for suffix in suffixes:
            if base.endswith(suffix):
                base = base[:-len(suffix)]
                break
        
        # lib 접두사 처리 (libssl3 → openssl, libcurl4 → curl)
        lib_mappings = {
            'libssl': 'openssl',
            'libcrypto': 'openssl',
            'libcurl': 'curl',
            'libz': 'zlib',
            'zlib': 'zlib',
            'libpng': 'libpng',
            'libjpeg': 'libjpeg',
        }
        
        for lib_prefix, mapped_name in lib_mappings.items():
            if base.startswith(lib_prefix):
                return mapped_name
        
        # 버전 번호 제거 (libssl1.1 → libssl, zlib1g → zlib)
        import re
        base = re.sub(r'\d+(\.\d+)*[a-z]?$', '', base)
        base = re.sub(r'\d+g$', '', base)  # Debian-style (zlib1g)
        
        return base if base and base != pkg_name else None

    def _parse_version(self, version_str: str) -> str:
        """Parse version string and extract core version number"""
        # Remove Ubuntu/Debian specific suffixes
        # Examples:
        # "1.1.1f-1ubuntu2" -> "1.1.1f"
        # "3.8.10-0ubuntu1~20.04.5" -> "3.8.10"
        # "2.31-0ubuntu9.9" -> "2.31"

        import re

        # Remove everything after first dash or tilde
        version = re.split(r'[-~]', version_str)[0]

        return version.strip()

    def _is_version_vulnerable(self, installed_version: str, version_range: Dict) -> bool:
        """Check if installed version falls within vulnerable range"""
        # Extract version range boundaries
        start_including = version_range.get("versionStartIncluding")
        end_including = version_range.get("versionEndIncluding")
        start_excluding = version_range.get("versionStartExcluding")
        end_excluding = version_range.get("versionEndExcluding")

        # If no version range specified, assume all versions vulnerable
        if not any([start_including, end_including, start_excluding, end_excluding]):
            # Check CPE criteria version
            criteria = version_range.get("criteria", "")
            parts = criteria.split(":")
            if len(parts) > 5:
                cpe_version = parts[5]
                if cpe_version and cpe_version != "*" and cpe_version != "-":
                    # Specific version in CPE
                    return self._compare_versions(installed_version, cpe_version) == 0
            # No specific version info - assume vulnerable
            return True

        # Check lower bound
        if start_including:
            if self._compare_versions(installed_version, start_including) < 0:
                return False

        if start_excluding:
            if self._compare_versions(installed_version, start_excluding) <= 0:
                return False

        # Check upper bound
        if end_including:
            if self._compare_versions(installed_version, end_including) > 0:
                return False

        if end_excluding:
            if self._compare_versions(installed_version, end_excluding) >= 0:
                return False

        return True

    def _compare_versions(self, version1: str, version2: str) -> int:
        """
        Compare two version strings.
        Returns: -1 if version1 < version2
                  0 if version1 == version2
                  1 if version1 > version2
        """
        import re

        def normalize_version(v):
            """Split version into comparable parts"""
            # Handle versions like "1.1.1f", "2.31", "3.8.10"
            parts = []
            for part in re.split(r'[.\-_]', v):
                # Try to extract numeric part
                numeric_match = re.match(r'^(\d+)', part)
                if numeric_match:
                    parts.append(int(numeric_match.group(1)))
                    # Add letter suffix if exists (e.g., "1f" -> [1, 'f'])
                    remainder = part[len(numeric_match.group(1)):]
                    if remainder:
                        parts.append(remainder)
                elif part:
                    parts.append(part)
            return parts

        v1_parts = normalize_version(version1)
        v2_parts = normalize_version(version2)

        # Compare part by part
        for i in range(max(len(v1_parts), len(v2_parts))):
            # Get part or default to 0/"" if one version is shorter
            p1 = v1_parts[i] if i < len(v1_parts) else 0
            p2 = v2_parts[i] if i < len(v2_parts) else 0

            # Compare integers directly
            if isinstance(p1, int) and isinstance(p2, int):
                if p1 < p2:
                    return -1
                elif p1 > p2:
                    return 1
            # String comparison
            elif isinstance(p1, str) and isinstance(p2, str):
                if p1 < p2:
                    return -1
                elif p1 > p2:
                    return 1
            # Mixed type: int < str
            elif isinstance(p1, int):
                return -1
            else:
                return 1

        return 0

    async def _match_packages_fast(
        self,
        session: AsyncSession,
        host_id: int,
        packages: List[Dict],
        scan_id: Optional[int],
        start_time: float
    ) -> Dict[str, int]:
        """Fast mode: Process packages using CPE index for maximum speed"""
        from ..models.schemas import ScanHistory
        from sqlalchemy import select
        import time

        total_cves = 0
        high_risk = 0
        total_packages = len(packages)
        
        # 프로세스 캐시 미리 로드 (CVE 스캔 전에 ps aux 한 번만 실행)
        print("[FAST] Preloading process cache before CVE scan...")
        await self.usage_analyzer.preload_process_cache()
        
        # 인덱스 로드 여부에 따라 배치 크기 결정
        # 인덱스 사용 시 매우 빠르므로 큰 배치 가능
        if self.nvd_client.is_index_loaded():
            batch_size = 100  # 인덱스 사용 시 100개씩
            print(f"[스캔] 배치 모드 시작: {total_packages}개 패키지 처리")
        else:
            batch_size = 40  # 기존 방식
            print(f"[스캔] 배치 모드 시작: {total_packages}개 패키지 처리")

        for batch_start in range(0, total_packages, batch_size):
            batch_end = min(batch_start + batch_size, total_packages)
            batch = packages[batch_start:batch_end]

            batch_num = (batch_start // batch_size) + 1
            total_batches = (total_packages - 1) // batch_size + 1
            
            batch_start_time = time.time()
            print(f"[스캔] 배치 {batch_num}/{total_batches} - {len(batch)}개 패키지 CVE 검색 중...")

            # Process batch in parallel - collect data WITHOUT committing to DB
            tasks = [self._process_package_data_only(pkg_data) for pkg_data in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            batch_elapsed = time.time() - batch_start_time

            # 배치 전체 CVE 미리 조회 (성능 최적화)
            all_cve_data = []
            for result in results:
                if isinstance(result, Exception) or not result:
                    continue
                if result.get('findings'):
                    all_cve_data.extend(result['findings'])
            
            # 한 번의 쿼리로 배치 전체 CVE 조회
            cve_map = {}
            if all_cve_data:
                cve_map = await self._get_or_create_cves_batch(session, all_cve_data)

            # Now save all batch results to DB in one transaction
            successful = 0
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    continue
                if result and result['findings']:
                    # Save to DB (CVE는 이미 cve_map에 있음)
                    try:
                        await self._save_batch_results_fast(session, host_id, batch[i], result, cve_map)
                        total_cves += result['cve_count']
                        high_risk += result['high_risk_count']
                        successful += 1
                    except Exception as e:
                        pass

            # Commit once per batch
            await session.commit()
            
            # 배치 완료 로그
            print(f"[스캔] 배치 {batch_num}/{total_batches} 완료 - {successful}개 패키지, 누적 CVE {total_cves}개 ({batch_elapsed:.1f}초)")

            # Update progress after each batch
            if scan_id:
                scan_result = await session.execute(
                    select(ScanHistory).where(ScanHistory.id == scan_id)
                )
                scan_record = scan_result.scalar_one_or_none()

                if scan_record:
                    progress = int((batch_end / total_packages) * 100)
                    elapsed = time.time() - start_time
                    avg_time_per_pkg = elapsed / batch_end if batch_end > 0 else 0
                    remaining_pkgs = total_packages - batch_end
                    estimated_remaining = int(avg_time_per_pkg * remaining_pkgs)

                    scan_record.current_package = f"Batch {batch_start//batch_size + 1}/{(total_packages-1)//batch_size + 1}"
                    scan_record.progress_percent = progress
                    scan_record.estimated_time_remaining = estimated_remaining
                    scan_record.packages_found = total_packages
                    scan_record.cves_found = total_cves
                    scan_record.high_risk_count = high_risk
                    await session.commit()

        print(f"[스캔] 패키지 스캔 완료 - {total_packages}개 패키지, {total_cves}개 CVE")
        print(f"[커널] 커널 CVE 검색 시작...")
        
        # 커널 CVE 검색 (패키지 스캔과 별도로)
        kernel_result = await self._scan_kernel_cves(session, host_id, scan_id)
        if kernel_result:
            total_cves += kernel_result.get("cve_count", 0)
            high_risk += kernel_result.get("high_risk_count", 0)
            print(f"[커널] {kernel_result.get('cve_count', 0)}개 CVE 발견")
        
        # 패치 필터링 통계 출력
        self._print_patch_stats()

        # EPSS/KEV 배치 업데이트 (현재 스캔의 모든 CVE)
        await self._batch_update_epss_kev(session, scan_id)

        print(f"[완료] 스캔 완료 - 총 {total_cves}개 CVE, 고위험 {high_risk}개")
        return {
            "total_cves": total_cves,
            "high_risk_count": high_risk,
            "filtered_by_patch": self._stats["filtered_by_patch"]
        }

    async def _process_single_package(
        self,
        session: AsyncSession,
        host_id: int,
        pkg_data: Dict
    ) -> Optional[Dict[str, int]]:
        """Process a single package and return CVE stats"""
        try:
            # 현재 스캔 ID 사용 (미리 저장되어 있음)
            package = await self._get_or_create_package(session, host_id, pkg_data, self._current_scan_id)

            cves = await self.nvd_client.search_cve_by_keyword(
                pkg_data["name"],
                cve_years=self._scan_options.get("cve_years")
            )

            cve_count = 0
            high_risk_count = 0
            seen_cves = set()

            for cve_data in cves:
                cve_id = cve_data.get("cve_id")
                if cve_id in seen_cves:
                    continue
                seen_cves.add(cve_id)
                cve = await self._get_or_create_cve(session, cve_data)

                if await self._is_relevant_cve(cve_data, pkg_data):
                    await self._create_finding(
                        session, host_id, package.id, cve.id, cve_data,
                        pkg_name=pkg_data.get("name"),
                        package_manager=pkg_data.get("package_manager")
                    )
                    cve_count += 1

                    cvss_score = cve_data.get("cvss_v3_score")
                    if cvss_score is not None and cvss_score >= 7.0:
                        high_risk_count += 1

            await session.commit()

            return {
                "cve_count": cve_count,
                "high_risk_count": high_risk_count
            }
        except Exception as e:
            print(f"Error processing package {pkg_data.get('name', 'unknown')}: {e}")
            await session.rollback()
            return None

    async def _process_package_data_only(self, pkg_data: Dict) -> Optional[Dict]:
        """Process a single package - collect CVE data only, NO database writes (dev_local_scanner 스타일)"""
        try:
            pkg_name = pkg_data["name"]
            base_name = self._get_base_package_name(pkg_name)

            # 너무 짧은 base_name은 오탐 위험 (2글자 이하) 또는 base_name이 pkg_name과 같으면 한 번만 검색
            if len(base_name) <= 2 or base_name == pkg_name:
                base_name = pkg_name
                search_full_name = False  # 중복 검색 방지
            else:
                search_full_name = True

            # Base name으로 검색 (캐시 hit rate 높음)
            cves = await self.nvd_client.search_cve_by_keyword(
                base_name,
                cve_years=self._scan_options.get("cve_years")
            )

            # Base name 결과가 없고, full name이 다르면 full name으로 재검색
            if not cves and search_full_name:
                cves = await self.nvd_client.search_cve_by_keyword(
                    pkg_name,
                    cve_years=self._scan_options.get("cve_years")
                )

            relevant_cves = []
            cve_count = 0
            high_risk_count = 0
            seen_cves = set()

            for cve_data in cves:
                cve_id = cve_data.get("cve_id")
                if cve_id in seen_cves:
                    continue
                seen_cves.add(cve_id)
                if await self._is_relevant_cve(cve_data, pkg_data):
                    relevant_cves.append(cve_data)
                    cve_count += 1

                    cvss_score = cve_data.get("cvss_v3_score")
                    if cvss_score is not None and cvss_score >= 7.0:
                        high_risk_count += 1

            # 취약점이 발견된 경우에만 사용 상태와 패치 정보 수집
            usage_info = None
            patch_info = None
            if relevant_cves:
                try:
                    # 타임아웃 3초 (속도 최우선)
                    usage_info = await asyncio.wait_for(
                        self.usage_analyzer.analyze_package(pkg_name),
                        timeout=3.0
                    )
                    if usage_info and usage_info.get("usage_level") == "active":
                        self._stats["active_packages"] = self._stats.get("active_packages", 0) + 1
                except asyncio.TimeoutError:
                    pass  # 타임아웃 무시
                except Exception:
                    pass

                try:
                    patch_info = await self.patch_checker.check_available_update(pkg_name)
                except Exception:
                    pass
            
            # 상세 로그: 검색된 CVE vs 관련 CVE (대량만 출력)
            if len(cves) > 500:
                # 대량 검색 케이스 (오탐 가능성)
                print(f"  {pkg_name}: 검색 {len(cves)}개 → 관련 {cve_count}개 CVE")
            elif cve_count > 10:
                print(f"  {pkg_name}: {cve_count}개 CVE")

            return {
                "cve_count": cve_count,
                "high_risk_count": high_risk_count,
                "findings": relevant_cves,
                "usage_info": usage_info,
                "patch_info": patch_info
            }
        except Exception as e:
            print(f"  {pkg_data.get('name', 'unknown')} CVE 조회 실패: {e}")
            return None

    def _get_base_package_name(self, pkg_name: str) -> str:
        """Extract base package name for better cache hit rate"""
        base = pkg_name.lower()
        
        # 커널 패키지 이름 매핑 (NVD에서 "linux kernel"로 검색되도록)
        kernel_patterns = ['linux-lts', 'linux-virt', 'linux-image', 'linux-headers', 
                          'linux-firmware', 'kernel', 'linux-generic', 'linux-aws',
                          'linux-azure', 'linux-gcp', 'linux-oracle']
        for pattern in kernel_patterns:
            if pattern in base:
                return "linux kernel"  # NVD 키워드와 일치하도록
        
        # Remove common suffixes
        suffixes = ['-dev', '-dbg', '-doc', '-common', '-bin', '-data', '-tools']

        for suffix in suffixes:
            if base.endswith(suffix):
                base = base[:-len(suffix)]
                break

        # Remove version numbers (e.g., libssl1.1 -> libssl)
        import re
        base = re.sub(r'\d+(\.\d+)*$', '', base)

        return base if base else pkg_name

    async def _get_or_create_cves_batch(
        self,
        session: AsyncSession,
        cve_data_list: List[Dict]
    ) -> Dict[str, CVE]:
        """배치로 CVE 조회 및 생성 (성능 최적화) - EPSS 조회 생략"""
        if not cve_data_list:
            return {}
        
        # 중복 CVE ID 제거
        seen_ids = set()
        unique_cve_data = []
        for cve_data in cve_data_list:
            cve_id = cve_data["cve_id"]
            if cve_id not in seen_ids:
                seen_ids.add(cve_id)
                unique_cve_data.append(cve_data)
        
        cve_ids = list(seen_ids)
        
        # 한 번의 쿼리로 기존 CVE 모두 조회
        result = await session.execute(
            select(CVE).where(CVE.cve_id.in_(cve_ids))
        )
        existing_cves = {cve.cve_id: cve for cve in result.scalars().all()}
        
        # 없는 CVE만 생성 (EPSS 조회 생략 - 속도 최우선)
        new_cves = {}
        new_cve_objects = []
        
        for cve_data in unique_cve_data:
            cve_id = cve_data["cve_id"]
            if cve_id in existing_cves or cve_id in new_cves:
                continue
            
            # KEV 정보만 조회 (로컬 캐시, 빠름)
            is_kev = self.kev_client.is_known_exploited(cve_id)
            kev_info = self.kev_client.get_kev_info(cve_id) if is_kev else None
            
            cve = CVE(
                cve_id=cve_id,
                description=cve_data.get("description"),
                published_date=cve_data.get("published_date"),
                last_modified=cve_data.get("last_modified"),
                cvss_v3_score=cve_data.get("cvss_v3_score"),
                cvss_v3_vector=cve_data.get("cvss_v3_vector"),
                cvss_v3_severity=cve_data.get("cvss_v3_severity"),
                cvss_v2_score=cve_data.get("cvss_v2_score"),
                cvss_v2_vector=cve_data.get("cvss_v2_vector"),
                cvss_v2_severity=cve_data.get("cvss_v2_severity"),
                attack_vector=cve_data.get("attack_vector"),
                attack_complexity=cve_data.get("attack_complexity"),
                privileges_required=cve_data.get("privileges_required"),
                user_interaction=cve_data.get("user_interaction"),
                scope=cve_data.get("scope"),
                confidentiality_impact=cve_data.get("confidentiality_impact"),
                integrity_impact=cve_data.get("integrity_impact"),
                availability_impact=cve_data.get("availability_impact"),
                cpe_list=cve_data.get("cpe_list"),
                references=cve_data.get("references"),
                # EPSS는 나중에 별도로 업데이트 (스캔 속도 최우선)
                epss_score=None,
                epss_percentile=None,
                is_kev=is_kev,
                kev_date_added=kev_info.get("date_added") if kev_info else None,
                kev_due_date=kev_info.get("due_date") if kev_info else None,
                kev_ransomware=kev_info.get("known_ransomware", False) if kev_info else False
            )
            new_cve_objects.append(cve)
            new_cves[cve_id] = cve
        
        # 배치로 한 번에 추가
        if new_cve_objects:
            session.add_all(new_cve_objects)
            await session.flush()
        
        # 기존 + 새 CVE 합쳐서 반환
        all_cves = {**existing_cves, **new_cves}
        return all_cves

    async def _save_batch_results(
        self,
        session: AsyncSession,
        host_id: int,
        pkg_data: Dict,
        result: Dict
    ):
        """Save batch results to database (legacy - slower)"""
        # Create or get package (with current scan_id)
        package = await self._get_or_create_package(session, host_id, pkg_data, self._current_scan_id)

        # 사용 상태 및 패치 정보
        usage_info = result.get('usage_info')
        patch_info = result.get('patch_info')

        #  배치로 CVE 조회 (하나씩 조회 대신)
        cve_map = await self._get_or_create_cves_batch(session, result['findings'])

        # Create findings
        for cve_data in result['findings']:
            cve = cve_map[cve_data["cve_id"]]
            await self._create_finding(
                session, host_id, package.id, cve.id, cve_data,
                usage_info=usage_info,
                patch_info=patch_info,
                pkg_name=pkg_data.get("name"),
                package_manager=pkg_data.get("package_manager")
            )

        await session.flush()

    async def _save_batch_results_fast(
        self,
        session: AsyncSession,
        host_id: int,
        pkg_data: Dict,
        result: Dict,
        cve_map: Dict[str, CVE]
    ):
        """Save batch results to database (fast - CVE already loaded)"""
        # Create or get package (with current scan_id)
        package = await self._get_or_create_package(session, host_id, pkg_data, self._current_scan_id)

        # 사용 상태 및 패치 정보
        usage_info = result.get('usage_info')
        patch_info = result.get('patch_info')

        # Create findings (CVE는 이미 cve_map에 로드됨)
        for cve_data in result['findings']:
            cve = cve_map.get(cve_data["cve_id"])
            if not cve:
                # 혹시 없으면 개별 조회 (fallback)
                cve = await self._get_or_create_cve(session, cve_data)
            
            await self._create_finding(
                session, host_id, package.id, cve.id, cve_data,
                usage_info=usage_info,
                patch_info=patch_info,
                pkg_name=pkg_data.get("name"),
                package_manager=pkg_data.get("package_manager")
            )

        await session.flush()

    async def _process_single_package_with_session(
        self,
        host_id: int,
        pkg_data: Dict
    ) -> Optional[Dict[str, int]]:
        """Process a single package with its own database session (for normal mode)"""
        from ..models.database import async_session_maker

        async with async_session_maker() as session:
            try:
                package = await self._get_or_create_package(session, host_id, pkg_data)

                cves = await self.nvd_client.search_cve_by_keyword(pkg_data["name"])

                cve_count = 0
                high_risk_count = 0
                seen_cves = set()

                for cve_data in cves:
                    try:
                        cve_id = cve_data.get("cve_id")
                        if cve_id in seen_cves:
                            continue
                        seen_cves.add(cve_id)
                        cve = await self._get_or_create_cve(session, cve_data)

                        if await self._is_relevant_cve(cve_data, pkg_data):
                            await self._create_finding(
                                session, host_id, package.id, cve.id, cve_data,
                                pkg_name=pkg_data.get("name"),
                                package_manager=pkg_data.get("package_manager")
                            )
                            cve_count += 1

                            cvss_score = cve_data.get("cvss_v3_score")
                            if cvss_score is not None and cvss_score >= 7.0:
                                high_risk_count += 1
                    except Exception as cve_error:
                        continue

                await session.commit()

                if cve_count > 0:
                    print(f"  {pkg_data['name']}: {cve_count}개 CVE 발견")

                return {
                    "cve_count": cve_count,
                    "high_risk_count": high_risk_count
                }
            except Exception as e:
                print(f"패키지 처리 실패 ({pkg_data.get('name', 'unknown')}): {e}")
                await session.rollback()
                return None
