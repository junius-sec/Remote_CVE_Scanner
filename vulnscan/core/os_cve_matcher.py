"""
OS-Level CVE Matcher
OS 버전, 커널 버전으로 시스템 레벨 취약점 매칭

개선사항:
- 엄격한 버전 범위 검증
- OS별 패치 상태 확인
- 느슨한 description 매칭 제거
"""

import logging
import re
from typing import List, Dict, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class OSCVEMatcher:
    """OS/커널 기반 CVE 매칭 - 엄격한 버전 검증"""
    
    def __init__(self, nvd_client):
        self.nvd_client = nvd_client
        self.cve_years = None  # CVE 검색 시작 년도
        
    def _parse_kernel_version(self, kernel_version: str) -> str:
        """커널 버전 문자열에서 순수 버전 번호 추출
        
        Examples:
            6.6.31+rpt-rpi-v8 -> 6.6.31
            6.8.0-90-generic -> 6.8.0
            6.18.5-0-lts -> 6.18.5
        """
        # 버전 번호만 추출 (숫자.숫자.숫자 패턴)
        match = re.match(r'^(\d+\.\d+\.\d+)', kernel_version)
        if match:
            return match.group(1)
        return kernel_version.split('-')[0].split('+')[0]
        
    def generate_os_cpes(self, os_info: Dict) -> List[str]:
        """
        OS 정보로부터 CPE 생성
        
        Args:
            os_info: {
                'distro_id': 'alpine',
                'distro_version': '3.23.2',
                'kernel_version': '6.18.5-0-lts',
                'arch': 'x86_64'
            }
        
        Returns:
            CPE 문자열 리스트
        """
        cpes = []
        distro_id = os_info.get('distro_id', '').lower()
        distro_version = os_info.get('distro_version', '')
        kernel_version = os_info.get('kernel_version', '')
        
        # Raspbian은 Debian 기반
        if distro_id in ['raspbian', 'raspberry']:
            distro_id = 'debian'
        
        # Alpine Linux CPE
        if distro_id == 'alpine':
            if distro_version:
                # cpe:2.3:o:alpinelinux:alpine_linux:3.23.2
                cpes.append(f"cpe:2.3:o:alpinelinux:alpine_linux:{distro_version}")
                # 마이너 버전만 (3.23)
                major_minor = '.'.join(distro_version.split('.')[:2])
                cpes.append(f"cpe:2.3:o:alpinelinux:alpine_linux:{major_minor}")
        
        # Ubuntu CPE
        elif distro_id == 'ubuntu':
            if distro_version:
                # cpe:2.3:o:canonical:ubuntu_linux:22.04
                cpes.append(f"cpe:2.3:o:canonical:ubuntu_linux:{distro_version}")
        
        # Debian CPE
        elif distro_id == 'debian':
            if distro_version:
                # cpe:2.3:o:debian:debian_linux:12
                cpes.append(f"cpe:2.3:o:debian:debian_linux:{distro_version}")
        
        # CentOS/RHEL CPE
        elif distro_id in ['centos', 'rhel', 'redhat']:
            if distro_version:
                vendor = 'centos' if distro_id == 'centos' else 'redhat'
                cpes.append(f"cpe:2.3:o:{vendor}:{distro_id}:{distro_version}")
        
        # Linux Kernel CPE (모든 배포판에서 공통)
        if kernel_version:
            # 커널 버전 정규화
            kernel_clean = self._parse_kernel_version(kernel_version)
            cpes.append(f"cpe:2.3:o:linux:linux_kernel:{kernel_clean}")
            
            # 메이저.마이너 버전 (6.18) - 더 넓은 매칭용
            kernel_major_minor = '.'.join(kernel_clean.split('.')[:2])
            cpes.append(f"cpe:2.3:o:linux:linux_kernel:{kernel_major_minor}")
        
        return cpes
    
    async def find_os_cves(self, os_info: Dict) -> List[Dict]:
        """
        OS 정보로 CVE 검색
        
        Returns:
            [{
                'cve_id': 'CVE-2024-1234',
                'type': 'os' or 'kernel',
                'target': 'Alpine Linux 3.23.2' or 'Linux Kernel 6.18.5',
                'cvss_score': 7.5,
                'description': '...',
                ...
            }]
        """
        results = []
        cpes = self.generate_os_cpes(os_info)
        
        if not cpes:
            logger.warning("No CPEs generated from OS info")
            return results
        
        logger.info(f"Generated CPEs: {cpes}")
        
        for cpe in cpes:
            try:
                # NVD에서 CPE로 CVE 검색
                cves = await self._search_cve_by_cpe(cpe, os_info)
                
                # 타입 판별 (kernel vs os)
                cve_type = 'kernel' if 'linux_kernel' in cpe else 'os'
                target = self._get_target_name(cpe, os_info)
                
                for cve in cves:
                    cve['type'] = cve_type
                    cve['target'] = target
                    cve['cpe'] = cpe
                    results.append(cve)
                    
            except Exception as e:
                logger.error(f"Failed to search CVE for CPE {cpe}: {e}")
                continue
        
        # 중복 제거 (CVE ID 기준)
        seen = set()
        unique_results = []
        for cve in results:
            if cve['cve_id'] not in seen:
                seen.add(cve['cve_id'])
                unique_results.append(cve)
        
        logger.info(f"Found {len(unique_results)} unique OS/Kernel CVEs")
        return unique_results
    
    async def _search_cve_by_cpe(self, cpe: str, os_info: Dict) -> List[Dict]:
        """CPE로 NVD에서 CVE 검색 - 엄격한 버전 검증 포함"""
        from datetime import datetime
        
        try:
            # NVD API 2.0 사용
            # cve_years가 설정되어 있으면 해당 년도 이후만 검색
            pub_start_date = None
            if self.cve_years:
                pub_start_date = (self.cve_years, 1, 1)
                logger.info(f"OS CVE 검색: {cpe}, 시작 년도: {self.cve_years}")
            
            cves = await self.nvd_client.search_by_cpe(
                cpe, 
                pub_start_date=pub_start_date,
                results_per_page=100  # 최대 100개
            )
            
            logger.info(f"OS CVE 원본 결과: {cpe} -> {len(cves)}개")
            
            # 커널 CVE의 경우 엄격한 버전 검증
            is_kernel_cpe = 'linux:linux_kernel' in cpe.lower()
            kernel_version = None
            kernel_major = 6  # 기본값
            
            if is_kernel_cpe:
                kernel_version = self._parse_kernel_version(os_info.get('kernel_version', ''))
                try:
                    kernel_major = int(kernel_version.split('.')[0])
                except:
                    kernel_major = 6
            
            results = []
            filtered_count = 0
            cpe_mismatch_filtered = 0
            
            for cve_data in cves:
                # === CPE 정확도 검증 ===
                # NVD API의 cpeName 검색이 부정확하므로, 
                # 반환된 CVE의 CPE 리스트에 실제로 검색 CPE가 있는지 확인
                cve_cpe_list = cve_data.get('cpe_list', '').lower()
                
                # 검색한 CPE의 핵심 부분 추출 (예: debian:debian_linux:13)
                search_cpe_lower = cpe.lower()
                # cpe:2.3:o:debian:debian_linux:13 에서 vendor:product:version 추출
                cpe_parts = search_cpe_lower.split(':')
                if len(cpe_parts) >= 6:
                    vendor_product_version = ':'.join(cpe_parts[3:6])  # debian:debian_linux:13
                    
                    # CVE의 CPE 리스트에 해당 패턴이 있는지 확인
                    if vendor_product_version not in cve_cpe_list:
                        cpe_mismatch_filtered += 1
                        continue
                
                # 커널 CVE 추가 필터링
                if is_kernel_cpe and kernel_version:
                    # 버전 범위 검증 필수
                    version_ranges = cve_data.get('version_ranges', [])
                    if not self._is_kernel_version_affected(kernel_version, version_ranges):
                        filtered_count += 1
                        continue
                
                results.append({
                    'cve_id': cve_data.get('cve_id'),
                    'description': cve_data.get('description', ''),
                    'cvss_score': cve_data.get('cvss_v3_score') or cve_data.get('cvss_v2_score'),
                    'severity': cve_data.get('cvss_v3_severity') or cve_data.get('cvss_v2_severity'),
                    'published_date': cve_data.get('published_date'),
                    'last_modified': cve_data.get('last_modified'),
                    'version_ranges': cve_data.get('version_ranges', []),
                    'epss_score': None,  # EPSS는 별도 조회 필요
                })
            
            if cpe_mismatch_filtered > 0 or filtered_count > 0:
                logger.info(f"OS CVE 필터링: CPE불일치={cpe_mismatch_filtered}, 버전불일치={filtered_count}")
            logger.info(f"OS CVE 최종 결과: {cpe} -> {len(results)}개")
            
            return results
            
        except Exception as e:
            # 404 에러는 해당 CPE에 CVE가 없다는 의미이므로 경고만 표시
            if "404" in str(e):
                logger.debug(f"No CVEs found for CPE {cpe} (404)")
            else:
                logger.error(f"NVD CPE search failed for {cpe}: {e}")
            return []
    
    def _is_kernel_version_affected(self, kernel_version: str, version_ranges: list) -> bool:
        """커널 버전이 취약한 범위에 포함되는지 엄격하게 확인"""
        if not version_ranges:
            # 버전 범위가 없으면 취약하지 않은 것으로 간주 (엄격한 검증)
            return False
        
        kernel_major = int(kernel_version.split('.')[0]) if kernel_version else 6
        kernel_minor = int(kernel_version.split('.')[1]) if len(kernel_version.split('.')) > 1 else 0
        
        for vr in version_ranges:
            criteria = vr.get("criteria", "").lower()
            
            # linux_kernel CPE인지 확인
            if "linux_kernel" not in criteria and "linux:linux_kernel" not in criteria:
                continue

            start_incl = vr.get("versionStartIncluding")
            start_excl = vr.get("versionStartExcluding")
            end_incl = vr.get("versionEndIncluding")
            end_excl = vr.get("versionEndExcluding")

            # 버전 범위가 하나도 없으면 스킵
            if not any([start_incl, start_excl, end_incl, end_excl]):
                continue
            
            # 버전 범위가 현재 커널 브랜치를 포함하는지 확인
            if not self._version_range_covers_branch(
                kernel_major, kernel_minor,
                start_incl or start_excl, end_incl or end_excl
            ):
                continue

            # 버전 범위 체크
            in_range = True
            
            if start_incl:
                if self._compare_versions(kernel_version, start_incl) < 0:
                    in_range = False
            if start_excl:
                if self._compare_versions(kernel_version, start_excl) <= 0:
                    in_range = False
            if end_excl:
                if self._compare_versions(kernel_version, end_excl) >= 0:
                    in_range = False
            if end_incl:
                if self._compare_versions(kernel_version, end_incl) > 0:
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
    
    def _compare_versions(self, v1: str, v2: str) -> int:
        """버전 비교 (-1: v1 < v2, 0: v1 == v2, 1: v1 > v2)"""
        def normalize(v):
            parts = []
            for segment in re.split(r'[.\-_]', v):
                match = re.match(r'^(\d+)', segment)
                if match:
                    parts.append(int(match.group(1)))
            return parts
        
        p1, p2 = normalize(v1), normalize(v2)
        
        for i in range(max(len(p1), len(p2))):
            n1 = p1[i] if i < len(p1) else 0
            n2 = p2[i] if i < len(p2) else 0
            if n1 < n2:
                return -1
            elif n1 > n2:
                return 1
        return 0
    
    def _get_target_name(self, cpe: str, os_info: Dict) -> str:
        """CPE로부터 타겟 이름 생성"""
        if 'linux_kernel' in cpe:
            return f"Linux Kernel {os_info.get('kernel_version', 'Unknown')}"
        
        distro_id = os_info.get('distro_id', '')
        distro_version = os_info.get('distro_version', '')
        
        if distro_id == 'alpine':
            return f"Alpine Linux {distro_version}"
        elif distro_id == 'ubuntu':
            return f"Ubuntu {distro_version}"
        elif distro_id == 'debian':
            return f"Debian {distro_version}"
        else:
            return f"{distro_id.title()} {distro_version}"
    
    def should_collect_os_cves(self, package_count: int, distro_id: str) -> bool:
        """
        OS 레벨 CVE를 수집할지 결정
        
        Args:
            package_count: 발견된 패키지 수
            distro_id: 배포판 ID
        
        Returns:
            True if should collect OS CVEs
        """
        # 경량 배포판은 항상 수집
        lightweight_distros = ['alpine', 'busybox', 'buildroot', 'tinycore']
        if distro_id.lower() in lightweight_distros:
            return True
        
        # 패키지가 100개 이하면 OS CVE도 수집
        if package_count < 100:
            return True
        
        # 일반 배포판이라도 항상 커널 CVE는 확인
        return True


async def collect_os_vulnerabilities(
    nvd_client,
    os_info: Dict,
    package_count: int = 0,
    cve_years: Optional[int] = None
) -> List[Dict]:
    """
    OS/Kernel 취약점 수집
    
    Args:
        nvd_client: NVD 클라이언트
        os_info: OS 정보
        package_count: 패키지 개수
        cve_years: CVE 검색 시작 년도 (None = 전체)
    
    Returns:
        OS/Kernel CVE 리스트
    """
    matcher = OSCVEMatcher(nvd_client)
    matcher.cve_years = cve_years  # 년도 필터 설정
    
    # OS CVE 수집 여부 판단
    if not matcher.should_collect_os_cves(package_count, os_info.get('distro_id', '')):
        logger.info("Skipping OS CVE collection (too many packages)")
        return []
    
    # OS/Kernel CVE 검색
    os_cves = await matcher.find_os_cves(os_info)
    
    logger.info(
        f"OS CVE Collection: {len(os_cves)} CVEs found for "
        f"{os_info.get('distro_id')} {os_info.get('distro_version')}"
    )
    
    return os_cves
