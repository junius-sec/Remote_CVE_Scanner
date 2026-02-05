"""
SBOM Generator - CycloneDX 형식

Alpine 같은 경량 리눅스를 위한 SBOM(Software Bill of Materials) 생성기
패키지가 적은 시스템에서는 SBOM + OS 정보로 CVE를 찾는 것이 효과적
"""

import json
from typing import List, Dict
from datetime import datetime
import hashlib


class SBOMGenerator:
    """CycloneDX 1.4 형식 SBOM 생성"""
    
    def __init__(self):
        self.sbom_version = "1.4"
        self.spec_version = "1.4"
    
    def generate(self, host_info: Dict, packages: List[Dict], metadata: Dict = None, findings: List[Dict] = None) -> Dict:
        """
        SBOM 생성 (CVE 취약점 정보 포함)
        
        Args:
            host_info: 호스트 정보 (hostname, os, kernel 등)
            packages: 패키지 리스트
            metadata: 추가 메타데이터
            findings: CVE 취약점 정보 리스트 (패키지별 CVE 매핑)
        
        Returns:
            CycloneDX SBOM with vulnerabilities (dict)
        """
        components = []
        vulnerabilities = []  # CycloneDX 취약점 리스트
        
        # 패키지별 CVE 매핑 생성
        pkg_cve_map = self._build_package_cve_map(findings) if findings else {}
        
        # OS 컴포넌트 추가 (가장 중요!)
        if host_info.get('distro_id'):
            os_bom_ref = f"os-{host_info.get('distro_id')}"
            os_component = {
                "bom-ref": os_bom_ref,
                "type": "operating-system",
                "name": host_info.get('distro_id'),
                "version": host_info.get('distro_version', 'unknown'),
                "purl": self._generate_os_purl(host_info),
                "properties": [
                    {"name": "cpe", "value": self._generate_os_cpe(host_info)},
                    {"name": "architecture", "value": host_info.get('arch', 'unknown')},
                    {"name": "kernel", "value": host_info.get('kernel_version', 'unknown')},
                    {"name": "package_manager", "value": host_info.get('pkg_manager', 'unknown')}
                ]
            }
            
            # OS 레벨 CVE 추가
            os_cves = pkg_cve_map.get('__OS__', [])
            if os_cves:
                for cve_info in os_cves:
                    vulnerabilities.append(self._create_vulnerability(cve_info, os_bom_ref))
            
            components.append(os_component)
        
        # 커널 컴포넌트 추가
        if host_info.get('kernel_version'):
            kernel_bom_ref = f"kernel-{host_info['kernel_version']}"
            
            # 커널 CVE 조회 및 통계 계산
            kernel_cves = pkg_cve_map.get('__KERNEL__', [])
            kernel_cve_count = len(kernel_cves)
            critical_count = sum(1 for c in kernel_cves if c.get('cvss_score', 0) >= 9.0)
            high_count = sum(1 for c in kernel_cves if 7.0 <= c.get('cvss_score', 0) < 9.0)
            
            kernel_component = {
                "bom-ref": kernel_bom_ref,
                "type": "platform",
                "name": "linux-kernel",
                "version": host_info['kernel_version'],
                "purl": f"pkg:generic/linux-kernel@{host_info['kernel_version']}",
                "properties": [
                    {"name": "cpe", "value": self._generate_kernel_cpe(host_info)}
                ]
            }
            
            # 커널 CVE 통계 추가
            if kernel_cve_count > 0:
                kernel_component['properties'].extend([
                    {"name": "vulnerabilities_count", "value": str(kernel_cve_count)},
                    {"name": "critical_cves", "value": str(critical_count)},
                    {"name": "high_cves", "value": str(high_count)}
                ])
            
            # 커널 취약점 추가
            if kernel_cves:
                for cve_info in kernel_cves:
                    vulnerabilities.append(self._create_vulnerability(cve_info, kernel_bom_ref))
            
            components.append(kernel_component)
        
        # 패키지 컴포넌트 추가
        for pkg in packages:
            pkg_name = pkg['name']
            bom_ref = f"pkg-{pkg_name}-{pkg['version']}"
            
            component = {
                "bom-ref": bom_ref,
                "type": "library",
                "name": pkg_name,
                "version": pkg['version'],
                "purl": self._generate_purl(pkg, host_info),
            }
            
            # 기본 메타데이터 속성 추가
            properties = []
            
            # 패키지 관리자
            if pkg.get('package_manager'):
                properties.append({"name": "package_manager", "value": pkg['package_manager']})
            
            # Architecture
            if pkg.get('architecture'):
                properties.append({"name": "architecture", "value": pkg['architecture']})
            
            # Supplier (패키지 관리자 기반 추정)
            pkg_mgr = pkg.get('package_manager', '')
            if pkg_mgr == 'dpkg':
                properties.append({"name": "supplier", "value": "Debian/Ubuntu"})
            elif pkg_mgr == 'rpm':
                properties.append({"name": "supplier", "value": "Red Hat/CentOS"})
            elif pkg_mgr == 'apk':
                properties.append({"name": "supplier", "value": "Alpine Linux"})
            elif pkg_mgr == 'opkg':
                properties.append({"name": "supplier", "value": "OpenWrt"})
            
            # Checksum (있다면)
            if pkg.get('checksum'):
                component['hashes'] = [{"alg": "SHA-256", "content": pkg['checksum']}]
            
            if properties:
                component['properties'] = properties
            
            # 사용 정보 (있다면) - 내부용 메타데이터
            if pkg.get('is_running'):
                component.setdefault('properties', []).append(
                    {"name": "running", "value": "true"}
                )
            
            # 패키지 CVE 추가
            pkg_cves = pkg_cve_map.get(pkg_name, [])
            if pkg_cves:
                # CVE 통계
                critical_count = sum(1 for c in pkg_cves if c.get('cvss_score', 0) >= 9.0)
                high_count = sum(1 for c in pkg_cves if 7.0 <= c.get('cvss_score', 0) < 9.0)
                
                component.setdefault('properties', []).extend([
                    {"name": "vulnerabilities_count", "value": str(len(pkg_cves))},
                    {"name": "critical_cves", "value": str(critical_count)},
                    {"name": "high_cves", "value": str(high_count)}
                ])
                
                # 취약점 추가
                for cve_info in pkg_cves:
                    vulnerabilities.append(self._create_vulnerability(cve_info, bom_ref))
            
            components.append(component)
        
        # 취약점 통계 계산
        vuln_stats = self._calculate_vuln_stats(vulnerabilities)
        
        # SBOM 문서 생성
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": self.spec_version,
            "serialNumber": f"urn:uuid:{self._generate_uuid(host_info)}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "component": {
                    "type": "device",
                    "name": host_info.get('hostname', 'unknown-host'),
                    "version": host_info.get('distro_version', 'unknown')
                },
                "tools": [
                    {
                        "vendor": "VulnScan",
                        "name": "Remote CVE Scanner",
                        "version": "2.0.0"
                    }
                ],
                "properties": [
                    {"name": "total_vulnerabilities", "value": str(len(vulnerabilities))},
                    {"name": "critical_count", "value": str(vuln_stats['critical'])},
                    {"name": "high_count", "value": str(vuln_stats['high'])},
                    {"name": "medium_count", "value": str(vuln_stats['medium'])},
                    {"name": "low_count", "value": str(vuln_stats['low'])},
                    {"name": "kev_count", "value": str(vuln_stats['kev'])},
                    {"name": "patchable_count", "value": str(vuln_stats.get('patchable', 0))},
                    {"name": "running_vulnerable_count", "value": str(vuln_stats.get('running_vulnerable', 0))},
                    {"name": "total_components", "value": str(len(components))},
                    {"name": "scan_type", "value": "agentless_remote"}
                ]
            },
            "components": components,
            "vulnerabilities": vulnerabilities  # CycloneDX 1.4 표준
        }
        
        if metadata:
            sbom['metadata'].update(metadata)
        
        return sbom
    
    def _build_package_cve_map(self, findings: List[Dict]) -> Dict[str, List[Dict]]:
        """패키지별 CVE 매핑 생성"""
        pkg_cve_map = {}
        
        for finding in findings:
            pkg_name = finding.get('package_name', 'unknown')
            cve_info = {
                'cve_id': finding.get('cve_id'),
                'cvss_score': finding.get('cvss_score', 0.0),
                'severity': finding.get('severity', 'UNKNOWN'),
                'epss_score': finding.get('epss_score'),
                'in_kev': finding.get('in_kev', False),
                'description': finding.get('description', ''),
                'published': finding.get('published_date'),
                'references': finding.get('references', [])
            }
            
            if pkg_name not in pkg_cve_map:
                pkg_cve_map[pkg_name] = []
            pkg_cve_map[pkg_name].append(cve_info)
        
        return pkg_cve_map
    
    def _create_vulnerability(self, cve_info: Dict, bom_ref: str) -> Dict:
        """CycloneDX 취약점 객체 생성"""
        severity_map = {
            'CRITICAL': 'critical',
            'HIGH': 'high',
            'MEDIUM': 'medium',
            'LOW': 'low',
            'UNKNOWN': 'unknown'
        }
        
        vuln = {
            "bom-ref": f"vuln-{cve_info['cve_id']}-{bom_ref}",
            "id": cve_info['cve_id'],
            "source": {
                "name": "NVD",
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_info['cve_id']}"
            },
            "ratings": [
                {
                    "source": {"name": "NVD"},
                    "score": cve_info.get('cvss_score', 0.0),
                    "severity": severity_map.get(cve_info.get('severity', 'UNKNOWN'), 'unknown'),
                    "method": "CVSSv3"
                }
            ],
            "description": cve_info.get('description', ''),
            "published": cve_info.get('published', ''),
            "affects": [
                {
                    "ref": bom_ref
                }
            ],
            "properties": []
        }
        
        # EPSS 추가
        if cve_info.get('epss_score') is not None:
            vuln['properties'].append({
                "name": "epss_score",
                "value": f"{cve_info['epss_score']:.4f}"
            })
        
        # KEV 플래그
        if cve_info.get('in_kev'):
            vuln['properties'].append({
                "name": "in_kev",
                "value": "true"
            })
        
        # 패치 가능 여부
        if cve_info.get('has_patch_available'):
            vuln['properties'].append({
                "name": "has_patch",
                "value": "true"
            })
            if cve_info.get('patch_version'):
                vuln['properties'].append({
                    "name": "patch_version",
                    "value": cve_info['patch_version']
                })
        
        # 실행 중 패키지 여부 (매우 위험!)
        if cve_info.get('pkg_is_running'):
            vuln['properties'].append({
                "name": "is_running",
                "value": "true"
            })
        
        # 참조 링크
        if cve_info.get('references'):
            vuln['references'] = [{"url": ref} for ref in cve_info['references'][:5]]
        
        return vuln
    
    def _calculate_vuln_stats(self, vulnerabilities: List[Dict]) -> Dict[str, int]:
        """취약점 통계 계산"""
        stats = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'kev': 0,
            'patchable': 0,
            'running_vulnerable': 0
        }
        
        for vuln in vulnerabilities:
            # Severity 카운트
            if vuln.get('ratings'):
                severity = vuln['ratings'][0].get('severity', 'unknown')
                if severity in stats:
                    stats[severity] += 1
            
            # KEV, 패치 가능, 실행 중 카운트
            if vuln.get('properties'):
                for prop in vuln['properties']:
                    if prop.get('name') == 'in_kev' and prop.get('value') == 'true':
                        stats['kev'] += 1
                    elif prop.get('name') == 'has_patch' and prop.get('value') == 'true':
                        stats['patchable'] += 1
                    elif prop.get('name') == 'is_running' and prop.get('value') == 'true':
                        stats['running_vulnerable'] += 1
        
        return stats
    
    def _generate_purl(self, pkg: Dict, host_info: Dict) -> str:
        """Package URL (purl) 생성"""
        pkg_manager = pkg.get('package_manager', 'generic')
        name = pkg['name']
        version = pkg['version']
        
        # Alpine apk
        if pkg_manager == 'apk':
            # pkg:apk/alpine/musl@1.2.5?arch=x86_64&distro=alpine-3.23.2
            distro = host_info.get('distro_id', 'alpine')
            distro_ver = host_info.get('distro_version', '')
            arch = host_info.get('arch', 'x86_64')
            return f"pkg:apk/{distro}/{name}@{version}?arch={arch}&distro={distro}-{distro_ver}"
        
        # Debian/Ubuntu dpkg
        elif pkg_manager in ['dpkg', 'apt']:
            distro = host_info.get('distro_id', 'debian')
            return f"pkg:deb/{distro}/{name}@{version}"
        
        # RedHat rpm
        elif pkg_manager == 'rpm':
            return f"pkg:rpm/{name}@{version}"
        
        # Generic
        else:
            return f"pkg:generic/{name}@{version}"
    
    def _generate_os_purl(self, host_info: Dict) -> str:
        """OS purl 생성"""
        distro = host_info.get('distro_id', 'linux')
        version = host_info.get('distro_version', 'unknown')
        
        if distro == 'alpine':
            return f"pkg:apk/alpine/alpine-base@{version}"
        elif distro == 'ubuntu':
            return f"pkg:deb/ubuntu/ubuntu@{version}"
        else:
            return f"pkg:generic/{distro}@{version}"
    
    def _generate_os_cpe(self, host_info: Dict) -> str:
        """OS CPE 생성 (CVE 매칭용)"""
        distro = host_info.get('distro_id', '').lower()
        version = host_info.get('distro_version', '')
        
        if distro == 'alpine':
            return f"cpe:2.3:o:alpinelinux:alpine_linux:{version}"
        elif distro == 'ubuntu':
            return f"cpe:2.3:o:canonical:ubuntu_linux:{version}"
        elif distro == 'debian':
            return f"cpe:2.3:o:debian:debian_linux:{version}"
        else:
            return f"cpe:2.3:o:{distro}:{distro}:{version}"
    
    def _generate_kernel_cpe(self, host_info: Dict) -> str:
        """Kernel CPE 생성"""
        kernel_ver = host_info.get('kernel_version', '').split('-')[0]
        return f"cpe:2.3:o:linux:linux_kernel:{kernel_ver}"
    
    def _generate_uuid(self, host_info: Dict) -> str:
        """UUID 생성"""
        data = f"{host_info.get('hostname')}-{datetime.utcnow().isoformat()}"
        hash_val = hashlib.sha256(data.encode()).hexdigest()
        # UUID v4 형식으로 변환
        return f"{hash_val[:8]}-{hash_val[8:12]}-{hash_val[12:16]}-{hash_val[16:20]}-{hash_val[20:32]}"
    
    def to_json(self, sbom: Dict, indent: int = 2) -> str:
        """SBOM을 JSON 문자열로 변환"""
        return json.dumps(sbom, indent=indent, ensure_ascii=False)
    
    def save_to_file(self, sbom: Dict, filepath: str):
        """SBOM을 파일로 저장"""
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(self.to_json(sbom))


# SBOM을 이용한 CVE 매칭 강화
def extract_cpes_from_sbom(sbom: Dict) -> List[str]:
    """
    SBOM에서 모든 CPE 추출
    
    이걸로 NVD API에서 CVE를 검색하면
    OS/커널 레벨 취약점까지 모두 찾을 수 있음!
    """
    cpes = []
    
    for component in sbom.get('components', []):
        # properties에서 CPE 찾기
        if 'properties' in component:
            for prop in component['properties']:
                if prop.get('name') == 'cpe':
                    cpes.append(prop['value'])
        
        # purl에서 CPE 생성 가능
        if 'purl' in component:
            # purl을 CPE로 변환하는 로직 추가 가능
            pass
    
    return cpes


async def generate_sbom_for_host(session, host_id: int) -> Dict:
    """
    호스트의 SBOM 생성 (CVE 취약점 정보 포함)
    
    이 함수를 스캔 후 호출하면 SBOM + CVE 매핑 정보 생성됨
    """
    from sqlalchemy import select, and_, desc
    from vulnscan.models.schemas import Host, Package, Finding, ScanHistory, CVE, AssetSnapshot
    import json as json_lib
    
    # 호스트 정보 조회
    result = await session.execute(select(Host).where(Host.id == host_id))
    host = result.scalar_one_or_none()
    
    if not host:
        raise ValueError(f"Host {host_id} not found")
    
    # 최신 AssetSnapshot 조회 (전체 패키지 목록 포함)
    snapshot_query = select(AssetSnapshot).where(
        AssetSnapshot.host_id == host_id
    ).order_by(desc(AssetSnapshot.created_at)).limit(1)
    
    snapshot_result = await session.execute(snapshot_query)
    snapshot = snapshot_result.scalar_one_or_none()
    
    # 전체 패키지 목록 (AssetSnapshot에서)
    all_packages = []
    if snapshot and snapshot.packages_json:
        try:
            all_packages = json_lib.loads(snapshot.packages_json)
        except:
            pass
    
    # 최신 스캔 ID 조회
    latest_scan_query = select(ScanHistory.id).where(
        ScanHistory.host_id == host_id
    ).order_by(desc(ScanHistory.scan_started)).limit(1)
    
    latest_scan_result = await session.execute(latest_scan_query)
    latest_scan_id = latest_scan_result.scalar_one_or_none()
    
    # 최신 스캔의 Finding 정보 조회 (CVE 매핑용)
    findings_list = []
    if latest_scan_id:
        # Finding, CVE, Package 조인해서 조회
        findings_query = select(Finding, CVE, Package).join(
            CVE, Finding.cve_id == CVE.id
        ).join(
            Package, Finding.package_id == Package.id
        ).where(
            Finding.scan_id == latest_scan_id
        )
        
        findings_result = await session.execute(findings_query)
        findings_rows = findings_result.all()
        
        for finding, cve, package in findings_rows:
            findings_list.append({
                'package_name': package.name,
                'package_version': package.version,
                'cve_id': cve.cve_id,
                'cvss_score': cve.cvss_v3_score or 0.0,
                'severity': cve.cvss_v3_severity or 'UNKNOWN',
                'epss_score': cve.epss_score,
                'in_kev': cve.is_kev,
                'description': cve.description,
                'published_date': cve.published_date.isoformat() if cve.published_date else None,
                'references': cve.references or [],
                'has_patch_available': finding.has_patch_available,
                'patch_version': finding.patch_version,
                'pkg_is_running': finding.pkg_is_running
            })
    
    # 호스트 정보 dict 변환 (AssetSnapshot 우선)
    host_info = {
        'hostname': host.hostname,
        'distro_id': snapshot.distro_id if snapshot else host.distro_id,
        'distro_version': snapshot.distro_version if snapshot else host.os_version,
        'kernel_version': snapshot.kernel_version if snapshot else (host.kernel_version if hasattr(host, 'kernel_version') else None),
        'arch': snapshot.arch if snapshot else host.arch,
        'pkg_manager': snapshot.pkg_manager if snapshot else host.pkg_manager
    }
    
    # 패키지 정보 dict 변환 (AssetSnapshot에서 전체 패키지 사용)
    # linux-kernel 제외 - 이미 커널 컴포넌트로 추가됨
    pkg_list = [
        {
            'name': pkg.get('name'),
            'version': pkg.get('version'),
            'package_manager': pkg.get('package_manager') or host_info.get('pkg_manager'),
            'architecture': pkg.get('architecture') or host_info.get('arch')
        }
        for pkg in all_packages
        if pkg.get('name') and pkg.get('name') != 'linux-kernel' and not pkg.get('name', '').startswith('__')
    ]
    
    # SBOM 생성 (CVE 정보 포함)
    generator = SBOMGenerator()
    sbom = generator.generate(host_info, pkg_list, findings=findings_list)
    
    return sbom
