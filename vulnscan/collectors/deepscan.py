"""
DeepScan Collector - 패키지/바이너리 심층 수집 모듈

Discovery 결과에 따라 조건부로 실행되며:
- 패키지 매니저가 있으면: 패키지 목록 수집 (정확도 high)
- 없으면: 바이너리 버전 추정 수집 (정확도 medium/low)
"""

import re
import json
import hashlib
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field, asdict
from datetime import datetime
import logging

from .ssh_exec import SSHExecutor, CommandResult
from .discovery import DiscoveryResult

logger = logging.getLogger(__name__)


@dataclass
class PackageInfo:
    """패키지 정보"""
    name: str
    version: str
    architecture: str = ""
    package_manager: str = ""
    raw_version: str = ""  # 정규화 전 원본 버전
    confidence: str = "high"  # high, medium, low
    evidence: str = ""  # 수집 근거/명령
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class BinaryInfo:
    """바이너리 버전 정보"""
    name: str
    version: str
    path: str = ""
    raw_output: str = ""  # 버전 추출 원본 출력
    confidence: str = "medium"  # high, medium, low
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class DeepScanResult:
    """DeepScan 결과"""
    # 수집 모드
    collector_mode: str = "pkg"  # pkg, binary, kernel
    
    # 패키지 목록 (pkg_manager가 있을 때)
    packages: List[PackageInfo] = field(default_factory=list)
    packages_count: int = 0
    
    # 바이너리 버전 (pkg_manager가 없을 때)
    binaries: List[BinaryInfo] = field(default_factory=list)
    binaries_count: int = 0
    
    # 커널/모듈 정보
    kernel_modules: List[str] = field(default_factory=list)
    kernel_config: Dict[str, str] = field(default_factory=dict)
    
    # 데이터 해시 (캐시 키)
    packages_hash: str = ""
    binaries_hash: str = ""
    
    # 신뢰도
    data_confidence: str = "high"  # high, medium, low
    confidence_reason: str = ""
    
    # 수집 근거
    evidence: str = ""  # 어떤 명령으로 수집했는지
    
    # 메타데이터
    collected_at: str = ""
    collection_duration_ms: float = 0.0
    errors: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        result = asdict(self)
        result["packages"] = [p.to_dict() if hasattr(p, 'to_dict') else p for p in self.packages]
        result["binaries"] = [b.to_dict() if hasattr(b, 'to_dict') else b for b in self.binaries]
        return result
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)
    
    def compute_hashes(self):
        """데이터 해시 계산"""
        # 패키지 해시
        if self.packages:
            pkg_data = json.dumps(
                sorted([{"name": p.name, "version": p.version} for p in self.packages], 
                       key=lambda x: x["name"]),
                sort_keys=True
            )
            self.packages_hash = hashlib.sha256(pkg_data.encode()).hexdigest()
        
        # 바이너리 해시
        if self.binaries:
            bin_data = json.dumps(
                sorted([{"name": b.name, "version": b.version} for b in self.binaries],
                       key=lambda x: x["name"]),
                sort_keys=True
            )
            self.binaries_hash = hashlib.sha256(bin_data.encode()).hexdigest()


class DeepScanCollector:
    """
    DeepScan 수집기
    
    Discovery 결과에 따라 적절한 수집 방법을 선택합니다:
    
    1. pkg_manager 존재 시:
       - apk info -v (Alpine)
       - dpkg-query -W -f=... (Debian/Ubuntu)
       - rpm -qa --queryformat=... (RHEL/CentOS)
       - opkg list-installed (OpenWRT)
    
    2. pkg_manager 없을 시 (Yocto/BusyBox 등):
       - 핵심 바이너리 버전 수집 (openssl, dropbear, busybox 등)
       - 라이브러리 버전 수집 (glibc 등)
       - 커널 모듈 목록
    """
    
    # 버전 추출 대상 바이너리 및 명령
    BINARY_VERSION_COMMANDS = {
        "openssl": ("openssl version", r"OpenSSL\s+(\d+\.\d+\.\d+[a-z]?)"),
        "dropbear": ("dropbear -V 2>&1 | head -1", r"Dropbear\s+v?(\d+\.\d+(?:\.\d+)?)"),
        "busybox": ("busybox --version 2>/dev/null | head -1", r"BusyBox\s+v?(\d+\.\d+\.\d+)"),
        "ssh": ("ssh -V 2>&1", r"OpenSSH[_\s]+(\d+\.\d+(?:p\d+)?)"),
        "curl": ("curl --version 2>/dev/null | head -1", r"curl\s+(\d+\.\d+\.\d+)"),
        "wget": ("wget --version 2>/dev/null | head -1", r"Wget\s+(\d+\.\d+(?:\.\d+)?)"),
        "nginx": ("nginx -v 2>&1", r"nginx/(\d+\.\d+\.\d+)"),
        "apache": ("httpd -v 2>&1 || apache2 -v 2>&1", r"Apache/(\d+\.\d+\.\d+)"),
        "python": ("python3 --version 2>/dev/null || python --version 2>/dev/null", r"Python\s+(\d+\.\d+\.\d+)"),
        "node": ("node --version 2>/dev/null", r"v?(\d+\.\d+\.\d+)"),
        "dnsmasq": ("dnsmasq --version 2>/dev/null | head -1", r"version\s+(\d+\.\d+(?:\.\d+)?)"),
        "lighttpd": ("lighttpd -v 2>/dev/null | head -1", r"lighttpd/(\d+\.\d+\.\d+)"),
    }
    
    # glibc 버전 추출
    GLIBC_COMMANDS = [
        ("/lib/libc.so.6", r"GNU C Library.*?(\d+\.\d+)"),
        ("/lib64/libc.so.6", r"GNU C Library.*?(\d+\.\d+)"),
        ("/lib/x86_64-linux-gnu/libc.so.6", r"GNU C Library.*?(\d+\.\d+)"),
        ("/lib/aarch64-linux-gnu/libc.so.6", r"GNU C Library.*?(\d+\.\d+)"),
    ]
    
    def __init__(self, ssh_executor: SSHExecutor, discovery_result: DiscoveryResult):
        self.ssh = ssh_executor
        self.discovery = discovery_result
        self._result = DeepScanResult()
    
    async def collect(self, preset: str = "standard") -> DeepScanResult:
        """
        DeepScan 수행
        
        Args:
            preset: fast, standard, deep
            
        Returns:
            DeepScanResult: 수집 결과
        """
        start_time = datetime.now()
        self._result = DeepScanResult()
        self._result.collected_at = start_time.isoformat()
        
        if not self.discovery.ssh_connected:
            self._result.errors.append("SSH not connected (from discovery)")
            self._result.data_confidence = "low"
            return self._result
        
        try:
            pkg_mgr = self.discovery.pkg_manager
            
            if pkg_mgr and pkg_mgr != "none":
                # 패키지 매니저 기반 수집 (정확도 high)
                await self._collect_packages(pkg_mgr)
                self._result.collector_mode = "pkg"
                
                # deep 프리셋: 바이너리 정보도 추가 수집
                if preset == "deep":
                    await self._collect_binaries()
            else:
                # 바이너리 기반 수집 (정확도 medium/low)
                await self._collect_binaries()
                self._result.collector_mode = "binary"
            
            # 커널 정보 수집 (standard 이상)
            if preset in ["standard", "deep"]:
                await self._collect_kernel_info()
            
            # 해시 계산
            self._result.compute_hashes()
            
            # 신뢰도 계산
            self._calculate_confidence()
            
        except Exception as e:
            self._result.errors.append(f"DeepScan error: {str(e)}")
            self._result.data_confidence = "low"
            logger.exception("DeepScan collection failed")
        
        self._result.collection_duration_ms = (datetime.now() - start_time).total_seconds() * 1000
        
        return self._result
    
    async def _collect_packages(self, pkg_manager: str):
        """패키지 매니저별 패키지 목록 수집"""
        
        if pkg_manager == "apk":
            await self._collect_apk_packages()
        elif pkg_manager == "dpkg":
            await self._collect_dpkg_packages()
        elif pkg_manager == "rpm":
            await self._collect_rpm_packages()
        elif pkg_manager == "opkg":
            await self._collect_opkg_packages()
        else:
            self._result.errors.append(f"Unknown package manager: {pkg_manager}")
    
    async def _collect_apk_packages(self):
        """Alpine apk 패키지 수집"""
        result = await self.ssh.execute("apk info -v 2>/dev/null")
        
        if not result.success:
            self._result.errors.append(f"apk info failed: {result.error_message}")
            return
        
        self._result.evidence = "apk info -v"
        packages = []
        
        for line in result.stdout.strip().split('\n'):
            if not line:
                continue
            
            # 형식: package-name-version
            # 예: busybox-1.36.1-r2, openssl-3.1.4-r0
            match = re.match(r'^(.+)-(\d+\.\d+(?:\.\d+)?(?:-r\d+)?)$', line.strip())
            if match:
                name = match.group(1)
                raw_version = match.group(2)
                # 버전 정규화: 1.36.1-r2 → 1.36.1
                version = self._normalize_version(raw_version, "apk")
                
                packages.append(PackageInfo(
                    name=name,
                    version=version,
                    raw_version=raw_version,
                    architecture=self.discovery.arch,
                    package_manager="apk"
                ))
        
        self._result.packages = packages
        self._result.packages_count = len(packages)
    
    async def _collect_dpkg_packages(self):
        """Debian/Ubuntu dpkg 패키지 수집"""
        result = await self.ssh.execute(
            "dpkg-query -W -f='${Package}\\t${Version}\\t${Architecture}\\n' 2>/dev/null"
        )
        
        if not result.success:
            self._result.errors.append(f"dpkg-query failed: {result.error_message}")
            return
        
        self._result.evidence = "dpkg-query -W -f='${Package}\\t${Version}\\t${Architecture}\\n'"
        packages = []
        
        for line in result.stdout.strip().split('\n'):
            if not line:
                continue
            
            parts = line.split('\t')
            if len(parts) >= 2:
                name = parts[0]
                raw_version = parts[1]
                arch = parts[2] if len(parts) > 2 else self.discovery.arch
                
                # 버전 정규화: 1.1.1f-1ubuntu2.16 → 1.1.1f
                version = self._normalize_version(raw_version, "dpkg")
                
                packages.append(PackageInfo(
                    name=name,
                    version=version,
                    raw_version=raw_version,
                    architecture=arch,
                    package_manager="dpkg"
                ))
        
        self._result.packages = packages
        self._result.packages_count = len(packages)
    
    async def _collect_rpm_packages(self):
        """RPM 패키지 수집"""
        result = await self.ssh.execute(
            "rpm -qa --queryformat '%{NAME}\\t%{VERSION}-%{RELEASE}\\t%{ARCH}\\n' 2>/dev/null"
        )
        
        if not result.success:
            self._result.errors.append(f"rpm query failed: {result.error_message}")
            return
        
        self._result.evidence = "rpm -qa --queryformat '%{NAME}\\t%{VERSION}-%{RELEASE}\\t%{ARCH}\\n'"
        packages = []
        
        for line in result.stdout.strip().split('\n'):
            if not line:
                continue
            
            parts = line.split('\t')
            if len(parts) >= 2:
                name = parts[0]
                raw_version = parts[1]
                arch = parts[2] if len(parts) > 2 else self.discovery.arch
                
                # 버전 정규화: 1.0.2k-19.el7 → 1.0.2k
                version = self._normalize_version(raw_version, "rpm")
                
                packages.append(PackageInfo(
                    name=name,
                    version=version,
                    raw_version=raw_version,
                    architecture=arch,
                    package_manager="rpm"
                ))
        
        self._result.packages = packages
        self._result.packages_count = len(packages)
    
    async def _collect_opkg_packages(self):
        """OpenWRT opkg 패키지 수집"""
        result = await self.ssh.execute("opkg list-installed 2>/dev/null")
        
        if not result.success:
            self._result.errors.append(f"opkg list-installed failed: {result.error_message}")
            return
        
        self._result.evidence = "opkg list-installed"
        packages = []
        
        for line in result.stdout.strip().split('\n'):
            if not line:
                continue
            
            # 형식: package - version
            parts = line.split(' - ')
            if len(parts) >= 2:
                name = parts[0].strip()
                raw_version = parts[1].strip()
                version = self._normalize_version(raw_version, "opkg")
                
                packages.append(PackageInfo(
                    name=name,
                    version=version,
                    raw_version=raw_version,
                    architecture=self.discovery.arch,
                    package_manager="opkg"
                ))
        
        self._result.packages = packages
        self._result.packages_count = len(packages)
    
    async def _collect_binaries(self):
        """
        바이너리 버전 수집 (패키지 매니저 없을 때 또는 Deep 모드)
        
        Deep 모드에서는 더 많은 바이너리를 수집하여
        패키지 매니저로 관리되지 않는 취약점도 찾음
        """
        binaries = []
        evidence_parts = []
        
        # 기본 바이너리 명령어
        for binary_name, (command, pattern) in self.BINARY_VERSION_COMMANDS.items():
            # 명령 존재 확인 후 실행
            result = await self.ssh.execute(command)
            
            if result.success and result.stdout:
                match = re.search(pattern, result.stdout, re.IGNORECASE)
                if match:
                    version = match.group(1)
                    binaries.append(BinaryInfo(
                        name=binary_name,
                        version=version,
                        raw_output=result.stdout[:200],  # 첫 200자만
                        confidence="medium"
                    ))
                    evidence_parts.append(f"{binary_name}: {command}")
        
        # Deep 모드 전용: 추가 바이너리 수집
        # 웹 서버, 데이터베이스, 네트워크 도구 등
        deep_binaries = {
            "nginx": ("nginx -v 2>&1", r"nginx/([\d\.]+)"),
            "apache": ("httpd -v 2>&1 || apache2 -v 2>&1", r"Apache/([\d\.]+)"),
            "php": ("php -v 2>&1", r"PHP ([\d\.]+)"),
            "python": ("python --version 2>&1 || python3 --version 2>&1", r"Python ([\d\.]+)"),
            "mysql": ("mysql --version 2>&1", r"mysql.*Ver ([\d\.]+)"),
            "postgresql": ("postgres --version 2>&1 || psql --version 2>&1", r"PostgreSQL.*?([\d\.]+)"),
            "redis": ("redis-server --version 2>&1", r"Redis.*v=([\d\.]+)"),
            "node": ("node --version 2>&1", r"v([\d\.]+)"),
            "docker": ("docker --version 2>&1", r"Docker version ([\d\.]+)"),
            "git": ("git --version 2>&1", r"git version ([\d\.]+)"),
            "openssh": ("ssh -V 2>&1", r"OpenSSH_([\d\.]+)"),
            "sudo": ("sudo -V 2>&1 | head -1", r"Sudo version ([\d\.]+)"),
            "busybox": ("busybox 2>&1 | head -1", r"BusyBox v([\d\.]+)"),
        }
        
        for binary_name, (command, pattern) in deep_binaries.items():
            result = await self.ssh.execute(command)
            
            if result.success and result.stdout:
                match = re.search(pattern, result.stdout, re.IGNORECASE)
                if match:
                    version = match.group(1)
                    binaries.append(BinaryInfo(
                        name=binary_name,
                        version=version,
                        raw_output=result.stdout[:200],
                        confidence="medium"
                    ))
                    evidence_parts.append(f"{binary_name}: {command}")
        
        # glibc 버전 수집
        glibc_version = await self._get_glibc_version()
        if glibc_version:
            binaries.append(BinaryInfo(
                name="glibc",
                version=glibc_version,
                confidence="medium"
            ))
        
        self._result.binaries = binaries
        self._result.binaries_count = len(binaries)
        
        if evidence_parts:
            self._result.evidence = "; ".join(evidence_parts[:5])  # 최대 5개
    
    async def _get_glibc_version(self) -> Optional[str]:
        """glibc 버전 추출"""
        for lib_path, pattern in self.GLIBC_COMMANDS:
            result = await self.ssh.execute(f"{lib_path} 2>&1 | head -1")
            if result.success and result.stdout:
                match = re.search(pattern, result.stdout)
                if match:
                    return match.group(1)
        return None
    
    async def _collect_kernel_info(self):
        """커널 모듈 및 설정 수집"""
        
        # 커널 모듈 목록
        lsmod_result = await self.ssh.execute("lsmod 2>/dev/null || cat /proc/modules 2>/dev/null")
        if lsmod_result.success and lsmod_result.stdout:
            modules = []
            for line in lsmod_result.stdout.strip().split('\n')[1:]:  # 헤더 스킵
                if line:
                    parts = line.split()
                    if parts:
                        modules.append(parts[0])
            self._result.kernel_modules = modules[:100]  # 최대 100개
    
    def _normalize_version(self, version: str, pkg_type: str) -> str:
        """
        버전 문자열 정규화
        
        배포판별 접미사를 제거하여 순수 버전만 추출:
        - dpkg: 1.1.1f-1ubuntu2.16 → 1.1.1f
        - rpm: 1.0.2k-19.el7 → 1.0.2k
        - apk: 1.36.1-r2 → 1.36.1
        - opkg: 유사한 처리
        """
        if not version:
            return ""
        
        original = version
        
        if pkg_type == "dpkg":
            # Debian/Ubuntu: epoch:upstream-debian 형식
            # epoch 제거
            if ':' in version:
                version = version.split(':', 1)[1]
            # debian revision 제거 (하이픈 뒤 첫 번째 숫자 이후)
            match = re.match(r'^([0-9]+\.[0-9]+(?:\.[0-9]+)?[a-z]?)', version)
            if match:
                return match.group(1)
            # 하이픈으로 분리 후 첫 부분
            if '-' in version:
                return version.split('-')[0]
        
        elif pkg_type == "rpm":
            # RPM: version-release 형식
            # release 부분 제거
            if '-' in version:
                version = version.split('-')[0]
            # .el7, .fc35 등 제거
            version = re.sub(r'\.(el|fc|rhel|centos)\d+.*$', '', version, flags=re.IGNORECASE)
        
        elif pkg_type == "apk":
            # Alpine: version-r0 형식
            # -r0, -r1 등 제거
            version = re.sub(r'-r\d+$', '', version)
        
        elif pkg_type == "opkg":
            # OpenWRT: 다양한 형식
            # 하이픈 뒤 숫자가 아닌 부분 제거
            match = re.match(r'^([0-9]+\.[0-9]+(?:\.[0-9]+)?)', version)
            if match:
                return match.group(1)
        
        return version if version else original
    
    def _calculate_confidence(self):
        """수집 결과 신뢰도 계산"""
        
        if self._result.collector_mode == "pkg" and self._result.packages_count > 0:
            # 패키지 매니저 기반 - 높은 신뢰도
            self._result.data_confidence = "high"
            self._result.confidence_reason = f"Package manager based ({self._result.packages_count} packages)"
        
        elif self._result.collector_mode == "binary":
            if self._result.binaries_count >= 5:
                # 바이너리 5개 이상 - 중간 신뢰도
                self._result.data_confidence = "medium"
                self._result.confidence_reason = f"Binary version extraction ({self._result.binaries_count} binaries)"
            elif self._result.binaries_count > 0:
                # 바이너리 5개 미만 - 낮은 신뢰도
                self._result.data_confidence = "low"
                self._result.confidence_reason = f"Limited binary info ({self._result.binaries_count} binaries)"
            else:
                # 바이너리 없음 - 매우 낮은 신뢰도
                self._result.data_confidence = "low"
                self._result.confidence_reason = "No version information collected"
        
        else:
            self._result.data_confidence = "low"
            self._result.confidence_reason = "No data collected"
        
        # 에러가 있으면 신뢰도 하락
        if self._result.errors:
            if self._result.data_confidence == "high":
                self._result.data_confidence = "medium"
            self._result.confidence_reason += f"; {len(self._result.errors)} errors"


async def run_deepscan(
    ssh_executor: SSHExecutor, 
    discovery_result: DiscoveryResult,
    preset: str = "standard"
) -> DeepScanResult:
    """DeepScan 실행 헬퍼 함수"""
    collector = DeepScanCollector(ssh_executor, discovery_result)
    return await collector.collect(preset)
