"""
Discovery Collector - OS/환경 식별 모듈

타깃 시스템의 OS, 아키텍처, 커널, 패키지 매니저 등을 식별합니다.
항상 실행되며, 저부하/실패내성 설계입니다.
"""

import re
import json
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime
import logging

from .ssh_exec import SSHExecutor, CommandResult

logger = logging.getLogger(__name__)


@dataclass
class DiscoveryResult:
    """Discovery 결과"""
    # 기본 OS 정보
    os_family: str = "linux"
    distro_id: str = "unknown"  # alpine, debian, ubuntu, poky, openwrt, unknown
    distro_version: str = ""
    distro_codename: str = ""
    pretty_name: str = ""
    
    # 시스템 정보
    arch: str = ""  # x86_64, aarch64, armv7l, mips, etc.
    kernel: str = ""  # uname -r 결과
    
    # 패키지 매니저
    pkg_manager: str = "none"  # apk, dpkg, rpm, opkg, none
    pkg_manager_path: str = ""  # 패키지 매니저 경로
    
    # 환경 특성
    is_busybox: bool = False
    busybox_version: str = ""
    has_systemd: bool = False
    is_container: bool = False
    is_wsl: bool = False
    
    # 사용 가능한 명령/기능
    capabilities: List[str] = field(default_factory=list)
    
    # 신뢰도
    confidence: str = "high"  # high, medium, low
    confidence_reason: str = ""
    
    # 원본 데이터
    raw_os_release: str = ""
    raw_uname: str = ""
    
    # 수집 메타데이터
    collected_at: str = ""
    collection_duration_ms: float = 0.0
    ssh_connected: bool = False
    errors: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return asdict(self)
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)


class DiscoveryCollector:
    """
    Discovery 수집기
    
    타깃 시스템 환경을 식별합니다:
    1. SSH 연결 확인
    2. OS 식별 (/etc/os-release 우선, fallback: uname -a, /proc/version)
    3. 아키텍처 (uname -m)
    4. 커널 버전 (uname -r)
    5. 패키지 매니저 탐지 (apk, dpkg, rpm, opkg)
    6. BusyBox 여부
    7. systemd 여부
    """
    
    # 알려진 배포판 매핑
    DISTRO_MAPPING = {
        "alpine": "alpine",
        "debian": "debian",
        "ubuntu": "ubuntu",
        "raspbian": "debian",
        "centos": "centos",
        "rhel": "rhel",
        "fedora": "fedora",
        "rocky": "rocky",
        "almalinux": "almalinux",
        "opensuse": "opensuse",
        "sles": "sles",
        "arch": "arch",
        "manjaro": "arch",
        "gentoo": "gentoo",
        "openwrt": "openwrt",
        "lede": "openwrt",
        "poky": "yocto",
        "yocto": "yocto",
        "buildroot": "buildroot",
        "photon": "photon",
        "amzn": "amazon",
        "ol": "oracle",
    }
    
    # 패키지 매니저 우선순위 (왼쪽이 우선)
    PKG_MANAGERS = [
        ("dpkg", "/usr/bin/dpkg"),
        ("dpkg", "/bin/dpkg"),
        ("apk", "/sbin/apk"),
        ("apk", "/usr/sbin/apk"),
        ("rpm", "/usr/bin/rpm"),
        ("rpm", "/bin/rpm"),
        ("opkg", "/usr/bin/opkg"),
        ("opkg", "/bin/opkg"),
    ]
    
    # 기본 필수 명령
    ESSENTIAL_COMMANDS = ["cat", "ls", "echo", "uname", "test"]
    
    # 유용한 명령 (있으면 좋음)
    USEFUL_COMMANDS = [
        "which", "command", "readlink", "awk", "sed", "grep",
        "lsmod", "ps", "netstat", "ss", "systemctl", "service",
        "openssl", "busybox", "dpkg", "apk", "rpm", "opkg"
    ]
    
    def __init__(self, ssh_executor: SSHExecutor):
        self.ssh = ssh_executor
        self._result = DiscoveryResult()
        
    async def collect(self) -> DiscoveryResult:
        """
        전체 Discovery 수행
        
        Returns:
            DiscoveryResult: 수집 결과
        """
        start_time = datetime.now()
        self._result = DiscoveryResult()
        self._result.collected_at = start_time.isoformat()
        
        try:
            # 1. SSH 연결 테스트
            connected, msg = await self.ssh.test_connection()
            self._result.ssh_connected = connected
            
            if not connected:
                self._result.confidence = "low"
                self._result.confidence_reason = f"SSH connection failed: {msg}"
                self._result.errors.append(msg)
                return self._result
            
            # 2. 기본 정보 수집 (병렬 실행 가능한 것들)
            await self._collect_basic_info()
            
            # 3. OS 식별
            await self._identify_os()
            
            # 4. 패키지 매니저 탐지
            await self._detect_package_manager()
            
            # 5. 환경 특성 탐지
            await self._detect_environment()
            
            # 6. 사용 가능한 명령 탐지
            await self._detect_capabilities()
            
            # 7. 신뢰도 계산
            self._calculate_confidence()
            
        except Exception as e:
            self._result.errors.append(f"Discovery error: {str(e)}")
            self._result.confidence = "low"
            self._result.confidence_reason = f"Collection error: {str(e)}"
            logger.exception("Discovery collection failed")
        
        # 수집 시간 기록
        self._result.collection_duration_ms = (datetime.now() - start_time).total_seconds() * 1000
        
        return self._result
    
    async def _collect_basic_info(self):
        """기본 시스템 정보 수집 (uname 계열)"""
        # uname -a (전체 정보)
        uname_a = await self.ssh.execute("uname -a")
        if uname_a.success:
            self._result.raw_uname = uname_a.stdout
        
        # uname -m (아키텍처)
        uname_m = await self.ssh.execute("uname -m")
        if uname_m.success:
            self._result.arch = uname_m.stdout.strip()
        
        # uname -r (커널 버전)
        uname_r = await self.ssh.execute("uname -r")
        if uname_r.success:
            self._result.kernel = uname_r.stdout.strip()
    
    async def _identify_os(self):
        """OS 식별 (여러 소스 순차 시도)"""
        
        # 1순위: /etc/os-release
        os_release = await self.ssh.read_file("/etc/os-release")
        if os_release.success and os_release.stdout:
            self._result.raw_os_release = os_release.stdout
            self._parse_os_release(os_release.stdout)
            return
        
        # 2순위: /etc/lsb-release (Ubuntu 구버전)
        lsb_release = await self.ssh.read_file("/etc/lsb-release")
        if lsb_release.success and lsb_release.stdout:
            self._parse_lsb_release(lsb_release.stdout)
            return
        
        # 3순위: 배포판별 release 파일
        distro_files = [
            ("/etc/alpine-release", "alpine"),
            ("/etc/debian_version", "debian"),
            ("/etc/redhat-release", "rhel"),
            ("/etc/centos-release", "centos"),
            ("/etc/fedora-release", "fedora"),
            ("/etc/openwrt_release", "openwrt"),
            ("/etc/openwrt_version", "openwrt"),
        ]
        
        for filepath, distro in distro_files:
            result = await self.ssh.read_file(filepath)
            if result.success and result.stdout:
                self._result.distro_id = distro
                self._result.distro_version = result.stdout.strip().split('\n')[0]
                return
        
        # 4순위: /proc/version
        proc_version = await self.ssh.read_file("/proc/version")
        if proc_version.success:
            self._parse_proc_version(proc_version.stdout)
            return
        
        # 5순위: uname -a 기반 추정
        if self._result.raw_uname:
            self._parse_uname_fallback(self._result.raw_uname)
    
    def _parse_os_release(self, content: str):
        """os-release 파일 파싱"""
        data = {}
        for line in content.strip().split('\n'):
            if '=' in line:
                key, _, value = line.partition('=')
                data[key.strip()] = value.strip().strip('"\'')
        
        # ID (배포판 식별자)
        distro_id = data.get("ID", "").lower()
        self._result.distro_id = self.DISTRO_MAPPING.get(distro_id, distro_id) or "unknown"
        
        # 버전 정보
        self._result.distro_version = data.get("VERSION_ID", "")
        self._result.distro_codename = data.get("VERSION_CODENAME", "")
        self._result.pretty_name = data.get("PRETTY_NAME", "")
        
        # ID_LIKE 로 패밀리 추정 (예: ubuntu -> debian)
        id_like = data.get("ID_LIKE", "").lower()
        if "debian" in id_like and self._result.distro_id not in ["debian", "ubuntu"]:
            self._result.distro_id = f"{self._result.distro_id}"  # 유지하되 참고용
    
    def _parse_lsb_release(self, content: str):
        """lsb-release 파일 파싱"""
        data = {}
        for line in content.strip().split('\n'):
            if '=' in line:
                key, _, value = line.partition('=')
                data[key.strip()] = value.strip().strip('"\'')
        
        distro_id = data.get("DISTRIB_ID", "").lower()
        self._result.distro_id = self.DISTRO_MAPPING.get(distro_id, distro_id) or "unknown"
        self._result.distro_version = data.get("DISTRIB_RELEASE", "")
        self._result.distro_codename = data.get("DISTRIB_CODENAME", "")
        self._result.pretty_name = data.get("DISTRIB_DESCRIPTION", "")
    
    def _parse_proc_version(self, content: str):
        """proc/version 기반 추정"""
        content_lower = content.lower()
        
        # 배포판 키워드 찾기
        for keyword, distro in self.DISTRO_MAPPING.items():
            if keyword in content_lower:
                self._result.distro_id = distro
                break
        
        # 버전 추출 시도
        version_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', content)
        if version_match and not self._result.distro_version:
            self._result.distro_version = version_match.group(1)
    
    def _parse_uname_fallback(self, uname_output: str):
        """uname -a 기반 fallback 추정"""
        uname_lower = uname_output.lower()
        
        # 알려진 패턴 매칭
        patterns = [
            (r'alpine', 'alpine'),
            (r'ubuntu', 'ubuntu'),
            (r'debian', 'debian'),
            (r'centos', 'centos'),
            (r'red\s*hat', 'rhel'),
            (r'fedora', 'fedora'),
            (r'openwrt', 'openwrt'),
            (r'yocto|poky', 'yocto'),
            (r'buildroot', 'buildroot'),
        ]
        
        for pattern, distro in patterns:
            if re.search(pattern, uname_lower):
                self._result.distro_id = distro
                break
    
    async def _detect_package_manager(self):
        """패키지 매니저 탐지"""
        for pkg_mgr, path in self.PKG_MANAGERS:
            exists = await self.ssh.file_exists(path)
            if exists:
                self._result.pkg_manager = pkg_mgr
                self._result.pkg_manager_path = path
                return
        
        # which/command -v로 재시도
        for pkg_mgr in ["dpkg", "apk", "rpm", "opkg"]:
            exists = await self.ssh.command_exists(pkg_mgr)
            if exists:
                self._result.pkg_manager = pkg_mgr
                # 경로 확인
                which_result = await self.ssh.execute(f"which {pkg_mgr} 2>/dev/null || command -v {pkg_mgr} 2>/dev/null")
                if which_result.success:
                    self._result.pkg_manager_path = which_result.stdout.strip()
                return
        
        self._result.pkg_manager = "none"
    
    async def _detect_environment(self):
        """환경 특성 탐지 (BusyBox, systemd, 컨테이너 등)"""
        
        # BusyBox 확인
        busybox_result = await self.ssh.execute("busybox --version 2>/dev/null || busybox 2>&1 | head -1")
        if busybox_result.success and "busybox" in busybox_result.stdout.lower():
            self._result.is_busybox = True
            # 버전 추출
            version_match = re.search(r'v?(\d+\.\d+(?:\.\d+)?)', busybox_result.stdout)
            if version_match:
                self._result.busybox_version = version_match.group(1)
        
        # systemd 확인
        systemctl_exists = await self.ssh.command_exists("systemctl")
        if systemctl_exists:
            # 실제로 동작하는지 확인
            systemctl_test = await self.ssh.execute("systemctl --version 2>/dev/null | head -1")
            self._result.has_systemd = systemctl_test.success and "systemd" in systemctl_test.stdout.lower()
        
        # 컨테이너 환경 확인
        dockerenv = await self.ssh.file_exists("/.dockerenv")
        if dockerenv:
            self._result.is_container = True
        else:
            cgroup = await self.ssh.read_file("/proc/1/cgroup")
            if cgroup.success and ("docker" in cgroup.stdout or "lxc" in cgroup.stdout or "kubepods" in cgroup.stdout):
                self._result.is_container = True
        
        # WSL 확인
        if self._result.raw_uname and "microsoft" in self._result.raw_uname.lower():
            self._result.is_wsl = True
    
    async def _detect_capabilities(self):
        """사용 가능한 명령 탐지"""
        capabilities = []
        
        # 필수 명령 확인
        for cmd in self.ESSENTIAL_COMMANDS:
            exists = await self.ssh.command_exists(cmd)
            if exists:
                capabilities.append(cmd)
        
        # 유용한 명령 확인
        for cmd in self.USEFUL_COMMANDS:
            exists = await self.ssh.command_exists(cmd)
            if exists:
                capabilities.append(cmd)
        
        self._result.capabilities = capabilities
    
    def _calculate_confidence(self):
        """수집 결과 신뢰도 계산"""
        score = 100
        reasons = []
        
        # SSH 연결 실패
        if not self._result.ssh_connected:
            self._result.confidence = "low"
            self._result.confidence_reason = "SSH connection failed"
            return
        
        # OS 식별 실패
        if self._result.distro_id == "unknown":
            score -= 30
            reasons.append("Unknown distro")
        
        # 패키지 매니저 없음
        if self._result.pkg_manager == "none":
            score -= 20
            reasons.append("No package manager")
        
        # BusyBox 환경 (일반적으로 정보 제한적)
        if self._result.is_busybox:
            score -= 10
            reasons.append("BusyBox environment")
        
        # os-release 없음
        if not self._result.raw_os_release:
            score -= 15
            reasons.append("No os-release file")
        
        # 아키텍처/커널 정보 없음
        if not self._result.arch:
            score -= 10
            reasons.append("No arch info")
        if not self._result.kernel:
            score -= 10
            reasons.append("No kernel info")
        
        # 에러 발생
        if self._result.errors:
            score -= len(self._result.errors) * 5
            reasons.append(f"{len(self._result.errors)} errors")
        
        # 신뢰도 결정
        if score >= 80:
            self._result.confidence = "high"
        elif score >= 50:
            self._result.confidence = "medium"
        else:
            self._result.confidence = "low"
        
        self._result.confidence_reason = "; ".join(reasons) if reasons else "All checks passed"


async def run_discovery(ssh_executor: SSHExecutor) -> DiscoveryResult:
    """Discovery 실행 헬퍼 함수"""
    collector = DiscoveryCollector(ssh_executor)
    return await collector.collect()
