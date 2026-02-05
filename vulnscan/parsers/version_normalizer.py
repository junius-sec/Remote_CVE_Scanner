"""
Version Normalizer - 버전 정규화 유틸리티
"""

import re
from typing import Dict, Optional, Tuple


class VersionNormalizer:
    """
    버전 문자열 정규화 및 비교 유틸리티
    
    다양한 배포판의 버전 형식을 표준화합니다:
    - Debian/Ubuntu: 1.1.1f-1ubuntu2.16 → 1.1.1f
    - Alpine: 1.36.1-r2 → 1.36.1
    - RHEL/CentOS: 1.0.2k-19.el7 → 1.0.2k
    - OpenWRT: 다양한 형식
    """
    
    # 배포판별 버전 패턴
    PATTERNS = {
        "dpkg": {
            "epoch": r'^(\d+):',  # epoch 제거
            "debian": r'-[^-]+$',  # debian revision
            "ubuntu": r'ubuntu\d+(\.\d+)?$',  # ubuntu 빌드 번호
            "extract": r'^([0-9]+\.[0-9]+(?:\.[0-9]+)?[a-z]?)',  # 업스트림 추출
        },
        "rpm": {
            "release": r'-\d+(?:\.[^.]+)+$',  # release 부분
            "distro": r'\.(el|fc|rhel|centos|amzn|ol)\d+.*$',  # 배포판 태그
            "extract": r'^([0-9]+\.[0-9]+(?:\.[0-9]+)?[a-z]?)',
        },
        "apk": {
            "alpine": r'-r\d+$',  # Alpine revision
            "extract": r'^([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
        },
        "opkg": {
            "openwrt": r'-\d+$',  # OpenWRT 빌드 번호
            "extract": r'^([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
        },
    }
    
    # 알려진 소프트웨어의 특수 버전 형식
    SPECIAL_FORMATS = {
        "openssl": r'^(\d+\.\d+\.\d+[a-z]?)',  # 1.1.1f, 3.0.2
        "openssh": r'^(\d+\.\d+(?:p\d+)?)',  # 8.9p1
        "linux": r'^(\d+\.\d+(?:\.\d+)?)',  # 5.15.0
        "python": r'^(\d+\.\d+\.\d+)',  # 3.10.6
        "node": r'^(\d+\.\d+\.\d+)',  # 18.12.0
    }
    
    @classmethod
    def normalize(
        cls, 
        version: str, 
        pkg_manager: str = "",
        package_name: str = ""
    ) -> str:
        """
        버전 정규화
        
        Args:
            version: 원본 버전 문자열
            pkg_manager: 패키지 매니저 (dpkg, rpm, apk, opkg)
            package_name: 패키지명 (특수 형식 처리용)
            
        Returns:
            str: 정규화된 버전
        """
        if not version:
            return ""
        
        original = version
        
        # 1. 특수 패키지 형식 확인
        pkg_lower = package_name.lower()
        for software, pattern in cls.SPECIAL_FORMATS.items():
            if software in pkg_lower:
                match = re.search(pattern, version)
                if match:
                    return match.group(1)
        
        # 2. 패키지 매니저별 처리
        if pkg_manager in cls.PATTERNS:
            patterns = cls.PATTERNS[pkg_manager]
            
            # epoch 제거
            if "epoch" in patterns:
                version = re.sub(patterns["epoch"], '', version)
            
            # 배포판 접미사 제거
            for key, pattern in patterns.items():
                if key not in ("epoch", "extract"):
                    version = re.sub(pattern, '', version, flags=re.IGNORECASE)
            
            # 업스트림 버전 추출
            if "extract" in patterns:
                match = re.match(patterns["extract"], version)
                if match:
                    return match.group(1)
        
        # 3. 일반 정규화 (하이픈 기준 분리)
        if '-' in version:
            # 첫 하이픈 앞부분 추출 (단, 알파벳 뒤 하이픈은 유지)
            parts = version.split('-')
            if len(parts) >= 2:
                # 뒤 부분이 숫자로만 구성되면 릴리스 번호
                if parts[-1].replace('.', '').isdigit():
                    version = '-'.join(parts[:-1])
        
        return version if version else original
    
    @classmethod
    def compare(cls, v1: str, v2: str) -> int:
        """
        버전 비교
        
        Args:
            v1: 첫 번째 버전
            v2: 두 번째 버전
            
        Returns:
            int: -1 (v1 < v2), 0 (v1 == v2), 1 (v1 > v2)
        """
        def version_key(v: str):
            """버전을 비교 가능한 키로 변환"""
            # 숫자와 알파벳 분리
            parts = re.findall(r'(\d+|[a-zA-Z]+)', v)
            result = []
            for part in parts:
                if part.isdigit():
                    result.append((0, int(part), ''))  # 숫자 우선
                else:
                    result.append((1, 0, part.lower()))  # 알파벳
            return result
        
        k1, k2 = version_key(v1), version_key(v2)
        
        if k1 < k2:
            return -1
        elif k1 > k2:
            return 1
        return 0
    
    @classmethod
    def is_vulnerable(
        cls, 
        installed_version: str, 
        vulnerable_version: str,
        fixed_version: Optional[str] = None
    ) -> Tuple[bool, str]:
        """
        취약 버전 여부 확인
        
        Args:
            installed_version: 설치된 버전
            vulnerable_version: 취약 버전 (범위 시작)
            fixed_version: 수정 버전 (선택)
            
        Returns:
            Tuple[bool, str]: (취약여부, 판정근거)
        """
        norm_installed = cls.normalize(installed_version)
        norm_vuln = cls.normalize(vulnerable_version)
        
        if not norm_installed or not norm_vuln:
            return False, "Version info insufficient"
        
        # 정확히 취약 버전과 일치
        if norm_installed == norm_vuln:
            return True, f"Exact match: {norm_installed} == {norm_vuln}"
        
        # 범위 비교 (fixed_version이 있을 때)
        if fixed_version:
            norm_fixed = cls.normalize(fixed_version)
            
            # installed >= vuln AND installed < fixed → 취약
            if cls.compare(norm_installed, norm_vuln) >= 0:
                if cls.compare(norm_installed, norm_fixed) < 0:
                    return True, f"In range: {norm_vuln} <= {norm_installed} < {norm_fixed}"
        
        # 단순 버전 미만 비교
        if cls.compare(norm_installed, norm_vuln) <= 0:
            return True, f"Version {norm_installed} <= {norm_vuln}"
        
        return False, f"Version {norm_installed} > {norm_vuln}"
    
    @classmethod
    def extract_major_minor(cls, version: str) -> Tuple[int, int, int]:
        """
        Major.Minor.Patch 추출
        
        Args:
            version: 버전 문자열
            
        Returns:
            Tuple[int, int, int]: (major, minor, patch)
        """
        match = re.match(r'^(\d+)(?:\.(\d+))?(?:\.(\d+))?', version)
        if match:
            major = int(match.group(1) or 0)
            minor = int(match.group(2) or 0)
            patch = int(match.group(3) or 0)
            return (major, minor, patch)
        return (0, 0, 0)
