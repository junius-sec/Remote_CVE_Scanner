"""
Binary Parser - 바이너리 버전 추출 파서

패키지 매니저가 없는 환경(Yocto, BusyBox 등)에서
핵심 바이너리의 버전을 추출합니다.
"""

import re
from typing import List, Dict, Optional, Tuple
from .base import BaseParser, PackageData


class BinaryParser(BaseParser):
    """바이너리 버전 추출 파서"""
    
    PKG_MANAGER = "binary"
    
    # 바이너리별 버전 추출 패턴
    VERSION_PATTERNS = {
        "openssl": [
            (r'OpenSSL\s+(\d+\.\d+\.\d+[a-z]?)', "high"),
            (r'(\d+\.\d+\.\d+[a-z]?)', "medium"),
        ],
        "openssh": [
            (r'OpenSSH[_\s]+(\d+\.\d+(?:p\d+)?)', "high"),
            (r'SSH-\d+\.\d+-OpenSSH_(\d+\.\d+(?:p\d+)?)', "high"),
        ],
        "busybox": [
            (r'BusyBox\s+v?(\d+\.\d+\.\d+)', "high"),
            (r'v?(\d+\.\d+\.\d+)', "medium"),
        ],
        "dropbear": [
            (r'Dropbear\s+v?(\d+\.\d+(?:\.\d+)?)', "high"),
            (r'SSH-\d+\.\d+-dropbear_(\d+\.\d+)', "high"),
        ],
        "curl": [
            (r'curl\s+(\d+\.\d+\.\d+)', "high"),
        ],
        "wget": [
            (r'GNU\s+Wget\s+(\d+\.\d+(?:\.\d+)?)', "high"),
            (r'Wget\s+(\d+\.\d+(?:\.\d+)?)', "high"),
        ],
        "nginx": [
            (r'nginx/(\d+\.\d+\.\d+)', "high"),
        ],
        "apache": [
            (r'Apache/(\d+\.\d+\.\d+)', "high"),
            (r'Server version:\s+Apache/(\d+\.\d+\.\d+)', "high"),
        ],
        "python": [
            (r'Python\s+(\d+\.\d+\.\d+)', "high"),
        ],
        "node": [
            (r'v?(\d+\.\d+\.\d+)', "medium"),
        ],
        "glibc": [
            (r'GNU C Library.*?(\d+\.\d+)', "high"),
            (r'glibc\s+(\d+\.\d+)', "high"),
            (r'libc[- ](\d+\.\d+)', "medium"),
        ],
        "dnsmasq": [
            (r'Dnsmasq\s+version\s+(\d+\.\d+(?:\.\d+)?)', "high"),
            (r'version\s+(\d+\.\d+(?:\.\d+)?)', "medium"),
        ],
        "lighttpd": [
            (r'lighttpd/(\d+\.\d+\.\d+)', "high"),
        ],
        "kernel": [
            (r'Linux\s+version\s+(\d+\.\d+\.\d+)', "high"),
            (r'^(\d+\.\d+\.\d+)', "high"),  # uname -r 직접 출력
        ],
    }
    
    def parse(self, raw_output: str, binary_name: str = "") -> List[PackageData]:
        """
        바이너리 버전 출력 파싱
        
        Args:
            raw_output: 버전 명령 출력
            binary_name: 바이너리 이름 (패턴 선택용)
            
        Returns:
            List[PackageData]: 보통 1개 또는 빈 리스트
        """
        packages = []
        self.clear_errors()
        
        if not raw_output:
            return packages
        
        result = self.extract_version(raw_output, binary_name)
        if result:
            version, confidence = result
            packages.append(PackageData(
                name=binary_name.lower(),
                version=version,
                raw_version=raw_output[:100],  # 원본 저장 (최대 100자)
                package_manager=self.PKG_MANAGER,
                confidence=confidence,
                evidence=f"{binary_name} version command"
            ))
        
        return packages
    
    def extract_version(
        self, 
        output: str, 
        binary_name: str = ""
    ) -> Optional[Tuple[str, str]]:
        """
        출력에서 버전 추출
        
        Args:
            output: 명령 출력
            binary_name: 바이너리 이름
            
        Returns:
            (version, confidence) 또는 None
        """
        binary_lower = binary_name.lower()
        
        # 1. 특정 바이너리용 패턴 시도
        if binary_lower in self.VERSION_PATTERNS:
            for pattern, confidence in self.VERSION_PATTERNS[binary_lower]:
                match = re.search(pattern, output, re.IGNORECASE | re.MULTILINE)
                if match:
                    return (match.group(1), confidence)
        
        # 2. 일반 버전 패턴 시도 (fallback)
        general_patterns = [
            (r'version\s+(\d+\.\d+(?:\.\d+)?)', "medium"),
            (r'v(\d+\.\d+(?:\.\d+)?)', "low"),
            (r'(\d+\.\d+\.\d+)', "low"),
        ]
        
        for pattern, confidence in general_patterns:
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                return (match.group(1), confidence)
        
        return None
    
    def normalize_version(self, version: str) -> str:
        """바이너리 버전 정규화 (대부분 그대로 사용)"""
        if not version:
            return ""
        
        # 앞뒤 공백 및 v 접두사 제거
        version = version.strip().lstrip('v')
        
        return version
    
    def parse_multiple(
        self, 
        outputs: Dict[str, str]
    ) -> List[PackageData]:
        """
        여러 바이너리 출력 일괄 파싱
        
        Args:
            outputs: {binary_name: output} 딕셔너리
            
        Returns:
            List[PackageData]
        """
        packages = []
        
        for binary_name, output in outputs.items():
            result = self.parse(output, binary_name)
            packages.extend(result)
        
        return packages
    
    def get_version_command(self, binary_name: str) -> str:
        """바이너리별 버전 확인 명령 반환"""
        commands = {
            "openssl": "openssl version",
            "openssh": "ssh -V 2>&1",
            "busybox": "busybox --version 2>/dev/null || busybox 2>&1 | head -1",
            "dropbear": "dropbear -V 2>&1 | head -1",
            "curl": "curl --version 2>/dev/null | head -1",
            "wget": "wget --version 2>/dev/null | head -1",
            "nginx": "nginx -v 2>&1",
            "apache": "httpd -v 2>&1 || apache2 -v 2>&1",
            "python": "python3 --version 2>/dev/null || python --version 2>/dev/null",
            "node": "node --version 2>/dev/null",
            "glibc": "/lib/libc.so.6 2>&1 | head -1 || /lib64/libc.so.6 2>&1 | head -1",
            "dnsmasq": "dnsmasq --version 2>/dev/null | head -1",
            "lighttpd": "lighttpd -v 2>/dev/null | head -1",
            "kernel": "uname -r",
        }
        
        return commands.get(binary_name.lower(), f"{binary_name} --version 2>/dev/null | head -1")
