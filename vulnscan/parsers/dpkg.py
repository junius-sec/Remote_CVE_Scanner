"""
DPKG Parser - Debian/Ubuntu 패키지 파서
"""

import re
from typing import List
from .base import BaseParser, PackageData


class DpkgParser(BaseParser):
    """Debian/Ubuntu dpkg 패키지 파서"""
    
    PKG_MANAGER = "dpkg"
    
    def parse(self, raw_output: str) -> List[PackageData]:
        """
        dpkg-query 출력 파싱
        
        명령: dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\n'
        
        출력 형식: package\tversion\tarch
        예시:
            openssl\t1.1.1f-1ubuntu2.16\tamd64
            libssl1.1\t1.1.1f-1ubuntu2.16\tamd64
            bash\t5.0-6ubuntu1.2\tamd64
        """
        packages = []
        self.clear_errors()
        
        if not raw_output:
            return packages
        
        for line in raw_output.strip().split('\n'):
            line = line.strip()
            if not line:
                continue
            
            try:
                parsed = self._parse_line(line)
                if parsed:
                    packages.append(parsed)
            except Exception as e:
                self._errors.append(f"Failed to parse line '{line}': {e}")
        
        return packages
    
    def _parse_line(self, line: str) -> PackageData:
        """단일 라인 파싱"""
        parts = line.split('\t')
        
        if len(parts) < 2:
            # 탭이 없으면 공백으로 시도
            parts = line.split()
        
        if len(parts) < 2:
            return None
        
        name = parts[0]
        raw_version = parts[1]
        arch = parts[2] if len(parts) > 2 else ""
        
        # 아키텍처가 이름에 붙어있는 경우 처리 (예: openssl:amd64)
        if ':' in name:
            name, arch_suffix = name.split(':', 1)
            if not arch:
                arch = arch_suffix
        
        return PackageData(
            name=self.normalize_package_name(name),
            version=self.normalize_version(raw_version),
            raw_version=raw_version,
            architecture=arch,
            package_manager=self.PKG_MANAGER,
            confidence="high",
            evidence="dpkg-query -W"
        )
    
    def normalize_version(self, version: str) -> str:
        """
        Debian/Ubuntu 버전 정규화
        
        형식: [epoch:]upstream[-debian_revision]
        
        예시:
            1.1.1f-1ubuntu2.16 → 1.1.1f
            2:8.2.3995-1ubuntu3 → 8.2.3995
            5.0-6ubuntu1.2 → 5.0
            1.2.11.dfsg-2ubuntu1 → 1.2.11
        """
        if not version:
            return ""
        
        # epoch 제거 (예: 2:8.2.3995 → 8.2.3995)
        if ':' in version:
            version = version.split(':', 1)[1]
        
        # Debian/Ubuntu 리비전 제거
        # 전략: 첫 번째 하이픈 뒤 첫 숫자 앞까지 또는 알려진 패턴
        
        # 방법 1: 알려진 패턴 제거
        patterns = [
            r'-\d*ubuntu[\d.]*$',     # ubuntu 리비전
            r'-\d+build\d+$',         # build 번호
            r'-\d+$',                 # 단순 리비전 번호
            r'\.dfsg[\d.]*',          # DFSG 표시
            r'\+deb\d+u\d+$',         # Debian 보안 업데이트
            r'\+really.*$',           # really 버전
        ]
        
        for pattern in patterns:
            version = re.sub(pattern, '', version, flags=re.IGNORECASE)
        
        # 방법 2: 업스트림 버전 추출
        # 숫자.숫자 형태로 시작하는 부분 추출
        match = re.match(r'^([0-9]+\.[0-9]+(?:\.[0-9]+)?[a-z]?(?:\.[0-9]+)?)', version)
        if match:
            return match.group(1)
        
        # 하이픈 앞 부분만
        if '-' in version:
            version = version.split('-')[0]
        
        return version
    
    def parse_dpkg_status(self, raw_output: str) -> List[PackageData]:
        """
        /var/lib/dpkg/status 파일 파싱 (대안)
        
        SSH로 dpkg-query 실행이 안 될 때 사용
        """
        packages = []
        current_pkg = {}
        
        for line in raw_output.split('\n'):
            if line.startswith('Package:'):
                if current_pkg.get('name') and current_pkg.get('version'):
                    packages.append(PackageData(
                        name=self.normalize_package_name(current_pkg['name']),
                        version=self.normalize_version(current_pkg['version']),
                        raw_version=current_pkg['version'],
                        architecture=current_pkg.get('arch', ''),
                        package_manager=self.PKG_MANAGER,
                        confidence="high",
                        evidence="/var/lib/dpkg/status"
                    ))
                current_pkg = {'name': line.split(':', 1)[1].strip()}
            elif line.startswith('Version:'):
                current_pkg['version'] = line.split(':', 1)[1].strip()
            elif line.startswith('Architecture:'):
                current_pkg['arch'] = line.split(':', 1)[1].strip()
        
        # 마지막 패키지
        if current_pkg.get('name') and current_pkg.get('version'):
            packages.append(PackageData(
                name=self.normalize_package_name(current_pkg['name']),
                version=self.normalize_version(current_pkg['version']),
                raw_version=current_pkg['version'],
                architecture=current_pkg.get('arch', ''),
                package_manager=self.PKG_MANAGER,
                confidence="high",
                evidence="/var/lib/dpkg/status"
            ))
        
        return packages
