"""
RPM Parser - RHEL/CentOS/Fedora 패키지 파서
"""

import re
from typing import List
from .base import BaseParser, PackageData


class RpmParser(BaseParser):
    """RPM 패키지 파서 (RHEL/CentOS/Fedora/Rocky/Alma)"""
    
    PKG_MANAGER = "rpm"
    
    def parse(self, raw_output: str) -> List[PackageData]:
        """
        rpm -qa 출력 파싱
        
        명령: rpm -qa --queryformat '%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n'
        
        출력 형식: name\tversion-release\tarch
        예시:
            openssl\t1.0.2k-19.el7\tx86_64
            bash\t4.2.46-35.el7_9\tx86_64
            kernel\t3.10.0-1160.el7\tx86_64
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
        
        return PackageData(
            name=self.normalize_package_name(name),
            version=self.normalize_version(raw_version),
            raw_version=raw_version,
            architecture=arch,
            package_manager=self.PKG_MANAGER,
            confidence="high",
            evidence="rpm -qa --queryformat"
        )
    
    def normalize_version(self, version: str) -> str:
        """
        RPM 버전 정규화
        
        형식: version-release
        release에는 배포판 태그 포함 (.el7, .fc35 등)
        
        예시:
            1.0.2k-19.el7 → 1.0.2k
            4.2.46-35.el7_9 → 4.2.46
            3.10.0-1160.el7 → 3.10.0
            8.2-1.fc35 → 8.2
        """
        if not version:
            return ""
        
        # release 부분 제거 (첫 번째 하이픈 뒤)
        if '-' in version:
            version = version.split('-')[0]
        
        # 배포판 태그가 남아있으면 제거
        patterns = [
            r'\.el\d+.*$',      # .el7, .el8
            r'\.fc\d+.*$',      # .fc35, .fc36
            r'\.rhel\d+.*$',    # .rhel7
            r'\.centos\d*$',    # .centos
            r'\.amzn\d+.*$',    # .amzn2
            r'\.module.*$',     # 모듈 스트림
        ]
        
        for pattern in patterns:
            version = re.sub(pattern, '', version, flags=re.IGNORECASE)
        
        return version
    
    def parse_rpm_simple(self, raw_output: str) -> List[PackageData]:
        """
        rpm -qa 간단 형식 파싱 (queryformat 없이)
        
        출력 형식: name-version-release.arch
        예시: openssl-1.0.2k-19.el7.x86_64
        """
        packages = []
        
        for line in raw_output.strip().split('\n'):
            line = line.strip()
            if not line:
                continue
            
            # NVRA 파싱: name-version-release.arch
            # 역순으로 분리 (아키텍처, 릴리스, 버전, 이름 순)
            
            # 아키텍처 분리
            if '.' in line:
                base, arch = line.rsplit('.', 1)
                # 알려진 아키텍처 확인
                if arch not in ['x86_64', 'i686', 'noarch', 'aarch64', 'armv7hl']:
                    arch = ''
                    base = line
            else:
                base = line
                arch = ''
            
            # name-version-release 분리
            parts = base.rsplit('-', 2)
            if len(parts) >= 3:
                name = parts[0]
                version = parts[1]
                release = parts[2]
                raw_version = f"{version}-{release}"
            elif len(parts) == 2:
                name = parts[0]
                raw_version = parts[1]
                version = raw_version
            else:
                continue
            
            packages.append(PackageData(
                name=self.normalize_package_name(name),
                version=self.normalize_version(raw_version),
                raw_version=raw_version,
                architecture=arch,
                package_manager=self.PKG_MANAGER,
                confidence="medium",
                evidence="rpm -qa (NVRA parsing)"
            ))
        
        return packages
