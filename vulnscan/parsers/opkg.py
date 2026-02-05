"""
OPKG Parser - OpenWRT 패키지 파서
"""

import re
from typing import List
from .base import BaseParser, PackageData


class OpkgParser(BaseParser):
    """OpenWRT opkg 패키지 파서"""
    
    PKG_MANAGER = "opkg"
    
    def parse(self, raw_output: str) -> List[PackageData]:
        """
        opkg list-installed 출력 파싱
        
        출력 형식: package - version
        예시:
            base-files - 1508-r23420-2df6ceb138
            busybox - 1.35.0-1
            dnsmasq - 2.86-9
            dropbear - 2022.83-1
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
        
        # 형식: name - version
        if ' - ' in line:
            parts = line.split(' - ', 1)
            name = parts[0].strip()
            raw_version = parts[1].strip()
        else:
            # 공백으로 분리 시도
            parts = line.split()
            if len(parts) >= 2:
                name = parts[0]
                raw_version = parts[1]
            else:
                return None
        
        return PackageData(
            name=self.normalize_package_name(name),
            version=self.normalize_version(raw_version),
            raw_version=raw_version,
            package_manager=self.PKG_MANAGER,
            confidence="high",
            evidence="opkg list-installed"
        )
    
    def normalize_version(self, version: str) -> str:
        """
        OpenWRT 버전 정규화
        
        형식이 다양함:
            1.35.0-1 → 1.35.0
            2.86-9 → 2.86
            2022.83-1 → 2022.83
            1508-r23420-2df6ceb138 → 1508 (빌드 해시 제거)
        """
        if not version:
            return ""
        
        # 빌드 해시 제거 (예: -r23420-2df6ceb138)
        version = re.sub(r'-r\d+-[a-f0-9]+$', '', version)
        
        # 일반적인 릴리스 번호 제거 (마지막 하이픈 뒤 숫자)
        if '-' in version:
            # 하이픈 뒤가 순수 숫자면 제거
            base, suffix = version.rsplit('-', 1)
            if suffix.isdigit():
                version = base
        
        return version
    
    def parse_opkg_info(self, raw_output: str) -> List[PackageData]:
        """
        opkg info 출력 파싱 (상세 정보)
        
        형식:
        Package: busybox
        Version: 1.35.0-1
        Status: install ok installed
        Architecture: mips_24kc
        """
        packages = []
        current_pkg = {}
        
        for line in raw_output.split('\n'):
            line = line.strip()
            
            if line.startswith('Package:'):
                if current_pkg.get('name') and current_pkg.get('version'):
                    packages.append(PackageData(
                        name=self.normalize_package_name(current_pkg['name']),
                        version=self.normalize_version(current_pkg['version']),
                        raw_version=current_pkg['version'],
                        architecture=current_pkg.get('arch', ''),
                        package_manager=self.PKG_MANAGER,
                        confidence="high",
                        evidence="opkg info"
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
                evidence="opkg info"
            ))
        
        return packages
