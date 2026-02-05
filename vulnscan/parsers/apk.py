"""
APK Parser - Alpine Linux 패키지 파서
"""

import re
from typing import List
from .base import BaseParser, PackageData


class ApkParser(BaseParser):
    """Alpine Linux apk 패키지 파서"""
    
    PKG_MANAGER = "apk"
    
    def parse(self, raw_output: str) -> List[PackageData]:
        """
        apk info -v 출력 파싱
        
        출력 형식: package-name-version
        예시:
            busybox-1.36.1-r2
            openssl-3.1.4-r0
            musl-1.2.4-r2
            alpine-baselayout-3.4.3-r1
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
        """
        단일 라인 파싱
        
        Alpine 패키지 형식: name-version
        버전은 항상 숫자로 시작하고 -rN 접미사 가능
        """
        # 뒤에서부터 버전 찾기 (숫자로 시작하는 마지막 하이픈 구분자)
        # 예: alpine-baselayout-3.4.3-r1
        #     name: alpine-baselayout, version: 3.4.3-r1
        
        # 정규식: 마지막 -숫자 패턴 찾기
        match = re.match(r'^(.+)-(\d+\.\d+(?:\.\d+)?(?:-r\d+)?)$', line)
        
        if match:
            name = match.group(1)
            raw_version = match.group(2)
            
            return PackageData(
                name=self.normalize_package_name(name),
                version=self.normalize_version(raw_version),
                raw_version=raw_version,
                package_manager=self.PKG_MANAGER,
                confidence="high",
                evidence="apk info -v"
            )
        
        # Fallback: 마지막 하이픈 기준 분리
        if '-' in line:
            parts = line.rsplit('-', 2)  # 최대 2개로 분리
            if len(parts) >= 2:
                # 뒤에서 두 번째가 숫자로 시작하면 그것이 버전
                if len(parts) == 3 and parts[1][0].isdigit():
                    name = parts[0]
                    raw_version = f"{parts[1]}-{parts[2]}"
                elif parts[-1][0].isdigit():
                    name = '-'.join(parts[:-1])
                    raw_version = parts[-1]
                else:
                    # 버전 추출 실패
                    return None
                
                return PackageData(
                    name=self.normalize_package_name(name),
                    version=self.normalize_version(raw_version),
                    raw_version=raw_version,
                    package_manager=self.PKG_MANAGER,
                    confidence="medium",  # fallback이므로 중간 신뢰도
                    evidence="apk info -v (fallback parsing)"
                )
        
        return None
    
    def normalize_version(self, version: str) -> str:
        """
        Alpine 버전 정규화
        
        1.36.1-r2 → 1.36.1
        3.1.4-r0 → 3.1.4
        """
        if not version:
            return ""
        
        # -rN 제거
        version = re.sub(r'-r\d+$', '', version)
        
        # _pN (패치 레벨) 처리 (예: 3.0.10_p1)
        version = re.sub(r'_p\d+$', '', version)
        
        # _alphaN, _betaN, _rcN 유지 (의미 있는 버전 정보)
        
        return version
