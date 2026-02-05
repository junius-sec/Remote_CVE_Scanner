"""
Base Parser - 파서 기본 클래스
"""

import re
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, asdict
from abc import ABC, abstractmethod


@dataclass
class PackageData:
    """표준화된 패키지 데이터 (CVE 파이프라인 입력용)"""
    name: str
    version: str  # 정규화된 버전
    raw_version: str = ""  # 원본 버전
    architecture: str = ""
    package_manager: str = ""
    
    # CVE 파이프라인 연동용 추가 정보
    confidence: str = "high"  # high, medium, low
    evidence: str = ""  # 수집 근거
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    def to_pipeline_format(self) -> Dict[str, Any]:
        """기존 CVE 파이프라인 입력 형식으로 변환"""
        return {
            "name": self.name,
            "version": self.version,
            "architecture": self.architecture,
            "package_manager": self.package_manager,
            # 추가 메타데이터 (파이프라인에서 활용)
            "_raw_version": self.raw_version,
            "_confidence": self.confidence,
            "_evidence": self.evidence,
        }


class BaseParser(ABC):
    """패키지 파서 기본 클래스"""
    
    # 패키지 매니저 식별자 (서브클래스에서 정의)
    PKG_MANAGER = "unknown"
    
    # 버전 정규화 시 제거할 일반적인 접미사
    COMMON_SUFFIXES = [
        r'-r\d+$',           # Alpine: -r0, -r1
        r'\.el\d+.*$',       # RHEL/CentOS: .el7, .el8
        r'\.fc\d+.*$',       # Fedora: .fc35
        r'~.*$',             # Debian: ~beta1
        r'\+.*$',            # 빌드 메타데이터
    ]
    
    def __init__(self):
        self._errors: List[str] = []
    
    @abstractmethod
    def parse(self, raw_output: str) -> List[PackageData]:
        """
        원시 출력을 파싱하여 PackageData 리스트 반환
        
        Args:
            raw_output: 패키지 매니저 명령 출력
            
        Returns:
            List[PackageData]: 파싱된 패키지 목록
        """
        pass
    
    @abstractmethod
    def normalize_version(self, version: str) -> str:
        """
        버전 문자열 정규화
        
        배포판별 접미사/접두사를 제거하여 순수 버전 추출
        
        Args:
            version: 원본 버전 문자열
            
        Returns:
            str: 정규화된 버전
        """
        pass
    
    def normalize_package_name(self, name: str) -> str:
        """
        패키지명 정규화
        
        Args:
            name: 원본 패키지명
            
        Returns:
            str: 정규화된 패키지명
        """
        # 소문자 변환
        name = name.lower().strip()
        
        # 아키텍처 접미사 제거 (예: openssl:amd64)
        if ':' in name:
            name = name.split(':')[0]
        
        return name
    
    def extract_upstream_version(self, version: str) -> str:
        """
        업스트림 버전만 추출 (예: 1.1.1f-1ubuntu2 → 1.1.1f)
        
        Args:
            version: 전체 버전 문자열
            
        Returns:
            str: 업스트림 버전
        """
        if not version:
            return ""
        
        # epoch 제거 (예: 2:1.2.3 → 1.2.3)
        if ':' in version:
            version = version.split(':', 1)[1]
        
        # 버전-릴리스 분리 (첫 하이픈 기준)
        # 단, 하이픈 뒤가 숫자로 시작하면 릴리스로 간주
        match = re.match(r'^([^-]+(?:-[a-zA-Z][^-]*)*)', version)
        if match:
            version = match.group(1)
        
        # 일반적인 접미사 제거
        for pattern in self.COMMON_SUFFIXES:
            version = re.sub(pattern, '', version)
        
        return version
    
    def compare_versions(self, v1: str, v2: str) -> int:
        """
        버전 비교 (-1: v1 < v2, 0: v1 == v2, 1: v1 > v2)
        
        Args:
            v1: 첫 번째 버전
            v2: 두 번째 버전
            
        Returns:
            int: 비교 결과
        """
        def version_tuple(v: str):
            """버전을 비교 가능한 튜플로 변환"""
            # 숫자와 문자 분리
            parts = re.findall(r'(\d+|[a-zA-Z]+)', v)
            result = []
            for part in parts:
                if part.isdigit():
                    result.append((0, int(part)))  # 숫자
                else:
                    result.append((1, part.lower()))  # 문자
            return result
        
        t1, t2 = version_tuple(v1), version_tuple(v2)
        
        if t1 < t2:
            return -1
        elif t1 > t2:
            return 1
        return 0
    
    def get_errors(self) -> List[str]:
        """파싱 중 발생한 에러 반환"""
        return self._errors.copy()
    
    def clear_errors(self):
        """에러 목록 초기화"""
        self._errors = []
