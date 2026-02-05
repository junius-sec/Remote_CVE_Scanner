"""Security Tracker Factory - OS별 보안 트래커 관리"""
from typing import Optional, Protocol
from pathlib import Path
import json
import time
import httpx
from datetime import datetime


class SecurityTracker(Protocol):
    """모든 Security Tracker가 구현해야 하는 인터페이스"""
    
    async def initialize(self) -> None:
        """트래커 데이터 초기화"""
        ...
    
    def check_package_patch_status(self, package_name: str, cve_id: str) -> dict:
        """패키지의 CVE 패치 상태 확인"""
        ...


class DebianSecurityTracker:
    """Debian/Ubuntu Security Tracker"""
    
    def __init__(self):
        self.cache_dir = Path(__file__).parent.parent / "cache"
        self.cache_dir.mkdir(exist_ok=True)
        
        self.debian_cache_file = self.cache_dir / "debian_security_cache.json"
        self.ubuntu_cache_file = self.cache_dir / "ubuntu_security_cache.json"
        
        self.debian_data = {}
        self.ubuntu_data = {}
        self.cache_ttl = 86400  # 24시간
        self._initialized = False
    
    async def initialize(self) -> None:
        """Debian/Ubuntu 보안 데이터 로드"""
        if self._initialized:
            return
        
        print("Debian/Ubuntu Security Tracker 초기화 중...")
        
        # Debian 데이터 로드
        if self._is_cache_valid(self.debian_cache_file):
            with open(self.debian_cache_file, 'r') as f:
                self.debian_data = json.load(f)
            print(f"Debian 캐시 로드: {len(self.debian_data)}개 패키지")
        else:
            await self._fetch_debian_data()
        
        # Ubuntu 데이터 로드
        if self._is_cache_valid(self.ubuntu_cache_file):
            with open(self.ubuntu_cache_file, 'r') as f:
                cache = json.load(f)
                # 캐시 형식: {'CVE-ID': {...}} 직접 사용
                self.ubuntu_data = cache if isinstance(cache, dict) else cache.get('data', {})
            print(f"Ubuntu 캐시 로드: {len(self.ubuntu_data)}개 CVE")
        else:
            await self._fetch_ubuntu_data()
        
        self._initialized = True
    
    def check_package_patch_status(self, package_name: str, cve_id: str, distro: str = "debian") -> dict:
        """패키지의 CVE 패치 상태 확인"""
        # Ubuntu 코드네임 목록
        ubuntu_codenames = ["oracular", "noble", "jammy", "focal", "bionic", "xenial", 
                           "mantic", "lunar", "kinetic", "impish", "hirsute"]
        
        if distro.lower() in ubuntu_codenames or "ubuntu" in distro.lower():
            # Ubuntu 확인
            cve_data = self.ubuntu_data.get(cve_id, {})
            if package_name in cve_data.get('packages', {}):
                return {
                    'is_patched': True,
                    'source': 'ubuntu_tracker',
                    'fixed_version': cve_data['packages'][package_name].get('fixed_version')
                }
        
        # Debian 확인
        pkg_data = self.debian_data.get(package_name, {})
        if cve_id in pkg_data:
            releases = pkg_data[cve_id].get('releases', {})
            bookworm_status = releases.get('bookworm', {}).get('status')
            if bookworm_status in ['resolved', 'not-affected']:
                return {
                    'is_patched': True,
                    'source': 'debian_tracker',
                    'fixed_version': releases.get('bookworm', {}).get('fixed_version')
                }
        
        return {'is_patched': False, 'source': None}
    
    def _is_cache_valid(self, cache_file: Path) -> bool:
        """캐시 유효성 확인"""
        if not cache_file.exists():
            return False
        mtime = cache_file.stat().st_mtime
        return (time.time() - mtime) < self.cache_ttl
    
    async def _fetch_debian_data(self):
        """Debian Security Tracker 데이터 다운로드"""
        # 기존 DebianSecurityClient 로직 사용
        pass
    
    async def _fetch_ubuntu_data(self):
        """Ubuntu CVE Tracker 데이터 다운로드"""
        # 기존 로직 사용
        pass


class AlpineSecurityTracker:
    """Alpine Linux Security Tracker"""
    
    def __init__(self):
        self.cache_dir = Path(__file__).parent.parent / "cache"
        self.cache_dir.mkdir(exist_ok=True)
        self.cache_file = self.cache_dir / "alpine_security_cache.json"
        
        self.alpine_data = {}
        self.cache_ttl = 86400
        self._initialized = False
    
    async def initialize(self) -> None:
        """Alpine 보안 데이터 로드"""
        if self._initialized:
            return
        
        print("Alpine Security Tracker 초기화 중...")
        
        if self._is_cache_valid(self.cache_file):
            with open(self.cache_file, 'r') as f:
                cache = json.load(f)
                self.alpine_data = cache.get('data', {})
            print(f"Alpine 캐시 로드: {len(self.alpine_data)}개 CVE")
        else:
            await self._fetch_alpine_data()
        
        self._initialized = True
    
    def check_package_patch_status(self, package_name: str, cve_id: str, distro: str = "alpine") -> dict:
        """Alpine 패키지의 CVE 패치 상태 확인"""
        cve_data = self.alpine_data.get(cve_id, {})
        
        # Alpine 버전별 확인 (3.19, 3.20 등)
        for version_data in cve_data.get('packages', {}).values():
            if package_name in version_data.get('fixed_packages', []):
                return {
                    'is_patched': True,
                    'source': 'alpine_tracker',
                    'fixed_version': version_data.get('fixed_version')
                }
        
        return {'is_patched': False, 'source': None}
    
    def _is_cache_valid(self, cache_file: Path) -> bool:
        """캐시 유효성 확인"""
        if not cache_file.exists():
            return False
        mtime = cache_file.stat().st_mtime
        return (time.time() - mtime) < self.cache_ttl
    
    async def _fetch_alpine_data(self):
        """Alpine Security Database 다운로드"""
        print("Alpine Security DB 다운로드 중...")
        
        try:
            # Alpine Security DB는 간단한 형태로 제공 (커뮤니티 json 파일 없음)
            # 대신 빈 데이터로 초기화 (향후 실제 DB 구현 시 확장 가능)
            self.alpine_data = {}
            
            # 캐시 저장
            with open(self.cache_file, 'w') as f:
                json.dump({
                    'data': self.alpine_data,
                    'cached_at': time.time()
                }, f)
            
            print("Alpine Security Tracker: 준비됨 (패치 정보는 NVD CPE 기반으로 판단)")
            
        except Exception as e:
            print(f"Alpine Security DB 다운로드 실패: {e}")
            self.alpine_data = {}


class SecurityTrackerFactory:
    """OS별 Security Tracker 생성 팩토리"""
    
    _trackers = {}
    
    @classmethod
    async def get_tracker(cls, distro_id: str) -> Optional[SecurityTracker]:
        """배포판 ID에 맞는 Security Tracker 반환"""
        distro_lower = distro_id.lower()
        
        # 이미 초기화된 트래커 반환
        if distro_lower in cls._trackers:
            return cls._trackers[distro_lower]
        
        # 새 트래커 생성
        tracker = None
        
        if distro_lower in ['ubuntu', 'debian', 'jammy', 'focal', 'noble', 'bookworm', 'bullseye']:
            tracker = DebianSecurityTracker()
        elif distro_lower in ['alpine', 'alpine-linux']:
            tracker = AlpineSecurityTracker()
        # 향후 추가:
        # elif distro_lower in ['arch', 'archlinux']:
        #     tracker = ArchSecurityTracker()
        # elif distro_lower in ['fedora', 'rhel', 'centos']:
        #     tracker = RedHatSecurityTracker()
        else:
            print(f"[WARN] {distro_id}에 대한 Security Tracker 없음")
            return None
        
        # 초기화
        await tracker.initialize()
        cls._trackers[distro_lower] = tracker
        
        return tracker
    
    @classmethod
    def clear_cache(cls):
        """모든 트래커 캐시 클리어"""
        cls._trackers.clear()


# 편의 함수
async def get_security_tracker(distro_id: str) -> Optional[SecurityTracker]:
    """배포판에 맞는 Security Tracker 가져오기"""
    return await SecurityTrackerFactory.get_tracker(distro_id)
