"""
Debian Security Tracker Client

Debian Security Tracker (https://security-tracker.debian.org/)의 JSON 데이터를 활용하여
실제 패치 상태를 확인합니다.

라이센스: 공개 데이터 (연구/상업 자유롭게 사용 가능)
데이터 출처: https://security-tracker.debian.org/tracker/data/json
"""

import httpx
import asyncio
import json
import os
import time
import subprocess
from typing import Optional, Dict, Tuple
from pathlib import Path


class DebianSecurityClient:
    """
    Debian/Ubuntu/Raspbian 패키지의 CVE 패치 상태를 확인하는 클라이언트

    - JSON 데이터를 로컬에 캐싱하여 빠른 조회 (O(1))
    - 24시간마다 자동 갱신
    - Ubuntu는 Ubuntu Security API 사용 (정확한 패치 정보)
    - Debian/Raspbian은 Debian Security Tracker 사용
    - Alpine은 별도 처리 (apk 기반)
    """
    # Ubuntu 트래커에 매칭되지 않으면 취약으로 보지 않음 (오탐 최소화)
    UBUNTU_STRICT_TRACKER_ONLY = False

    # Debian Security Tracker JSON URL
    DEBIAN_DATA_URL = "https://security-tracker.debian.org/tracker/data/json"

    # Ubuntu Security API (CVE별 조회)
    UBUNTU_CVE_API = "https://ubuntu.com/security/cves/{cve_id}.json"

    # Ubuntu 코드네임 목록 (Ubuntu인지 확인용)
    UBUNTU_CODENAMES = {
        "oracular", "noble", "jammy", "focal", "bionic", "xenial",  # LTS + 24.10
        "mantic", "lunar", "kinetic", "impish", "hirsute",  # 일반
    }
    
    # Raspbian 코드네임 (Debian 기반)
    RASPBIAN_CODENAMES = {
        "bookworm", "bullseye", "buster", "stretch",
    }

    # Ubuntu 코드네임 → Debian 코드네임 매핑 (fallback용)
    UBUNTU_TO_DEBIAN = {
        "oracular": "trixie",   # 24.10 → Debian 13
        "noble": "trixie",      # 24.04 → Debian 13
        "jammy": "bookworm",    # 22.04 → Debian 12
        "focal": "bullseye",    # 20.04 → Debian 11
        "bionic": "buster",     # 18.04 → Debian 10
        "mantic": "trixie",
        "lunar": "bookworm",
        "kinetic": "bookworm",
    }

    def __init__(self, cache_dir: Optional[str] = None):
        """
        Args:
            cache_dir: 캐시 디렉토리 경로 (기본: 현재 디렉토리)
        """
        self.cache_dir = Path(cache_dir) if cache_dir else Path(".")
        self.cache_file = self.cache_dir / "debian_security_cache.json"
        self.ubuntu_cache_file = self.cache_dir / "ubuntu_security_cache.json"
        self.cache_ttl = 86400  # 24시간

        # 메모리 캐시 (Debian)
        self._data: Optional[Dict] = None
        self._loaded_at: float = 0

        # Ubuntu CVE 캐시 (개별 CVE 조회 결과)
        self._ubuntu_cache: Dict[str, Dict] = {}
        self._ubuntu_cache_loaded: bool = False

        # OS 정보 (lazy load)
        self._os_codename: Optional[str] = None
        self._debian_codename: Optional[str] = None
        self._distro_id: Optional[str] = None  # 배포판 ID 추가
        self._is_ubuntu: Optional[bool] = None
        self._is_raspbian: Optional[bool] = None  # Raspbian 플래그 추가
        self._source_pkg_cache: Dict[str, Optional[str]] = {}

    async def initialize(self) -> bool:
        """
        데이터 초기화 (다운로드 또는 캐시 로드)

        Returns:
            성공 여부
        """
        # OS 정보 먼저 확인
        self._detect_os()
        
        # Ubuntu 캐시 로드
        if self._is_ubuntu:
            await self._load_ubuntu_cache()

        # 이미 로드됨
        if self._data and (time.time() - self._loaded_at) < self.cache_ttl:
            return True

        # 캐시 파일 확인
        if self.cache_file.exists():
            cache_age = time.time() - self.cache_file.stat().st_mtime
            if cache_age < self.cache_ttl:
                return await self._load_from_cache()

        # 새로 다운로드
        return await self._download_data()

    def _detect_os(self):
        """OS 정보 감지 (Ubuntu, Raspbian, Debian, Alpine 구분)"""
        if self._distro_id is not None:
            return
        
        self._distro_id = "unknown"
        self._os_codename = "unknown"
        self._is_ubuntu = False
        self._is_raspbian = False
        
        try:
            with open("/etc/os-release", "r") as f:
                content = f.read()
                for line in content.split('\n'):
                    if line.startswith("ID="):
                        self._distro_id = line.split("=")[1].strip('"').lower()
                    elif line.startswith("VERSION_CODENAME="):
                        self._os_codename = line.strip().split("=")[1].strip('"')
                    elif line.startswith("UBUNTU_CODENAME="):
                        self._os_codename = line.strip().split("=")[1].strip('"')
        except:
            pass
        
        # OS 타입 판단
        self._is_ubuntu = self._os_codename in self.UBUNTU_CODENAMES
        self._is_raspbian = (
            self._distro_id in ["raspbian", "debian"] and 
            self._os_codename in self.RASPBIAN_CODENAMES
        )
        
        # Debian 코드네임 매핑
        if self._is_ubuntu:
            self._debian_codename = self.UBUNTU_TO_DEBIAN.get(self._os_codename, self._os_codename)
        else:
            self._debian_codename = self._os_codename

    async def _load_ubuntu_cache(self):
        """Ubuntu CVE 캐시 로드"""
        if self.ubuntu_cache_file.exists():
            try:
                with open(self.ubuntu_cache_file, "r", encoding="utf-8") as f:
                    self._ubuntu_cache = json.load(f)
                self._ubuntu_cache_loaded = True
                print(f"Ubuntu CVE 캐시 로드: {len(self._ubuntu_cache)}개 CVE")
            except Exception:
                self._ubuntu_cache = {}

    async def _save_ubuntu_cache(self):
        """Ubuntu CVE 캐시 저장"""
        try:
            with open(self.ubuntu_cache_file, "w", encoding="utf-8") as f:
                json.dump(self._ubuntu_cache, f)
        except Exception:
            pass

    async def _load_from_cache(self) -> bool:
        """캐시 파일에서 로드"""
        try:
            with open(self.cache_file, "r", encoding="utf-8") as f:
                self._data = json.load(f)
            self._loaded_at = time.time()
            print(f"Debian Security 데이터 캐시 로드 완료 ({len(self._data)} 패키지)")
            return True
        except Exception as e:
            print(f"캐시 로드 실패: {e}")
            return await self._download_data()

    async def _download_data(self) -> bool:
        """Debian Security Tracker에서 데이터 다운로드"""
        print("Debian Security Tracker 데이터 다운로드 중...")

        try:
            async with httpx.AsyncClient(timeout=120.0) as client:
                response = await client.get(self.DEBIAN_DATA_URL)
                response.raise_for_status()

                self._data = response.json()
                self._loaded_at = time.time()

                # 캐시 파일로 저장
                self.cache_dir.mkdir(parents=True, exist_ok=True)
                with open(self.cache_file, "w", encoding="utf-8") as f:
                    json.dump(self._data, f)

                print(f"Debian Security 데이터 다운로드 완료 ({len(self._data)} 패키지)")
                return True

        except Exception as e:
            print(f"Debian Security 데이터 다운로드 실패: {e}")
            return False

    def _get_os_codename(self) -> str:
        """현재 OS의 코드네임 반환"""
        self._detect_os()
        return self._os_codename or "bookworm"

    def _get_debian_codename(self) -> str:
        """현재 OS에 대응하는 Debian 코드네임 반환"""
        self._detect_os()
        return self._debian_codename or "bookworm"
    
    def get_distro_id(self) -> str:
        """배포판 ID 반환 (ubuntu, debian, raspbian, alpine 등)"""
        self._detect_os()
        return self._distro_id or "unknown"
    
    def is_raspbian(self) -> bool:
        """Raspbian/Raspberry Pi OS인지 확인"""
        self._detect_os()
        return self._is_raspbian or False

    async def is_patched(self, package_name: str, cve_id: str, installed_version: str) -> Tuple[bool, Optional[str]]:
        """패키지의 CVE가 현재 설치된 버전에서 패치되었는지 확인"""
        status, fixed_version = await self.get_patch_status(package_name, cve_id, installed_version)
        return (status == "not_affected", fixed_version)

    async def get_patch_status(self, package_name: str, cve_id: str, installed_version: str, 
                               allow_api_fallback: bool = False) -> Tuple[str, Optional[str]]:
        """
        패치 상태 반환
        
        우선순위:
        1. Ubuntu 캐시 (ubuntu_security_cache.json)
        2. Debian 캐시 (debian_security_cache.json)  
        3. API 호출 (allow_api_fallback=True일 때만, 기본 비활성)

        Returns:
            (status, fixed_version)
            - status: vulnerable_confirmed | not_affected | unknown
        """
        self._detect_os()
        
        # Ubuntu 계열
        if self._is_ubuntu:
            # 1. Ubuntu 캐시 확인
            status, fixed_version = self._check_ubuntu_patch_status(package_name, cve_id, installed_version)
            if status != "unknown":
                return (status, fixed_version)
        
        # Raspbian/Debian 계열 (Raspbian은 Debian 트래커 직접 사용)
        if self._is_raspbian or self._distro_id in ["debian", "raspbian"]:
            status, fixed_version = self._check_debian_patch_status(
                package_name, cve_id, installed_version, 
                is_raspbian=self._is_raspbian
            )
            if status != "unknown":
                return (status, fixed_version)
            
        # 2. Debian 캐시 확인 (fallback)
        status, fixed_version = self._check_debian_patch_status(package_name, cve_id, installed_version)
        if status != "unknown":
            return (status, fixed_version)
            
        # 3. API 호출 (최후의 수단, 기본 비활성)
        if allow_api_fallback and self._is_ubuntu and cve_id not in self._ubuntu_cache:
            await self.fetch_ubuntu_cve(cve_id)
            return self._check_ubuntu_patch_status(package_name, cve_id, installed_version)
            
        return ("unknown", None)

    def _check_ubuntu_patch_status(self, package_name: str, cve_id: str, installed_version: str) -> Tuple[str, Optional[str]]:
        """Ubuntu CVE 캐시에서 패치 상태 확인"""
        if cve_id not in self._ubuntu_cache:
            return ("unknown", None)

        cve_data = self._ubuntu_cache[cve_id]
        if not isinstance(cve_data, dict):
            return ("unknown", None)
        if cve_data.get("not_found"):
            return ("unknown", None)

        packages = cve_data.get("packages", [])
        if not isinstance(packages, list):
            return ("unknown", None)

        # 패키지 찾기 (소스 패키지명 기준)
        ubuntu_binary_to_source = {
            "libreoffice-common": "libreoffice",
            "libreoffice-core": "libreoffice",
            "libreoffice-writer": "libreoffice",
            "libreoffice-calc": "libreoffice",
            "libreoffice-impress": "libreoffice",
            "libreoffice-draw": "libreoffice",
            "vim": "vim",
            "vim-common": "vim",
            "vim-runtime": "vim",
            "vim-tiny": "vim",
            "vim-gtk": "vim",
        }
        candidates = [package_name]
        mapped = ubuntu_binary_to_source.get(package_name)
        if mapped and mapped not in candidates:
            candidates.append(mapped)
        resolved_source = self._resolve_source_package(package_name)
        if resolved_source and resolved_source not in candidates:
            candidates.append(resolved_source)
        if package_name.startswith("libreoffice-") and "libreoffice" not in candidates:
            candidates.append("libreoffice")

        pkg_info = None
        for info in packages:
            if not isinstance(info, dict):
                continue
            if info.get("name") in candidates:
                pkg_info = info
                break

        if not pkg_info:
            return ("unknown", None)

        # 현재 릴리스의 상태 확인
        os_codename = self._get_os_codename()
        statuses = pkg_info.get("statuses", [])
        if not isinstance(statuses, list):
            return ("unknown", None)

        status_info = None
        for entry in statuses:
            if entry.get("release_codename") == os_codename:
                status_info = entry
                break

        if not status_info:
            return ("unknown", None)

        status = status_info.get("status", "").lower()
        fixed_version = status_info.get("description") or status_info.get("fixed_version")

        strict_vulnerable = {"needed", "pending", "open"}
        if status in strict_vulnerable:
            return ("vulnerable_confirmed", None)

        if status == "released":
            if fixed_version and installed_version and "end of life" not in str(fixed_version).lower():
                if self._compare_versions(installed_version, fixed_version) >= 0:
                    return ("not_affected", fixed_version)
                return ("vulnerable_confirmed", fixed_version)
            return ("not_affected", fixed_version if fixed_version else None)

        if status == "not-affected":
            return ("not_affected", None)

        # needs-triage / undetermined 등은 잠재 이슈로 분류
        return ("unknown", None)

    def _check_debian_patch_status(
        self, 
        package_name: str, 
        cve_id: str, 
        installed_version: str,
        is_raspbian: bool = False
    ) -> Tuple[str, Optional[str]]:
        """Debian/Raspbian Security Tracker에서 패치 상태 확인
        
        Raspbian은 Debian 기반이므로 Debian 트래커를 사용하되,
        버전 비교를 정확히 수행합니다.
        """
        if not self._data:
            return ("unknown", None)

        # 패키지 정보 조회
        pkg_data = self._data.get(package_name)
        if not pkg_data:
            resolved_source = self._resolve_source_package(package_name)
            if resolved_source:
                pkg_data = self._data.get(resolved_source)
            if not pkg_data:
                pkg_data = self._find_by_binary_package(package_name)
            if not pkg_data:
                return ("unknown", None)

        # CVE 정보 조회
        cve_data = pkg_data.get(cve_id)
        if not cve_data:
            return ("unknown", None)

        # 릴리스별 상태 확인
        releases = cve_data.get("releases", {})
        debian_codename = self._get_debian_codename()
        os_codename = self._get_os_codename()

        # 현재 OS에 해당하는 릴리스 찾기 (Raspbian = Debian 코드네임 직접 사용)
        release_info = None
        search_order = [os_codename, debian_codename]
        
        # Raspbian은 bookworm, bullseye 등 Debian 코드네임 직접 사용
        if is_raspbian:
            search_order = [os_codename, "sid", "unstable"]
        
        for codename in search_order:
            if codename in releases:
                release_info = releases[codename]
                break
        
        # 못 찾으면 sid/unstable 확인
        if not release_info:
            for codename in ["sid", "unstable"]:
                if codename in releases:
                    release_info = releases[codename]
                    break

        if not release_info:
            return ("unknown", None)

        status = release_info.get("status", "")
        fixed_version = release_info.get("fixed_version")
        urgency = (release_info.get("urgency") or "").lower()
        nodsa = release_info.get("nodsa")
        nodsa_reason = release_info.get("nodsa_reason")

        # 상태 확인
        if status == "resolved":
            # Ubuntu인 경우: 버전 비교 건너뛰고 상태만 확인
            # (Debian fixed_version은 Ubuntu 버전과 다르므로)
            if self._is_ubuntu and not is_raspbian:
                return ("not_affected", None)

            # Debian/Raspbian인 경우: 버전 비교
            if fixed_version and installed_version:
                if self._compare_versions(installed_version, fixed_version) >= 0:
                    return ("not_affected", fixed_version)
                else:
                    return ("vulnerable_confirmed", fixed_version)
            return ("not_affected", fixed_version)

        elif status == "not-affected":
            return ("not_affected", None)

        elif status in ["open", "undetermined"]:
            if urgency in {"unimportant"} or nodsa or nodsa_reason:
                return ("not_affected", None)
            return ("vulnerable_confirmed", None)

        # 그 외 상태는 영향 없음/조치 불필요로 간주
        return ("not_affected", None)

    def _resolve_source_package(self, binary_name: str) -> Optional[str]:
        """Resolve Debian/Ubuntu source package name from a binary package."""
        if binary_name in self._source_pkg_cache:
            return self._source_pkg_cache[binary_name]

        source_name = None
        try:
            result = subprocess.check_output(
                ["dpkg-query", "-W", "-f=${source:Package}", binary_name],
                stderr=subprocess.DEVNULL,
                timeout=2
            ).decode("utf-8", errors="ignore").strip()
            if result:
                source_name = result
        except Exception:
            source_name = None

        if not source_name:
            try:
                output = subprocess.check_output(
                    ["apt-cache", "show", binary_name],
                    stderr=subprocess.DEVNULL,
                    timeout=2
                ).decode("utf-8", errors="ignore")
                for line in output.splitlines():
                    if line.startswith("Source:"):
                        source_name = line.split(":", 1)[1].strip().split(" ")[0]
                        break
            except Exception:
                source_name = None

        if source_name == binary_name:
            source_name = None

        self._source_pkg_cache[binary_name] = source_name
        return source_name

    async def fetch_ubuntu_cve(self, cve_id: str) -> Optional[Dict]:
        """
        Ubuntu Security API에서 CVE 정보 조회 (캐싱됨)

        첫 스캔 시 느릴 수 있지만, 결과는 캐싱되어 이후 스캔에서 재사용됨
        """
        # 캐시 확인
        if cve_id in self._ubuntu_cache:
            cache_entry = self._ubuntu_cache[cve_id]
            if time.time() - cache_entry.get("_cached_at", 0) < self.cache_ttl:
                return cache_entry

        # API 호출
        url = self.UBUNTU_CVE_API.format(cve_id=cve_id)
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(url)
                if response.status_code == 200:
                    data = response.json()
                    if not isinstance(data, dict):
                        self._ubuntu_cache[cve_id] = {"_cached_at": time.time(), "not_found": True}
                        return None
                    data["_cached_at"] = time.time()
                    self._ubuntu_cache[cve_id] = data
                    # 캐시 저장 (비동기적으로)
                    await self._save_ubuntu_cache()
                    return data
                elif response.status_code == 404:
                    # CVE가 없으면 빈 결과 캐싱
                    self._ubuntu_cache[cve_id] = {"_cached_at": time.time(), "not_found": True}
                    return None
        except Exception:
            pass

        return None

    def _find_by_binary_package(self, binary_name: str) -> Optional[Dict]:
        """바이너리 패키지명으로 소스 패키지 찾기"""
        # 일반적인 매핑 (자주 쓰이는 것들)
        BINARY_TO_SOURCE = {
            "libssl3": "openssl",
            "libssl1.1": "openssl",
            "libssl-dev": "openssl",
            "libcrypto3": "openssl",
            "python3": "python3.x",  # 버전에 따라 다름
            "libc6": "glibc",
            "libc-bin": "glibc",
            "libgcc-s1": "gcc-defaults",
            "libstdc++6": "gcc-defaults",
            "zlib1g": "zlib",
            "libcurl4": "curl",
            "libcurl3-gnutls": "curl",
            "vim": "vim",
            "vim-common": "vim",
            "vim-runtime": "vim",
            "libreoffice": "libreoffice",
            "libreoffice-common": "libreoffice",
        }

        source_name = BINARY_TO_SOURCE.get(binary_name)
        if source_name and source_name in self._data:
            return self._data[source_name]

        # lib 접두사 제거 시도
        if binary_name.startswith("lib"):
            base = binary_name[3:].split("-")[0].rstrip("0123456789.")
            if base in self._data:
                return self._data[base]

        return None

    def _compare_versions(self, v1: str, v2: str) -> int:
        """
        Debian 버전 비교

        Returns:
            -1: v1 < v2
             0: v1 == v2
             1: v1 > v2
        """
        try:
            # dpkg --compare-versions 사용이 가장 정확하지만
            # 여기서는 간단한 비교 구현
            import re

            def parse_version(v):
                # epoch:upstream-debian 형식 분리
                epoch = 0
                if ":" in v:
                    epoch_str, v = v.split(":", 1)
                    epoch = int(epoch_str)

                # upstream-debian 분리
                if "-" in v:
                    parts = v.rsplit("-", 1)
                    upstream = parts[0]
                    debian = parts[1] if len(parts) > 1 else ""
                else:
                    upstream = v
                    debian = ""

                return (epoch, upstream, debian)

            def version_key(part):
                """버전 문자열을 비교 가능한 튜플로 변환"""
                result = []
                for segment in re.split(r'(\d+)', part):
                    if segment.isdigit():
                        result.append((0, int(segment)))
                    elif segment:
                        result.append((1, segment))
                return result

            e1, u1, d1 = parse_version(v1)
            e2, u2, d2 = parse_version(v2)

            # epoch 비교
            if e1 != e2:
                return 1 if e1 > e2 else -1

            # upstream 비교
            k1, k2 = version_key(u1), version_key(u2)
            if k1 != k2:
                return 1 if k1 > k2 else -1

            # debian revision 비교
            k1, k2 = version_key(d1), version_key(d2)
            if k1 != k2:
                return 1 if k1 > k2 else -1

            return 0

        except Exception:
            # 파싱 실패시 문자열 비교
            if v1 == v2:
                return 0
            return 1 if v1 > v2 else -1

    def get_stats(self) -> Dict:
        """캐시 통계 반환"""
        if not self._data:
            return {"loaded": False}

        return {
            "loaded": True,
            "total_packages": len(self._data),
            "cache_age_hours": round((time.time() - self._loaded_at) / 3600, 1),
            "os_codename": self._get_os_codename(),
            "debian_codename": self._get_debian_codename(),
        }
