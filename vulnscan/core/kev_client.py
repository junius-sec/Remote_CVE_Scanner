"""
CISA KEV (Known Exploited Vulnerabilities) Client

CISA에서 관리하는 실제로 악용된 취약점 목록을 가져옵니다.
KEV에 등재된 CVE는 즉시 패치가 필요합니다.

데이터 출처: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
라이센스: 공개 데이터 (제한 없음)
"""

import httpx
import asyncio
import json
import time
from typing import Dict, List, Optional, Set
from pathlib import Path
from datetime import datetime


class KEVClient:
    """CISA Known Exploited Vulnerabilities 클라이언트"""

    KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def __init__(self, cache_dir: Optional[str] = None):
        self.cache_dir = Path(cache_dir) if cache_dir else Path(".")
        self.cache_file = self.cache_dir / "kev_cache.json"
        self.cache_ttl = 86400  # 24시간

        # 메모리 캐시
        self._kev_set: Set[str] = set()
        self._kev_data: Dict[str, Dict] = {}
        self._loaded_at: float = 0
        self._catalog_version: str = ""
        self._total_count: int = 0

    async def initialize(self) -> bool:
        """KEV 데이터 초기화 (다운로드 또는 캐시 로드)"""
        # 이미 로드됨
        if self._kev_set and (time.time() - self._loaded_at) < self.cache_ttl:
            return True

        # 캐시 파일 확인
        if self.cache_file.exists():
            cache_age = time.time() - self.cache_file.stat().st_mtime
            if cache_age < self.cache_ttl:
                return await self._load_from_cache()

        # 새로 다운로드
        return await self._download_data()

    async def _load_from_cache(self) -> bool:
        """캐시 파일에서 로드"""
        try:
            with open(self.cache_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            self._catalog_version = data.get("catalogVersion", "")
            self._total_count = data.get("count", 0)

            for vuln in data.get("vulnerabilities", []):
                cve_id = vuln.get("cveID", "").upper()
                if cve_id:
                    self._kev_set.add(cve_id)
                    self._kev_data[cve_id] = {
                        "cve_id": cve_id,
                        "vendor": vuln.get("vendorProject", ""),
                        "product": vuln.get("product", ""),
                        "name": vuln.get("vulnerabilityName", ""),
                        "date_added": vuln.get("dateAdded", ""),
                        "due_date": vuln.get("dueDate", ""),
                        "short_description": vuln.get("shortDescription", ""),
                        "required_action": vuln.get("requiredAction", ""),
                        "known_ransomware": vuln.get("knownRansomwareCampaignUse", "Unknown") == "Known"
                    }

            self._loaded_at = time.time()
            print(f"KEV 데이터 캐시 로드 완료 ({len(self._kev_set)}개 CVE)")
            return True
        except Exception as e:
            print(f"KEV 캐시 로드 실패: {e}")
            return await self._download_data()

    async def _download_data(self) -> bool:
        """CISA에서 KEV 데이터 다운로드"""
        print("KEV (Known Exploited Vulnerabilities) 데이터 다운로드 중...")

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.get(self.KEV_URL)
                response.raise_for_status()

                data = response.json()

                # 캐시 파일로 저장
                self.cache_dir.mkdir(parents=True, exist_ok=True)
                with open(self.cache_file, "w", encoding="utf-8") as f:
                    json.dump(data, f)

                self._catalog_version = data.get("catalogVersion", "")
                self._total_count = data.get("count", 0)

                for vuln in data.get("vulnerabilities", []):
                    cve_id = vuln.get("cveID", "").upper()
                    if cve_id:
                        self._kev_set.add(cve_id)
                        self._kev_data[cve_id] = {
                            "cve_id": cve_id,
                            "vendor": vuln.get("vendorProject", ""),
                            "product": vuln.get("product", ""),
                            "name": vuln.get("vulnerabilityName", ""),
                            "date_added": vuln.get("dateAdded", ""),
                            "due_date": vuln.get("dueDate", ""),
                            "short_description": vuln.get("shortDescription", ""),
                            "required_action": vuln.get("requiredAction", ""),
                            "known_ransomware": vuln.get("knownRansomwareCampaignUse", "Unknown") == "Known"
                        }

                self._loaded_at = time.time()
                print(f"KEV 데이터 다운로드 완료 ({len(self._kev_set)}개 CVE)")
                return True

        except Exception as e:
            print(f"KEV 데이터 다운로드 실패: {e}")
            return False

    def is_known_exploited(self, cve_id: str) -> bool:
        """CVE가 KEV에 등재되어 있는지 확인"""
        return cve_id.upper() in self._kev_set

    def get_kev_info(self, cve_id: str) -> Optional[Dict]:
        """KEV에 등재된 CVE의 상세 정보 반환"""
        return self._kev_data.get(cve_id.upper())

    def check_multiple(self, cve_ids: List[str]) -> Dict[str, bool]:
        """여러 CVE의 KEV 등재 여부 확인"""
        return {
            cve_id: self.is_known_exploited(cve_id)
            for cve_id in cve_ids
        }

    def get_kev_cves_from_list(self, cve_ids: List[str]) -> List[Dict]:
        """주어진 CVE 목록 중 KEV에 등재된 것들의 상세 정보 반환"""
        kev_cves = []
        for cve_id in cve_ids:
            info = self.get_kev_info(cve_id)
            if info:
                kev_cves.append(info)
        return kev_cves

    def get_stats(self) -> Dict:
        """KEV 통계 반환"""
        if not self._kev_set:
            return {"loaded": False}

        # 랜섬웨어 관련 CVE 수
        ransomware_count = sum(
            1 for v in self._kev_data.values()
            if v.get("known_ransomware")
        )

        return {
            "loaded": True,
            "total_cves": len(self._kev_set),
            "catalog_version": self._catalog_version,
            "ransomware_related": ransomware_count,
            "cache_age_hours": round((time.time() - self._loaded_at) / 3600, 1)
        }


