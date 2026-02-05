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


class VulnerabilityPrioritizer:
    """
    취약점 우선순위 결정기

    여러 지표를 종합하여 취약점의 실제 위험도와 조치 우선순위를 계산합니다.
    """

    def __init__(self):
        pass

    def calculate_priority_score(
        self,
        cvss_score: Optional[float] = None,
        epss_score: Optional[float] = None,
        is_kev: bool = False,
        usage_info: Optional[Dict] = None,
        has_patch_available: bool = False,
        cve_age_days: Optional[int] = None
    ) -> Dict:
        """
        종합 우선순위 점수 계산 (0-100)

        개선된 가중치 (CVSS/EPSS 중심):
        - CVSS (기본 심각도): 40점
        - EPSS (실제 악용 가능성): 35점 (비선형 스케일)
        - 시너지 보너스: 최대 15점 (CVSS High + EPSS High)
        - 사용 상태/KEV/패치: 추가 보너스

        임계값 기반 최소 보장:
        - CVSS >= 9.0: 최소 HIGH
        - EPSS >= 50%: 최소 HIGH
        - CVSS >= 9.0 AND EPSS >= 10%: 최소 CRITICAL
        - KEV 등재: 무조건 CRITICAL
        """
        score = 0.0
        factors = {}

        # 1. CVSS 기여 (0-40점) - 가중치 상향
        cvss_contribution = 0
        if cvss_score is not None:
            cvss_contribution = (cvss_score / 10.0) * 40
            score += cvss_contribution
        factors["cvss_contribution"] = round(cvss_contribution, 1)

        # 2. EPSS 기여 (0-35점) - 비선형 스케일로 높은 값에 더 큰 가중치
        epss_contribution = 0
        if epss_score is not None:
            if epss_score >= 0.5:
                # 50% 이상: 25-35점 (매우 위험)
                epss_contribution = 25 + (epss_score - 0.5) * 20
            elif epss_score >= 0.1:
                # 10-50%: 12-25점 (위험)
                epss_contribution = 12 + (epss_score - 0.1) * 32.5
            elif epss_score >= 0.01:
                # 1-10%: 3-12점 (주의)
                epss_contribution = 3 + (epss_score - 0.01) * 100
            else:
                # 1% 미만: 0-3점
                epss_contribution = epss_score * 300
            score += epss_contribution
        factors["epss_contribution"] = round(epss_contribution, 1)

        # 3. 시너지 보너스: CVSS High + EPSS High = 추가 점수 (최대 15점)
        synergy_bonus = 0
        if cvss_score and cvss_score >= 7.0 and epss_score and epss_score >= 0.05:
            # CVSS 7+ AND EPSS 5%+ 일 때 시너지
            cvss_factor = (cvss_score - 7.0) / 3.0  # 0-1 (7.0->0, 10.0->1)
            epss_factor = min(1.0, epss_score / 0.5)  # 0-1 (0->0, 0.5+->1)
            synergy_bonus = cvss_factor * epss_factor * 15
            score += synergy_bonus
        factors["synergy_bonus"] = round(synergy_bonus, 1)

        # 4. 사용 상태 기여 (0-10점)
        usage_contribution = 0
        if usage_info:
            usage_level = usage_info.get("usage_level", "installed")
            is_listening = usage_info.get("is_listening", False)
            is_running = usage_info.get("is_running", False)

            if usage_level == "active" or is_running:
                usage_contribution = 7
            elif usage_level == "recent":
                usage_contribution = 4
            elif usage_level == "installed":
                usage_contribution = 2

            # 네트워크 리스닝이면 추가
            if is_listening:
                usage_contribution += 3

            usage_contribution = min(usage_contribution, 10)
            score += usage_contribution
        factors["usage_contribution"] = round(usage_contribution, 1)

        # 5. KEV 등재 시 보너스 (+15점, 그리고 최소 CRITICAL 보장)
        kev_bonus = 0
        if is_kev:
            kev_bonus = 15
            score += kev_bonus
        factors["kev_bonus"] = kev_bonus

        # 6. 패치 가능 여부 (패치 가능하면 +5점 - 조치 가능하므로 우선순위 높임)
        patch_bonus = 0
        if has_patch_available:
            patch_bonus = 5
            score += patch_bonus
        factors["patch_bonus"] = patch_bonus

        # ========================================
        # 임계값 기반 최소 점수 보장
        # ========================================
        min_score = 0

        # KEV 등재: 무조건 CRITICAL (최소 80점)
        if is_kev:
            min_score = max(min_score, 80)

        # CVSS Critical (9.0+) AND EPSS 10%+: CRITICAL
        if cvss_score and cvss_score >= 9.0 and epss_score and epss_score >= 0.1:
            min_score = max(min_score, 80)

        # CVSS Critical (9.0+) OR EPSS 50%+: 최소 HIGH
        if cvss_score and cvss_score >= 9.0:
            min_score = max(min_score, 60)
        if epss_score and epss_score >= 0.5:
            min_score = max(min_score, 60)

        # CVSS High (7.0+) AND EPSS 10%+: 최소 HIGH
        if cvss_score and cvss_score >= 7.0 and epss_score and epss_score >= 0.1:
            min_score = max(min_score, 60)

        # 최소 점수 적용
        final_score = max(score, min_score)
        final_score = min(max(final_score, 0), 100)

        # 우선순위 레벨 결정
        if final_score >= 80:
            priority_level = "CRITICAL"
            action = "즉시 패치 필요"
        elif final_score >= 60:
            priority_level = "HIGH"
            action = "긴급 패치 권장"
        elif final_score >= 40:
            priority_level = "MEDIUM"
            action = "계획된 패치 필요"
        else:
            priority_level = "LOW"
            action = "모니터링 권장"

        # 권장 사항 생성
        recommendations = []
        if is_kev:
            recommendations.append("CISA KEV 등재 - 실제 공격에 사용됨")
        if epss_score and epss_score >= 0.5:
            recommendations.append(f"매우 높은 악용 가능성 (EPSS: {epss_score*100:.1f}%)")
        elif epss_score and epss_score >= 0.1:
            recommendations.append(f"높은 악용 가능성 (EPSS: {epss_score*100:.1f}%)")
        if cvss_score and cvss_score >= 9.0:
            recommendations.append(f"CVSS Critical ({cvss_score})")
        if usage_info and usage_info.get("is_listening"):
            recommendations.append(f"네트워크 노출됨 (포트: {usage_info.get('listening_ports', [])})")
        if usage_info and usage_info.get("usage_level") == "active":
            recommendations.append("현재 활성 사용 중")
        if has_patch_available:
            recommendations.append("패치 가능 - apt update로 적용 가능")

        return {
            "priority_score": round(final_score, 1),
            "priority_level": priority_level,
            "action_required": action,
            "factors": factors,
            "recommendations": recommendations
        }

    def sort_by_priority(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """취약점 목록을 우선순위 점수로 정렬"""
        return sorted(
            vulnerabilities,
            key=lambda v: v.get("priority_score", 0),
            reverse=True
        )
