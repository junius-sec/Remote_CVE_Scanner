"""EPSS (Exploit Prediction Scoring System) API Client - 캐시 없는 순수 배치 조회"""
import httpx
import asyncio
from typing import Dict, List, Optional


class EPSSClient:
    """
    FIRST.org EPSS API 클라이언트
    EPSS는 CVE가 실제로 익스플로잇될 확률을 예측하는 점수 시스템
    - epss_score: 0.0 ~ 1.0 (30일 내 익스플로잇 확률)
    - epss_percentile: 백분위 (다른 CVE 대비 순위)
    
    캐시 없음 - 항상 최신 데이터 조회
    """

    BASE_URL = "https://api.first.org/data/v1/epss"

    def __init__(self):
        # Rate limiting
        self._semaphore = asyncio.Semaphore(10)
        self._rate_limit_delay = 0.2
        print("[EPSS] 클라이언트 초기화 (캐시 없음, 실시간 조회)")

    async def get_epss_score(self, cve_id: str) -> Optional[Dict]:
        """단일 CVE의 EPSS 점수 조회 (캐시 없음)"""
        result = await self._fetch_epss([cve_id])
        if result and cve_id.upper() in result:
            return result[cve_id.upper()]
        return None

    async def get_epss_scores_batch(self, cve_ids: List[str]) -> Dict[str, Dict]:
        """여러 CVE의 EPSS 점수 일괄 조회 (캐시 없음, 최대 100개씩)"""
        if not cve_ids:
            return {}

        results = {}
        batch_size = 100
        
        for i in range(0, len(cve_ids), batch_size):
            batch = cve_ids[i:i + batch_size]
            batch_results = await self._fetch_epss(batch)
            results.update(batch_results)
            
            if i + batch_size < len(cve_ids):
                await asyncio.sleep(0.1)

        return results

    async def _fetch_epss(self, cve_ids: List[str]) -> Dict[str, Dict]:
        """EPSS API에서 데이터 가져오기"""
        async with self._semaphore:
            await asyncio.sleep(self._rate_limit_delay)

            try:
                cve_param = ",".join([cve.upper() for cve in cve_ids])
                print(f"[EPSS] API 호출: {len(cve_ids)}개 CVE 조회 중...")

                async with httpx.AsyncClient(timeout=30.0) as client:
                    response = await client.get(
                        self.BASE_URL,
                        params={"cve": cve_param}
                    )
                    response.raise_for_status()
                    data = response.json()

                results = {}
                for item in data.get("data", []):
                    cve_id = item.get("cve", "").upper()
                    if cve_id:
                        results[cve_id] = {
                            "cve_id": cve_id,
                            "epss_score": float(item.get("epss", 0)),
                            "epss_percentile": float(item.get("percentile", 0))
                        }

                print(f"[EPSS] API 응답: {len(results)}개 CVE 데이터 수신")
                return results

            except httpx.HTTPStatusError as e:
                print(f"[EPSS] HTTP 오류: {e.response.status_code}")
                return {}
            except httpx.HTTPError as e:
                print(f"[EPSS] 연결 오류: {e}")
                return {}
            except Exception as e:
                print(f"[EPSS] 오류: {e}")
                return {}

    def get_risk_priority(self, cvss_score: Optional[float], epss_score: Optional[float]) -> str:
        """CVSS와 EPSS 기반 위험 우선순위 계산"""
        cvss = cvss_score or 0
        epss = epss_score or 0

        if cvss >= 9.0 and epss >= 0.5:
            return "CRITICAL"
        elif (cvss >= 7.0 and epss >= 0.3) or cvss >= 9.0:
            return "HIGH"
        elif cvss >= 4.0 or epss >= 0.1:
            return "MEDIUM"
        else:
            return "LOW"


_epss_client: Optional[EPSSClient] = None

def get_epss_client() -> EPSSClient:
    """Get or create EPSS client singleton"""
    global _epss_client
    if _epss_client is None:
        _epss_client = EPSSClient()
    return _epss_client
