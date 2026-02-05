#!/usr/bin/env python3
"""
기존 CVE 레코드의 EPSS/KEV 정보 일괄 업데이트 스크립트
"""
import asyncio
from sqlalchemy import select
from vulnscan.models.database import async_session_maker
from vulnscan.models.schemas import CVE
from vulnscan.core.epss_client import EPSSClient
from vulnscan.core.kev_client import KEVClient


async def update_epss_kev():
    """모든 CVE의 EPSS/KEV 정보 업데이트"""
    epss_client = EPSSClient()
    kev_client = KEVClient()
    
    # KEV 데이터 초기화
    print("KEV 데이터 로딩...")
    await kev_client.initialize()
    kev_stats = kev_client.get_stats()
    print(f"KEV: {kev_stats.get('total_cves', 0)}개 CVE 로드됨")
    
    async with async_session_maker() as session:
        # EPSS가 없는 CVE 조회
        result = await session.execute(
            select(CVE).where(CVE.epss_score == None)
        )
        cves_without_epss = result.scalars().all()
        
        print(f"\nEPSS 정보 없는 CVE: {len(cves_without_epss)}개")
        
        if cves_without_epss:
            # 배치로 EPSS 조회 (100개씩)
            cve_ids = [cve.cve_id for cve in cves_without_epss]
            print(f"EPSS 점수 조회 중... (총 {len(cve_ids)}개)")
            
            batch_size = 100
            updated_count = 0
            
            for i in range(0, len(cve_ids), batch_size):
                batch = cve_ids[i:i + batch_size]
                epss_results = await epss_client.get_epss_scores_batch(batch)
                
                for cve in cves_without_epss[i:i + batch_size]:
                    epss_data = epss_results.get(cve.cve_id)
                    if epss_data:
                        cve.epss_score = epss_data.get("epss_score")
                        cve.epss_percentile = epss_data.get("epss_percentile")
                        updated_count += 1
                
                await session.commit()
                print(f"  진행: {min(i + batch_size, len(cve_ids))}/{len(cve_ids)} (업데이트: {updated_count})")
            
            print(f"✅ EPSS 업데이트 완료: {updated_count}개")
        
        # KEV 정보 업데이트
        result = await session.execute(
            select(CVE).where(
                (CVE.is_kev == None) | (CVE.is_kev == False)
            )
        )
        cves_to_check_kev = result.scalars().all()
        
        print(f"\nKEV 체크 대상 CVE: {len(cves_to_check_kev)}개")
        
        kev_updated = 0
        for cve in cves_to_check_kev:
            is_kev = kev_client.is_known_exploited(cve.cve_id)
            if is_kev:
                kev_info = kev_client.get_kev_info(cve.cve_id)
                cve.is_kev = True
                cve.kev_date_added = kev_info.get("date_added") if kev_info else None
                cve.kev_due_date = kev_info.get("due_date") if kev_info else None
                cve.kev_ransomware = kev_info.get("known_ransomware", False) if kev_info else False
                kev_updated += 1
        
        await session.commit()
        print(f"✅ KEV 업데이트 완료: {kev_updated}개")
        
        print("\n=== 완료 ===")
        print(f"EPSS 업데이트: {updated_count}개")
        print(f"KEV 발견: {kev_updated}개")


if __name__ == "__main__":
    print("EPSS/KEV 일괄 업데이트 시작...\n")
    asyncio.run(update_epss_kev())
