#!/usr/bin/env python3
"""
간단한 스캔 트리거 스크립트 - UI 스캔 시뮬레이션
"""
import asyncio
import sys
from pathlib import Path

# 프로젝트 루트를 sys.path에 추가
sys.path.insert(0, str(Path(__file__).parent))

from vulnscan.models.database import async_session_maker, init_db
from vulnscan.core.matcher import VulnerabilityMatcher
from vulnscan.core.nvd_client import NVDClient
from vulnscan.core.epss_client import EPSSClient
from vulnscan.core.kev_client import KEVClient
from vulnscan.core.exploit_client import ExploitClient
from vulnscan.core.debian_security_client import DebianSecurityClient
from vulnscan.parsers.dpkg import DpkgParser

async def quick_scan():
    """빠른 스캔 실행"""
    await init_db()
    
    async with async_session_maker() as session:
        # Matcher 초기화
        matcher = VulnerabilityMatcher(
            nvd_client=NVDClient(),
            epss_client=EPSSClient(),
            kev_client=KEVClient(),
            debian_security_client=DebianSecurityClient()
        )
        
        # KEV 초기화
        await matcher.kev_client.initialize()
        
        print("✅ 스캔 시작...")
        
        # 최소한의 패키지로 스캔 (glibc만)
        packages = [
            {
                "name": "libc6",
                "version": "2.36-9+rpt2+deb12u9",
                "architecture": "arm64"
            }
        ]
        
        # 스캔 실행
        stats = await matcher.match_package_vulnerabilities(
            session=session,
            packages=packages,
            os_name="debian",
            os_version="12",
            architecture="arm64",
            kernel_version="6.12.62",
            hostname="test-host"
        )
        
        print(f"✅ 스캔 완료: {stats}")
        
        # EPSS 확인
        from sqlalchemy import select, func
        from vulnscan.models.schemas import CVE
        
        result = await session.execute(
            select(CVE.cve_id, CVE.epss_score)
            .where(CVE.cve_id.in_(['CVE-2023-7216', 'CVE-2023-4039', 'CVE-2021-3538']))
        )
        
        print("\n=== 테스트 CVE EPSS 상태 ===")
        for row in result:
            print(f"{row.cve_id}: {row.epss_score}")
        
        # NULL인 CVE 개수 확인
        null_count = await session.execute(
            select(func.count()).select_from(CVE).where(CVE.epss_score == None)
        )
        print(f"\nEPSS가 NULL인 CVE 개수: {null_count.scalar()}")

if __name__ == "__main__":
    asyncio.run(quick_scan())
