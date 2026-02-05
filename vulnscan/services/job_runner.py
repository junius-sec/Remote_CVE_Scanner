"""
Job Runner - 비동기 스캔 작업 관리

기능:
- 스캔 작업 큐 관리
- 호스트당 1 job 제한
- 전체 동시 실행 제한 (기본 3)
- 작업 상태 추적 및 로깅
"""

import asyncio
import json
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class ScanPreset(Enum):
    """스캔 프리셋"""
    FAST = "fast"
    STANDARD = "standard"
    DEEP = "deep"


@dataclass
class ScanConfig:
    """스캔 설정"""
    preset: ScanPreset = ScanPreset.STANDARD
    
    # Discovery 옵션
    discovery_timeout: int = 30
    
    # DeepScan 옵션
    collect_packages: bool = True
    collect_binaries: bool = False  # deep에서만 True
    collect_kernel_info: bool = True
    
    # CVE 분석 옵션
    filter_patched: bool = True
    filter_old_cve: bool = True
    filter_other_os: bool = True
    categories: List[str] = field(default_factory=lambda: ["all"])
    cve_years: Optional[int] = None  # CVE 검색 시작 년도 (예: 2024), None = 전체 기간
    
    # 포트 스캔 옵션 (deep에서만)
    enable_port_scan: bool = False
    port_scan_ports: List[int] = field(default_factory=lambda: [22, 80, 443, 8080])
    
    @classmethod
    def from_preset(cls, preset: ScanPreset) -> "ScanConfig":
        """프리셋에서 설정 생성"""
        if preset == ScanPreset.FAST:
            return cls(
                preset=preset,
                discovery_timeout=15,
                collect_packages=True,
                collect_binaries=False,
                collect_kernel_info=False,
                filter_patched=True,
                filter_old_cve=True,
                categories=["security", "system"],  # 주요 카테고리만
            )
        elif preset == ScanPreset.DEEP:
            return cls(
                preset=preset,
                discovery_timeout=60,
                collect_packages=True,
                collect_binaries=True,
                collect_kernel_info=True,
                filter_patched=True,
                filter_old_cve=False,  # 오래된 CVE도 포함
                categories=["all"],
                enable_port_scan=False,  # 명시적 요청 시만
            )
        else:  # STANDARD
            return cls(
                preset=preset,
                discovery_timeout=30,
                collect_packages=True,
                collect_binaries=False,
                collect_kernel_info=True,
                filter_patched=True,
                filter_old_cve=True,
                categories=["all"],
            )


@dataclass
class JobState:
    """작업 상태"""
    job_id: int
    host_id: int
    status: str = "pending"  # pending, running, completed, failed, cancelled
    phase: str = ""  # discovery, deepscan, cve_analysis, complete
    progress: int = 0
    message: str = ""
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error: Optional[str] = None
    result: Optional[Dict] = None


class JobRunner:
    """
    비동기 스캔 작업 관리자
    
    사용 예시:
    ```python
    runner = JobRunner(max_concurrent=3)
    await runner.start()
    
    job_id = await runner.submit_job(host_id=1, preset=ScanPreset.STANDARD)
    status = runner.get_job_status(job_id)
    
    await runner.stop()
    ```
    """
    
    def __init__(
        self,
        max_concurrent: int = 3,
        max_per_host: int = 1
    ):
        """
        Args:
            max_concurrent: 전체 동시 실행 가능 작업 수
            max_per_host: 호스트당 동시 실행 가능 작업 수
        """
        self.max_concurrent = max_concurrent
        self.max_per_host = max_per_host
        
        # 작업 관리
        self._queue: asyncio.Queue = asyncio.Queue()
        self._jobs: Dict[int, JobState] = {}
        self._host_jobs: Dict[int, List[int]] = {}  # host_id -> [job_ids]
        
        # 동시성 제어
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._host_locks: Dict[int, asyncio.Lock] = {}
        
        # 러너 상태
        self._running = False
        self._workers: List[asyncio.Task] = []
        self._job_counter = 0
        
        # 콜백
        self._on_job_complete: Optional[Callable] = None
        self._on_job_progress: Optional[Callable] = None
    
    async def start(self, num_workers: int = 3):
        """러너 시작"""
        if self._running:
            return
        
        self._running = True
        
        # 워커 태스크 생성
        for i in range(num_workers):
            worker = asyncio.create_task(self._worker(i))
            self._workers.append(worker)
        
        logger.info(f"JobRunner started with {num_workers} workers")
    
    async def stop(self):
        """러너 중지"""
        self._running = False
        
        # 워커 종료
        for worker in self._workers:
            worker.cancel()
        
        await asyncio.gather(*self._workers, return_exceptions=True)
        self._workers.clear()
        
        logger.info("JobRunner stopped")
    
    async def submit_job(
        self,
        host_id: int,
        config: ScanConfig,
        initiated_by: str = "system",
        db_session = None
    ) -> int:
        """
        스캔 작업 제출
        
        Args:
            host_id: 대상 호스트 ID
            config: 스캔 설정
            initiated_by: 요청자
            db_session: DB 세션 (ScanJob 레코드 생성용)
            
        Returns:
            int: 작업 ID
        """
        # 호스트당 동시 실행 제한 확인
        if host_id in self._host_jobs:
            running_jobs = [
                jid for jid in self._host_jobs[host_id]
                if self._jobs.get(jid, {}).status in ("pending", "running")
            ]
            if len(running_jobs) >= self.max_per_host:
                raise ValueError(f"Host {host_id} already has {len(running_jobs)} running jobs")
        
        # 작업 ID 생성
        self._job_counter += 1
        job_id = self._job_counter
        
        # 작업 상태 초기화
        state = JobState(
            job_id=job_id,
            host_id=host_id,
            status="pending"
        )
        self._jobs[job_id] = state
        
        # 호스트별 작업 추적
        if host_id not in self._host_jobs:
            self._host_jobs[host_id] = []
        self._host_jobs[host_id].append(job_id)
        
        # DB에 ScanJob 레코드 생성 (세션이 있으면)
        if db_session:
            await self._create_scan_job_record(
                db_session, job_id, host_id, config, initiated_by
            )
        
        # 큐에 추가
        await self._queue.put((job_id, host_id, config, db_session))
        
        logger.info(f"Job {job_id} submitted for host {host_id}")
        return job_id
    
    async def _create_scan_job_record(
        self,
        session,
        job_id: int,
        host_id: int,
        config: ScanConfig,
        initiated_by: str
    ):
        """DB에 ScanJob 레코드 생성"""
        from ..models.schemas import ScanJob
        
        scan_job = ScanJob(
            id=job_id,
            host_id=host_id,
            status="pending",
            preset=config.preset.value,
            initiated_by=initiated_by,
            created_at=datetime.now(KST)
        )
        session.add(scan_job)
        await session.flush()
    
    def get_job_status(self, job_id: int) -> Optional[Dict]:
        """작업 상태 조회"""
        state = self._jobs.get(job_id)
        if not state:
            return None
        
        return {
            "job_id": state.job_id,
            "host_id": state.host_id,
            "status": state.status,
            "phase": state.phase,
            "progress": state.progress,
            "message": state.message,
            "started_at": state.started_at.isoformat() if state.started_at else None,
            "completed_at": state.completed_at.isoformat() if state.completed_at else None,
            "error": state.error,
        }
    
    def get_all_jobs(self, status: Optional[str] = None) -> List[Dict]:
        """모든 작업 조회"""
        jobs = []
        for state in self._jobs.values():
            if status and state.status != status:
                continue
            jobs.append(self.get_job_status(state.job_id))
        return jobs
    
    def get_host_jobs(self, host_id: int) -> List[Dict]:
        """특정 호스트의 작업 조회"""
        job_ids = self._host_jobs.get(host_id, [])
        return [self.get_job_status(jid) for jid in job_ids if jid in self._jobs]
    
    async def cancel_job(self, job_id: int) -> bool:
        """작업 취소"""
        state = self._jobs.get(job_id)
        if not state:
            return False
        
        if state.status in ("completed", "failed", "cancelled"):
            return False
        
        state.status = "cancelled"
        state.completed_at = datetime.utcnow()
        state.message = "Cancelled by user"
        
        logger.info(f"Job {job_id} cancelled")
        return True
    
    def set_on_complete(self, callback: Callable):
        """작업 완료 콜백 설정"""
        self._on_job_complete = callback
    
    def set_on_progress(self, callback: Callable):
        """진행상황 콜백 설정"""
        self._on_job_progress = callback
    
    async def _worker(self, worker_id: int):
        """워커 태스크"""
        logger.info(f"Worker {worker_id} started")
        
        while self._running:
            try:
                # 큐에서 작업 가져오기 (타임아웃 1초)
                try:
                    job_data = await asyncio.wait_for(
                        self._queue.get(),
                        timeout=1.0
                    )
                except asyncio.TimeoutError:
                    continue
                
                job_id, host_id, config, db_session = job_data
                state = self._jobs.get(job_id)
                
                if not state or state.status == "cancelled":
                    continue
                
                # 동시성 제어
                async with self._semaphore:
                    await self._execute_job(job_id, host_id, config, db_session)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.exception(f"Worker {worker_id} error: {e}")
        
        logger.info(f"Worker {worker_id} stopped")
    
    async def _execute_job(
        self,
        job_id: int,
        host_id: int,
        config: ScanConfig,
        db_session
    ):
        """작업 실행"""
        state = self._jobs.get(job_id)
        if not state:
            return
        
        # 상태 업데이트
        state.status = "running"
        state.started_at = datetime.now(KST)
        
        try:
            # RemoteScanner로 실제 스캔 수행
            from .remote_scanner import RemoteScanner
            
            scanner = RemoteScanner(host_id, config, db_session)
            
            # 진행상황 콜백 연결
            scanner.set_progress_callback(
                lambda phase, progress, msg: self._update_progress(
                    job_id, phase, progress, msg
                )
            )
            
            # 스캔 실행
            result = await scanner.run()
            
            # 완료
            state.status = "completed"
            state.phase = "complete"
            state.progress = 100
            state.result = result
            state.completed_at = datetime.now(KST)
            
            logger.info(f"Job {job_id} completed successfully")
            
        except Exception as e:
            state.status = "failed"
            state.error = str(e)
            state.completed_at = datetime.now(KST)
            logger.exception(f"Job {job_id} failed: {e}")
        
        # 완료 콜백 호출
        if self._on_job_complete:
            await self._on_job_complete(job_id, state)
    
    def _update_progress(
        self,
        job_id: int,
        phase: str,
        progress: int,
        message: str
    ):
        """진행상황 업데이트"""
        state = self._jobs.get(job_id)
        if state:
            state.phase = phase
            state.progress = progress
            state.message = message
            
            # 콜백 호출
            if self._on_job_progress:
                asyncio.create_task(
                    self._on_job_progress(job_id, phase, progress, message)
                )


# 글로벌 JobRunner 인스턴스 (싱글톤)
_job_runner: Optional[JobRunner] = None


def get_job_runner() -> JobRunner:
    """글로벌 JobRunner 인스턴스 반환"""
    global _job_runner
    if _job_runner is None:
        _job_runner = JobRunner()
    return _job_runner


async def init_job_runner(max_concurrent: int = 3):
    """글로벌 JobRunner 초기화 및 시작"""
    global _job_runner
    _job_runner = JobRunner(max_concurrent=max_concurrent)
    await _job_runner.start()
    return _job_runner
