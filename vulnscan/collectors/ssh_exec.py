"""
SSH Executor - 원격 명령 실행 추상화

보드/타깃에 SSH로 명령을 실행하고 결과를 수집합니다.
시스템 ssh subprocess 우선 사용 (설치 부담 최소화)
대안: asyncssh (pip install asyncssh)
"""

import asyncio
import shutil
import os
from typing import Dict, List, Optional, Tuple, Union
from dataclasses import dataclass, field
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


@dataclass
class SSHConfig:
    """SSH 연결 설정"""
    host: str
    port: int = 22
    username: str = "root"
    auth_method: str = "key"  # key, password
    key_path: Optional[str] = None
    password: Optional[str] = None
    timeout: int = 30  # 연결 타임아웃 (초)
    command_timeout: int = 60  # 명령 실행 타임아웃 (초)
    retry_count: int = 2
    retry_delay: float = 2.0


@dataclass
class CommandResult:
    """명령 실행 결과"""
    command: str
    stdout: str = ""
    stderr: str = ""
    return_code: int = -1
    success: bool = False
    duration_ms: float = 0.0
    error_message: str = ""
    
    def __bool__(self):
        return self.success


class SSHExecutor:
    """
    SSH 원격 명령 실행기
    
    시스템 ssh 명령을 우선 사용하여 설치 부담을 최소화합니다.
    asyncssh가 설치되어 있으면 대안으로 사용 가능합니다.
    """
    
    def __init__(self, config: SSHConfig):
        self.config = config
        self._connected = False
        self._system_ssh_available = self._check_system_ssh()
        self._asyncssh_available = self._check_asyncssh()
        
        # 연결 상태 추적
        self._last_connection_test: Optional[datetime] = None
        self._connection_test_cache_sec = 60  # 1분 캐시
        
    def _check_system_ssh(self) -> bool:
        """시스템 ssh 명령 사용 가능 여부 확인"""
        return shutil.which("ssh") is not None
    
    def _check_sshpass(self) -> bool:
        """sshpass 명령 사용 가능 여부 확인 (비밀번호 인증용)"""
        return shutil.which("sshpass") is not None
    
    def _check_asyncssh(self) -> bool:
        """asyncssh 라이브러리 사용 가능 여부 확인"""
        try:
            import asyncssh
            return True
        except ImportError:
            return False
    
    def get_backend_info(self) -> Dict[str, bool]:
        """사용 가능한 SSH 백엔드 정보"""
        return {
            "system_ssh": self._system_ssh_available,
            "asyncssh": self._asyncssh_available,
            "preferred": "system_ssh" if self._system_ssh_available else "asyncssh"
        }
    
    def _build_ssh_command(self, remote_command: str) -> List[str]:
        """시스템 ssh 명령 빌드"""
        cmd = []
        
        # 비밀번호 인증인 경우 sshpass 사용
        if self.config.auth_method == "password" and self.config.password:
            if self._check_sshpass():
                cmd.extend(["sshpass", "-p", self.config.password])
            else:
                logger.warning("sshpass not installed, password auth may fail. Install with: sudo apt install sshpass")
        
        cmd.append("ssh")
        
        # 옵션들 (보안 + 배치 실행용)
        # 비밀번호 인증일 때는 BatchMode=no
        if self.config.auth_method == "password":
            cmd.extend([
                "-o", "BatchMode=no",
                "-o", "StrictHostKeyChecking=accept-new",
                "-o", f"ConnectTimeout={self.config.timeout}",
                "-o", "ServerAliveInterval=10",
                "-o", "ServerAliveCountMax=3",
                "-o", "PreferredAuthentications=password",
                "-o", "PubkeyAuthentication=no",
            ])
        else:
            cmd.extend([
                "-o", "BatchMode=yes",
                "-o", "StrictHostKeyChecking=accept-new",
                "-o", f"ConnectTimeout={self.config.timeout}",
                "-o", "ServerAliveInterval=10",
                "-o", "ServerAliveCountMax=3",
            ])
        
        # 포트
        if self.config.port != 22:
            cmd.extend(["-p", str(self.config.port)])
        
        # 인증 방식
        if self.config.auth_method == "key" and self.config.key_path:
            cmd.extend(["-i", self.config.key_path])
        
        # 호스트
        cmd.append(f"{self.config.username}@{self.config.host}")
        
        # 원격 명령
        cmd.append(remote_command)
        
        return cmd
    
    async def execute(self, command: str, timeout: Optional[int] = None) -> CommandResult:
        """
        원격 명령 실행
        
        Args:
            command: 실행할 명령
            timeout: 타임아웃 (초), None이면 config.command_timeout 사용
            
        Returns:
            CommandResult: 실행 결과
        """
        timeout = timeout or self.config.command_timeout
        start_time = datetime.now()
        
        if self._system_ssh_available:
            return await self._execute_system_ssh(command, timeout, start_time)
        elif self._asyncssh_available:
            return await self._execute_asyncssh(command, timeout, start_time)
        else:
            return CommandResult(
                command=command,
                error_message="No SSH backend available (neither system ssh nor asyncssh)",
                return_code=-1
            )
    
    async def _execute_system_ssh(
        self, 
        command: str, 
        timeout: int,
        start_time: datetime
    ) -> CommandResult:
        """시스템 ssh를 사용한 명령 실행"""
        ssh_cmd = self._build_ssh_command(command)
        
        for attempt in range(self.config.retry_count + 1):
            try:
                process = await asyncio.create_subprocess_exec(
                    *ssh_cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                try:
                    stdout, stderr = await asyncio.wait_for(
                        process.communicate(),
                        timeout=timeout
                    )
                except asyncio.TimeoutError:
                    process.kill()
                    await process.wait()
                    
                    if attempt < self.config.retry_count:
                        await asyncio.sleep(self.config.retry_delay)
                        continue
                    
                    return CommandResult(
                        command=command,
                        error_message=f"Command timed out after {timeout}s",
                        return_code=-1,
                        duration_ms=(datetime.now() - start_time).total_seconds() * 1000
                    )
                
                duration_ms = (datetime.now() - start_time).total_seconds() * 1000
                
                return CommandResult(
                    command=command,
                    stdout=stdout.decode("utf-8", errors="replace").strip(),
                    stderr=stderr.decode("utf-8", errors="replace").strip(),
                    return_code=process.returncode,
                    success=process.returncode == 0,
                    duration_ms=duration_ms
                )
                
            except Exception as e:
                if attempt < self.config.retry_count:
                    logger.warning(f"SSH attempt {attempt + 1} failed: {e}")
                    await asyncio.sleep(self.config.retry_delay)
                    continue
                
                return CommandResult(
                    command=command,
                    error_message=str(e),
                    return_code=-1,
                    duration_ms=(datetime.now() - start_time).total_seconds() * 1000
                )
        
        return CommandResult(
            command=command,
            error_message="All retry attempts failed",
            return_code=-1
        )
    
    async def _execute_asyncssh(
        self, 
        command: str, 
        timeout: int,
        start_time: datetime
    ) -> CommandResult:
        """asyncssh를 사용한 명령 실행 (대안)"""
        try:
            import asyncssh
        except ImportError:
            return CommandResult(
                command=command,
                error_message="asyncssh not installed",
                return_code=-1
            )
        
        for attempt in range(self.config.retry_count + 1):
            try:
                # 연결 옵션 설정
                connect_kwargs = {
                    "host": self.config.host,
                    "port": self.config.port,
                    "username": self.config.username,
                    "known_hosts": None,  # 호스트 키 체크 비활성화 (내부망)
                }
                
                if self.config.auth_method == "key" and self.config.key_path:
                    connect_kwargs["client_keys"] = [self.config.key_path]
                elif self.config.auth_method == "password" and self.config.password:
                    connect_kwargs["password"] = self.config.password
                
                async with asyncssh.connect(**connect_kwargs) as conn:
                    result = await asyncio.wait_for(
                        conn.run(command, check=False),
                        timeout=timeout
                    )
                    
                    duration_ms = (datetime.now() - start_time).total_seconds() * 1000
                    
                    return CommandResult(
                        command=command,
                        stdout=result.stdout.strip() if result.stdout else "",
                        stderr=result.stderr.strip() if result.stderr else "",
                        return_code=result.exit_status,
                        success=result.exit_status == 0,
                        duration_ms=duration_ms
                    )
                    
            except asyncio.TimeoutError:
                if attempt < self.config.retry_count:
                    await asyncio.sleep(self.config.retry_delay)
                    continue
                return CommandResult(
                    command=command,
                    error_message=f"Command timed out after {timeout}s",
                    return_code=-1,
                    duration_ms=(datetime.now() - start_time).total_seconds() * 1000
                )
            except Exception as e:
                if attempt < self.config.retry_count:
                    logger.warning(f"SSH attempt {attempt + 1} failed: {e}")
                    await asyncio.sleep(self.config.retry_delay)
                    continue
                return CommandResult(
                    command=command,
                    error_message=str(e),
                    return_code=-1,
                    duration_ms=(datetime.now() - start_time).total_seconds() * 1000
                )
        
        return CommandResult(
            command=command,
            error_message="All retry attempts failed",
            return_code=-1
        )
    
    async def test_connection(self, force: bool = False) -> Tuple[bool, str]:
        """
        SSH 연결 테스트
        
        Args:
            force: 캐시 무시하고 강제 테스트
            
        Returns:
            (성공여부, 메시지)
        """
        # 캐시된 결과 사용 (1분 이내)
        if not force and self._last_connection_test:
            elapsed = (datetime.now() - self._last_connection_test).total_seconds()
            if elapsed < self._connection_test_cache_sec and self._connected:
                return True, "Connection test cached (success)"
        
        result = await self.execute("echo 'connection_test'", timeout=10)
        
        self._last_connection_test = datetime.now()
        self._connected = result.success and "connection_test" in result.stdout
        
        if self._connected:
            return True, f"Connected successfully (backend: {self.get_backend_info()['preferred']})"
        else:
            return False, f"Connection failed: {result.error_message or result.stderr}"
    
    async def execute_if_exists(
        self, 
        check_command: str, 
        main_command: str,
        fallback_result: str = ""
    ) -> CommandResult:
        """
        명령이 존재하면 실행, 없으면 스킵 (보드 설치 최소화 원칙)
        
        Args:
            check_command: 존재 확인 명령 (예: "which apk")
            main_command: 실행할 명령 (예: "apk info -v")
            fallback_result: 명령이 없을 때 반환할 stdout
            
        Returns:
            CommandResult
        """
        # 먼저 명령 존재 여부 확인
        check_result = await self.execute(check_command, timeout=5)
        
        if not check_result.success:
            # 명령이 없음 - 스킵
            return CommandResult(
                command=main_command,
                stdout=fallback_result,
                return_code=0,
                success=True,
                error_message="Command not available - skipped"
            )
        
        # 명령 실행
        return await self.execute(main_command)
    
    async def execute_batch(
        self, 
        commands: List[str], 
        stop_on_error: bool = False
    ) -> List[CommandResult]:
        """
        여러 명령 순차 실행
        
        Args:
            commands: 실행할 명령 목록
            stop_on_error: True면 오류 시 중단
            
        Returns:
            List[CommandResult]
        """
        results = []
        
        for cmd in commands:
            result = await self.execute(cmd)
            results.append(result)
            
            if stop_on_error and not result.success:
                break
        
        return results
    
    async def read_file(self, remote_path: str) -> CommandResult:
        """원격 파일 읽기"""
        return await self.execute(f"cat {remote_path}")
    
    async def file_exists(self, remote_path: str) -> bool:
        """원격 파일 존재 여부 확인"""
        result = await self.execute(f"test -f {remote_path} && echo 'exists'")
        return result.success and "exists" in result.stdout
    
    async def command_exists(self, command_name: str) -> bool:
        """원격 명령 존재 여부 확인"""
        result = await self.execute(f"which {command_name} 2>/dev/null || command -v {command_name} 2>/dev/null")
        return result.success and len(result.stdout) > 0


def create_ssh_executor(
    host: str,
    port: int = 22,
    username: str = "root",
    auth_method: str = "key",
    key_path: Optional[str] = None,
    password: Optional[str] = None,
    timeout: int = 30
) -> SSHExecutor:
    """SSH Executor 팩토리 함수"""
    config = SSHConfig(
        host=host,
        port=port,
        username=username,
        auth_method=auth_method,
        key_path=key_path,
        password=password,
        timeout=timeout
    )
    return SSHExecutor(config)


def create_ssh_executor_from_host(host_model) -> SSHExecutor:
    """Host 모델에서 SSH Executor 생성"""
    config = SSHConfig(
        host=host_model.ip_address,
        port=host_model.ssh_port or 22,
        username=host_model.ssh_username or "root",
        auth_method=host_model.auth_method or "key",
        key_path=host_model.ssh_key_path,
        password=getattr(host_model, 'ssh_password', None)  # 비밀번호 추가
    )
    return SSHExecutor(config)
