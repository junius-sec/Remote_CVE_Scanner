"""
Collectors 패키지

원격 자산 수집을 위한 모듈:
- ssh_exec: SSH 명령 실행 추상화
- discovery: OS/환경 식별
- deepscan: 패키지/바이너리 수집
"""

from .ssh_exec import SSHExecutor, SSHConfig, CommandResult, create_ssh_executor, create_ssh_executor_from_host
from .discovery import DiscoveryCollector, DiscoveryResult
from .deepscan import DeepScanCollector, DeepScanResult

__all__ = [
    "SSHExecutor",
    "SSHConfig", 
    "CommandResult",
    "create_ssh_executor",
    "create_ssh_executor_from_host",
    "DiscoveryCollector",
    "DiscoveryResult",
    "DeepScanCollector",
    "DeepScanResult",
]
