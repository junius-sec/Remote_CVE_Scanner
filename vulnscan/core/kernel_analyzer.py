"""
Kernel and Module Vulnerability Analyzer

커널 버전과 로드된 모듈에 대한 취약점을 분석합니다.
"""

import asyncio
import re
from typing import Dict, List, Optional, Tuple
from datetime import datetime


class KernelAnalyzer:
    """커널 및 모듈 취약점 분석기"""

    # 권한 상승 관련 CWE 목록
    PRIVESC_CWES = {
        "CWE-269": "Improper Privilege Management",
        "CWE-250": "Execution with Unnecessary Privileges",
        "CWE-266": "Incorrect Privilege Assignment",
        "CWE-274": "Improper Handling of Insufficient Privileges",
        "CWE-732": "Incorrect Permission Assignment for Critical Resource",
        "CWE-863": "Incorrect Authorization",
        "CWE-862": "Missing Authorization",
        "CWE-284": "Improper Access Control",
        "CWE-264": "Permissions, Privileges, and Access Controls",
    }

    # 커널 관련 패키지 패턴
    KERNEL_PATTERNS = [
        r'^linux-image-\d+',
        r'^linux-headers-\d+',
        r'^linux-modules-\d+',
        r'^kernel-\d+',
        r'^linux-generic',
        r'^linux-lowlatency',
        r'^linux-kernel$',  # 커널 분석에서 생성된 가상 패키지
        r'^linux_kernel$',
    ]

    def __init__(self):
        self._kernel_info: Optional[Dict] = None
        self._loaded_modules: Optional[List[Dict]] = None

    async def get_kernel_info(self) -> Dict:
        """현재 커널 정보 수집"""
        if self._kernel_info:
            return self._kernel_info

        info = {
            "version": None,
            "release": None,
            "architecture": None,
            "full_version": None,
            "distribution": None,
            "distro_kernel_version": None,
        }

        try:
            # uname -r: 커널 릴리즈 버전
            proc = await asyncio.create_subprocess_exec(
                "uname", "-r",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()
            if proc.returncode == 0:
                info["release"] = stdout.decode().strip()
                # 버전 파싱 (예: 6.8.0-90-generic -> 6.8.0)
                version_match = re.match(r'^(\d+\.\d+\.\d+)', info["release"])
                if version_match:
                    info["version"] = version_match.group(1)

            # uname -m: 아키텍처
            proc = await asyncio.create_subprocess_exec(
                "uname", "-m",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()
            if proc.returncode == 0:
                info["architecture"] = stdout.decode().strip()

            # uname -a: 전체 정보
            proc = await asyncio.create_subprocess_exec(
                "uname", "-a",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()
            if proc.returncode == 0:
                info["full_version"] = stdout.decode().strip()

            # /etc/os-release에서 배포판 정보
            proc = await asyncio.create_subprocess_exec(
                "cat", "/etc/os-release",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()
            if proc.returncode == 0:
                for line in stdout.decode().split('\n'):
                    if line.startswith('ID='):
                        info["distribution"] = line.split('=')[1].strip('"')
                    elif line.startswith('VERSION_ID='):
                        info["distro_kernel_version"] = line.split('=')[1].strip('"')

        except Exception as e:
            pass

        self._kernel_info = info
        return info

    async def get_loaded_modules(self) -> List[Dict]:
        """로드된 커널 모듈 목록 수집"""
        if self._loaded_modules:
            return self._loaded_modules

        modules = []

        try:
            # lsmod로 로드된 모듈 목록 가져오기
            proc = await asyncio.create_subprocess_exec(
                "lsmod",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()

            if proc.returncode == 0:
                lines = stdout.decode().strip().split('\n')[1:]  # 헤더 제외

                for line in lines:
                    parts = line.split()
                    if len(parts) >= 3:
                        module_name = parts[0]
                        size = int(parts[1])
                        used_by = int(parts[2])
                        dependencies = parts[3].split(',') if len(parts) > 3 else []

                        modules.append({
                            "name": module_name,
                            "size": size,
                            "used_count": used_by,
                            "dependencies": [d for d in dependencies if d != '-'],
                        })

        except Exception:
            pass

        self._loaded_modules = modules
        return modules

    async def get_module_info(self, module_name: str) -> Optional[Dict]:
        """특정 모듈의 상세 정보"""
        try:
            proc = await asyncio.create_subprocess_exec(
                "modinfo", module_name,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()

            if proc.returncode == 0:
                info = {"name": module_name}
                for line in stdout.decode().strip().split('\n'):
                    if ':' in line:
                        key, value = line.split(':', 1)
                        key = key.strip().lower().replace(' ', '_')
                        info[key] = value.strip()
                return info
        except Exception:
            pass
        return None

    def is_kernel_package(self, package_name: str) -> bool:
        """패키지가 커널 관련 패키지인지 확인"""
        for pattern in self.KERNEL_PATTERNS:
            if re.match(pattern, package_name, re.IGNORECASE):
                return True
        return False

    def is_privilege_escalation_cve(self, cve_data: Dict) -> Tuple[bool, str]:
        """
        CVE가 권한 상승 취약점인지 분석

        Returns:
            (is_privesc, reason)
        """
        reasons = []

        # 1. Scope가 CHANGED이면 권한 상승 가능성 높음
        if cve_data.get("scope") == "CHANGED":
            reasons.append("Scope changed (다른 컴포넌트에 영향)")

        # 2. 낮은 권한으로 높은 영향을 줄 수 있는 경우
        priv_req = cve_data.get("privileges_required", "").upper()
        if priv_req in ["NONE", "LOW"]:
            conf_impact = cve_data.get("confidentiality_impact", "").upper()
            int_impact = cve_data.get("integrity_impact", "").upper()

            if conf_impact == "HIGH" or int_impact == "HIGH":
                reasons.append(f"Low privilege ({priv_req}) -> High impact")

        # 3. 로컬 공격 + 권한 필요 없음
        attack_vector = cve_data.get("attack_vector", "").upper()
        if attack_vector == "LOCAL" and priv_req == "NONE":
            reasons.append("Local attack without privileges required")

        # 4. 설명에서 권한 상승 키워드 확인
        description = cve_data.get("description", "").lower()
        privesc_keywords = [
            "privilege escalation",
            "privilege elevation",
            "gain root",
            "root access",
            "elevated privileges",
            "local privilege",
            "escalate privileges",
            "bypass authentication",
            "authentication bypass",
            "sudo",
            "setuid",
            "setgid",
        ]

        for keyword in privesc_keywords:
            if keyword in description:
                reasons.append(f"Keyword: '{keyword}' in description")
                break

        # 5. CWE 확인
        references = cve_data.get("references", "")
        if isinstance(references, str):
            for cwe_id in self.PRIVESC_CWES.keys():
                if cwe_id in references:
                    reasons.append(f"{cwe_id}: {self.PRIVESC_CWES[cwe_id]}")
                    break

        is_privesc = len(reasons) > 0
        reason_str = "; ".join(reasons) if reasons else ""

        return is_privesc, reason_str

    async def analyze_kernel_security(self) -> Dict:
        """커널 보안 설정 분석"""
        security_info = {
            "aslr_enabled": None,
            "ptrace_scope": None,
            "kptr_restrict": None,
            "dmesg_restrict": None,
            "secure_boot": None,
            "selinux_enabled": None,
            "apparmor_enabled": None,
        }

        sysctl_checks = {
            "aslr_enabled": "/proc/sys/kernel/randomize_va_space",
            "ptrace_scope": "/proc/sys/kernel/yama/ptrace_scope",
            "kptr_restrict": "/proc/sys/kernel/kptr_restrict",
            "dmesg_restrict": "/proc/sys/kernel/dmesg_restrict",
        }

        for key, path in sysctl_checks.items():
            try:
                proc = await asyncio.create_subprocess_exec(
                    "cat", path,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, _ = await proc.communicate()
                if proc.returncode == 0:
                    value = stdout.decode().strip()
                    security_info[key] = int(value) if value.isdigit() else value
            except Exception:
                pass

        # SELinux 확인
        try:
            proc = await asyncio.create_subprocess_exec(
                "getenforce",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()
            if proc.returncode == 0:
                status = stdout.decode().strip().lower()
                security_info["selinux_enabled"] = status == "enforcing"
        except Exception:
            security_info["selinux_enabled"] = False

        # AppArmor 확인
        try:
            proc = await asyncio.create_subprocess_exec(
                "aa-status", "--enabled",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            _, _ = await proc.communicate()
            security_info["apparmor_enabled"] = proc.returncode == 0
        except Exception:
            security_info["apparmor_enabled"] = False

        return security_info

    async def check_kernel_cve_applicability(
        self, cve_id: str, affected_versions: List[str]
    ) -> Dict:
        """
        현재 커널에 특정 CVE가 적용되는지 확인

        Ubuntu/Debian은 backport 패치를 적용하므로
        단순 버전 비교가 아닌 Debian Security Tracker 확인 필요
        """
        kernel_info = await self.get_kernel_info()
        current_version = kernel_info.get("version")

        result = {
            "cve_id": cve_id,
            "current_kernel": kernel_info.get("release"),
            "potentially_affected": False,
            "needs_verification": True,
            "recommendation": "",
        }

        if not current_version:
            result["recommendation"] = "커널 버전을 확인할 수 없습니다."
            return result

        # 버전 기반 초기 검사
        for affected_ver in affected_versions:
            if self._version_in_range(current_version, affected_ver):
                result["potentially_affected"] = True
                break

        if result["potentially_affected"]:
            result["recommendation"] = (
                f"커널 버전 {current_version}이 영향 받을 수 있습니다. "
                f"'apt-cache policy linux-image-{kernel_info.get('release')}'로 "
                f"패치 상태를 확인하세요."
            )
        else:
            result["needs_verification"] = False
            result["recommendation"] = "현재 커널 버전은 영향 받지 않는 것으로 보입니다."

        return result

    def _version_in_range(self, current: str, affected_range: str) -> bool:
        """버전이 영향 범위에 포함되는지 확인 (간단한 비교)"""
        try:
            current_parts = [int(x) for x in current.split('.')[:3]]

            # "< 6.5.0" 형식
            if affected_range.startswith('<'):
                affected_ver = affected_range[1:].strip()
                affected_parts = [int(x) for x in affected_ver.split('.')[:3]]
                return current_parts < affected_parts

            # ">= 6.0.0" 형식
            elif affected_range.startswith('>='):
                affected_ver = affected_range[2:].strip()
                affected_parts = [int(x) for x in affected_ver.split('.')[:3]]
                return current_parts >= affected_parts

            # 정확한 버전 매치
            else:
                affected_parts = [int(x) for x in affected_range.split('.')[:3]]
                return current_parts == affected_parts

        except (ValueError, IndexError):
            return False


class NetworkExposureAnalyzer:
    """네트워크 노출 분석기"""

    async def get_listening_services(self) -> List[Dict]:
        """리스닝 중인 서비스 목록"""
        services = []

        try:
            # ss -tlnp로 TCP 리스닝 포트 확인
            proc = await asyncio.create_subprocess_exec(
                "ss", "-tlnp",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()

            if proc.returncode == 0:
                lines = stdout.decode().strip().split('\n')[1:]  # 헤더 제외

                for line in lines:
                    parts = line.split()
                    if len(parts) >= 6:
                        local_addr = parts[3]
                        process_info = parts[5] if len(parts) > 5 else ""

                        # 주소와 포트 분리
                        if ':' in local_addr:
                            addr, port = local_addr.rsplit(':', 1)
                        else:
                            addr, port = "*", local_addr

                        # 프로세스 정보 파싱
                        process_name = ""
                        pid = ""
                        if 'users:' in process_info:
                            match = re.search(r'\("([^"]+)",pid=(\d+)', process_info)
                            if match:
                                process_name = match.group(1)
                                pid = match.group(2)

                        services.append({
                            "protocol": "tcp",
                            "address": addr,
                            "port": int(port) if port.isdigit() else 0,
                            "process": process_name,
                            "pid": pid,
                            "is_external": addr in ["0.0.0.0", "::", "*"],
                        })

            # UDP 포트도 확인
            proc = await asyncio.create_subprocess_exec(
                "ss", "-ulnp",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()

            if proc.returncode == 0:
                lines = stdout.decode().strip().split('\n')[1:]

                for line in lines:
                    parts = line.split()
                    if len(parts) >= 5:
                        local_addr = parts[3]
                        process_info = parts[5] if len(parts) > 5 else ""

                        if ':' in local_addr:
                            addr, port = local_addr.rsplit(':', 1)
                        else:
                            addr, port = "*", local_addr

                        process_name = ""
                        pid = ""
                        if 'users:' in process_info:
                            match = re.search(r'\("([^"]+)",pid=(\d+)', process_info)
                            if match:
                                process_name = match.group(1)
                                pid = match.group(2)

                        services.append({
                            "protocol": "udp",
                            "address": addr,
                            "port": int(port) if port.isdigit() else 0,
                            "process": process_name,
                            "pid": pid,
                            "is_external": addr in ["0.0.0.0", "::", "*"],
                        })

        except Exception:
            pass

        return services

    async def get_running_daemons(self) -> List[Dict]:
        """실행 중인 데몬 프로세스 목록"""
        daemons = []

        try:
            # systemctl list-units로 활성 서비스 확인
            proc = await asyncio.create_subprocess_exec(
                "systemctl", "list-units", "--type=service", "--state=running",
                "--no-pager", "--no-legend",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()

            if proc.returncode == 0:
                for line in stdout.decode().strip().split('\n'):
                    if not line.strip():
                        continue

                    parts = line.split(None, 4)
                    if len(parts) >= 4:
                        service_name = parts[0].replace('.service', '')
                        load_state = parts[1]
                        active_state = parts[2]
                        sub_state = parts[3]
                        description = parts[4] if len(parts) > 4 else ""

                        daemons.append({
                            "name": service_name,
                            "load": load_state,
                            "active": active_state,
                            "sub": sub_state,
                            "description": description,
                        })

        except Exception:
            pass

        return daemons

    async def map_service_to_package(self, service_name: str) -> Optional[str]:
        """서비스명에서 패키지명 찾기"""
        try:
            # 서비스 파일 경로 찾기
            proc = await asyncio.create_subprocess_exec(
                "systemctl", "show", "-p", "FragmentPath", service_name,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()

            if proc.returncode == 0:
                path_line = stdout.decode().strip()
                if '=' in path_line:
                    service_path = path_line.split('=', 1)[1]

                    # dpkg -S로 파일 소유 패키지 찾기
                    if service_path:
                        proc2 = await asyncio.create_subprocess_exec(
                            "dpkg", "-S", service_path,
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE
                        )
                        stdout2, _ = await proc2.communicate()

                        if proc2.returncode == 0:
                            output = stdout2.decode().strip()
                            if ':' in output:
                                return output.split(':')[0]

        except Exception:
            pass

        return None
