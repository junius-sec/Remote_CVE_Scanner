"""
Package Usage Analyzer

패키지의 실제 사용 상태를 분석합니다:
- 현재 실행 중인 프로세스 여부
- 마지막 실행/사용 시간
- 시스템 서비스 여부
- 네트워크 리스닝 여부
"""

import asyncio
import os
import subprocess
import time
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from pathlib import Path


class PackageUsageAnalyzer:
    """패키지 사용 상태 분석기"""

    # 패키지명 -> 실행 파일/서비스 매핑
    PACKAGE_TO_EXECUTABLES = {
        # 웹 서버
        "apache2": ["apache2", "httpd"],
        "nginx": ["nginx"],
        "lighttpd": ["lighttpd"],

        # 데이터베이스
        "mysql-server": ["mysqld", "mysql"],
        "mariadb-server": ["mariadbd", "mysqld"],
        "postgresql": ["postgres", "postgresql"],
        "redis-server": ["redis-server"],
        "mongodb": ["mongod"],

        # SSH/보안
        "openssh-server": ["sshd"],
        "openssh-client": ["ssh", "ssh-agent"],
        "openssl": ["openssl"],

        # 시스템
        "systemd": ["systemd", "systemd-journald", "systemd-logind"],
        "sudo": ["sudo"],
        "cron": ["cron", "crond"],

        # 네트워크
        "bind9": ["named"],
        "dnsmasq": ["dnsmasq"],
        "curl": ["curl"],
        "wget": ["wget"],

        # 언어/런타임
        "python3": ["python3", "python"],
        "nodejs": ["node", "nodejs"],
        "openjdk": ["java"],

        # 컨테이너
        "docker": ["dockerd", "docker"],
        "containerd": ["containerd"],
    }

    # 시스템 서비스 매핑
    PACKAGE_TO_SERVICES = {
        "apache2": "apache2",
        "nginx": "nginx",
        "mysql-server": "mysql",
        "mariadb-server": "mariadb",
        "postgresql": "postgresql",
        "redis-server": "redis-server",
        "mongodb": "mongod",
        "openssh-server": "ssh",
        "bind9": "named",
        "docker": "docker",
        "cron": "cron",
    }

    def __init__(self):
        self._process_cache: List[Dict] = []  # ps aux 결과를 파싱한 프로세스 리스트
        self._cache_time: float = 0
        self._cache_ttl: float = 600  # 10분 캐시 (스캔 중 재실행 방지)
        self._ssh_executor = None  # SSH executor for remote scanning
        self._binary_atime_cache: Dict[str, Dict] = {}  # 바이너리명 -> {timestamp, last_access, path}

    def set_ssh_executor(self, ssh_executor):
        """원격 스캔을 위한 SSH executor 설정"""
        self._ssh_executor = ssh_executor

    async def preload_process_cache(self):
        """프로세스 캐시 + 바이너리 atime 캐시를 미리 로드 (스캔 전 1회 호출)"""
        # === 1) ps aux 프로세스 목록 캐시 ===
        try:
            if self._ssh_executor:
                result = await self._ssh_executor.execute("ps aux")
                if result.success:
                    stdout = result.stdout
                else:
                    return
            else:
                result = await asyncio.create_subprocess_exec(
                    "ps", "aux",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout_bytes, _ = await result.communicate()
                stdout = stdout_bytes.decode()

            lines = stdout.strip().split('\n')[1:]
            all_processes = []
            for line in lines:
                parts = line.split(None, 10)
                if len(parts) >= 11:
                    try:
                        user, pid, cpu, mem, vsz, rss, tty, stat, start, time_str, cmd = parts
                        all_processes.append({
                            "user": user,
                            "pid": int(pid),
                            "cpu": float(cpu),
                            "mem": float(mem),
                            "cmd": cmd,
                            "start": start
                        })
                    except (ValueError, IndexError):
                        continue
            self._process_cache = all_processes
            self._cache_time = time.time()
            print(f"[프로세스 캐시] {len(all_processes)}개 로드됨")
        except Exception as e:
            print(f"[WARN] 프로세스 캐시 로드 실패: {e}")

        # 바이너리 atime은 스캔 후 CVE 있는 패키지만 별도 수집 (load_binary_atimes_for_packages)

    async def analyze_package(self, package_name: str) -> Dict:
        """
        패키지의 사용 상태 분석

        Returns:
            {
                "package_name": "openssh-server",
                "is_running": True,
                "running_processes": [{"pid": 1234, "cmd": "sshd", "user": "root"}],
                "is_service": True,
                "service_status": "active",
                "is_listening": True,
                "listening_ports": [22],
                "last_used": "2024-01-12 10:30:00",
                "usage_level": "active",  # active, recent, installed, unused
                "risk_multiplier": 1.5  # 활성 사용 시 위험도 가중
            }
        """
        result = {
            "package_name": package_name,
            "is_running": False,
            "running_processes": [],
            "is_service": False,
            "service_status": None,
            "is_listening": False,
            "listening_ports": [],
            "last_used": None,
            "last_used_timestamp": None,
            "usage_level": "installed",
            "risk_multiplier": 1.0,
            "binary_paths": [],
        }

        # 1. 실행 중인 프로세스 확인 (ps aux만 사용 - 빠름)
        running_procs = await self._check_running_processes(package_name)
        if running_procs:
            result["is_running"] = True
            result["running_processes"] = running_procs

        # 2. 바이너리 atime은 캐시에 있으면 사용 (스캔 후 load_binary_atimes_for_packages로 수집된 경우)
        binary_info = self._get_binary_atime_from_cache(package_name)
        if binary_info:
            result["last_used"] = binary_info.get("last_access")
            result["last_used_timestamp"] = binary_info.get("timestamp")
            result["binary_paths"] = binary_info.get("paths", [])

        # 5. 사용 수준 결정 및 위험도 가중치 계산
        result["usage_level"] = self._determine_usage_level(result)
        result["risk_multiplier"] = self._calculate_risk_multiplier(result)

        return result

    async def _check_running_processes(self, package_name: str) -> List[Dict]:
        """현재 실행 중인 관련 프로세스 확인 (캐싱 사용)"""
        processes = []

        # 패키지에 해당하는 실행 파일 목록 가져오기
        executables = self._get_executables_for_package(package_name)

        # ps aux 결과 캐싱 - 1분 이내면 재사용
        current_time = time.time()
        if current_time - self._cache_time > self._cache_ttl:
            try:
                # SSH executor가 있으면 원격으로 실행, 없으면 로컬 실행
                if self._ssh_executor:
                    # 원격 실행 - execute() 메서드 사용 및 .stdout 접근
                    result = await self._ssh_executor.execute("ps aux")
                    if result.success:
                        stdout = result.stdout
                    else:
                        return processes
                else:
                    # 로컬 실행
                    result = await asyncio.create_subprocess_exec(
                        "ps", "aux",
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    stdout_bytes, _ = await result.communicate()
                    stdout = stdout_bytes.decode()

                # 프로세스 목록 파싱하여 캐시에 저장
                lines = stdout.strip().split('\n')[1:]  # 헤더 제외
                all_processes = []
                
                for line in lines:
                    parts = line.split(None, 10)
                    if len(parts) >= 11:
                        user, pid, cpu, mem, vsz, rss, tty, stat, start, time_str, cmd = parts
                        all_processes.append({
                            "user": user,
                            "pid": int(pid),
                            "cpu": float(cpu),
                            "mem": float(mem),
                            "cmd": cmd,
                            "start": start
                        })
                
                self._process_cache = all_processes
                self._cache_time = current_time
                
            except Exception as e:
                return processes

        # 캐시된 프로세스 목록에서 패키지와 매칭되는 것 찾기
        for proc in self._process_cache:
            cmd = proc["cmd"]
            cmd_base = os.path.basename(cmd.split()[0])

            for exe in executables:
                if exe in cmd_base or exe in cmd:
                    processes.append({
                        "pid": proc["pid"],
                        "user": proc["user"],
                        "cpu": proc["cpu"],
                        "mem": proc["mem"],
                        "cmd": cmd[:100],  # 명령어 100자 제한
                        "start": proc["start"]
                    })
                    break

        return processes

    async def _check_service_status(self, package_name: str) -> Optional[str]:
        """systemd 서비스 상태 확인"""
        service_name = self._get_service_for_package(package_name)
        if not service_name:
            return None

        try:
            result = await asyncio.create_subprocess_exec(
                "systemctl", "is-active", service_name,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await result.communicate()
            status = stdout.decode().strip()

            if status in ["active", "inactive", "failed", "activating"]:
                return status
        except Exception:
            pass

        return None

    async def _check_listening_ports(self, package_name: str) -> List[int]:
        """패키지 관련 프로세스가 리스닝 중인 포트 확인"""
        ports = []
        executables = self._get_executables_for_package(package_name)

        try:
            # ss 또는 netstat으로 리스닝 포트 확인
            result = await asyncio.create_subprocess_exec(
                "ss", "-tlnp",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await result.communicate()

            for line in stdout.decode().strip().split('\n')[1:]:
                for exe in executables:
                    if exe in line:
                        # 포트 번호 추출
                        parts = line.split()
                        if len(parts) >= 4:
                            addr_port = parts[3]
                            try:
                                port = int(addr_port.rsplit(':', 1)[-1])
                                if port not in ports:
                                    ports.append(port)
                            except (ValueError, IndexError):
                                pass
        except Exception:
            pass

        return sorted(ports)

    async def _check_binary_access_time(self, package_name: str) -> Optional[Dict]:
        """패키지 바이너리의 마지막 접근 시간 확인"""
        binary_paths = []
        last_access = None
        timestamp = None

        try:
            # SSH executor가 있으면 원격으로, 없으면 로컬로 dpkg -L 실행
            if self._ssh_executor:
                result = await self._ssh_executor.execute(f"dpkg -L {package_name} 2>/dev/null || apk info -L {package_name} 2>/dev/null")
                if result.success:
                    files = result.stdout.strip().split('\n')
                else:
                    return None
            else:
                result = await asyncio.create_subprocess_exec(
                    "dpkg", "-L", package_name,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, _ = await result.communicate()
                if result.returncode != 0:
                    return None
                files = stdout.decode().strip().split('\n')

            # 실행 파일만 필터링 (/usr/bin, /usr/sbin, /bin, /sbin)
            exec_dirs = ['/usr/bin/', '/usr/sbin/', '/bin/', '/sbin/']

            for filepath in files:
                if any(filepath.startswith(d) for d in exec_dirs):
                    # SSH를 통해 파일 존재 및 접근 시간 확인
                    if self._ssh_executor:
                        # stat 명령으로 파일 접근 시간 확인 (atime)
                        stat_result = await self._ssh_executor.execute(f"stat -c '%X' {filepath} 2>/dev/null")
                        if stat_result.success and stat_result.stdout.strip().isdigit():
                            binary_paths.append(filepath)
                            atime = int(stat_result.stdout.strip())
                            if timestamp is None or atime > timestamp:
                                timestamp = atime
                                last_access = datetime.fromtimestamp(atime).strftime("%Y-%m-%d %H:%M:%S")
                    else:
                        # 로컬 파일 접근
                        if os.path.isfile(filepath):
                            binary_paths.append(filepath)
                            try:
                                stat_info = os.stat(filepath)
                                atime = stat_info.st_atime
                                if timestamp is None or atime > timestamp:
                                    timestamp = atime
                                    last_access = datetime.fromtimestamp(atime).strftime("%Y-%m-%d %H:%M:%S")
                            except OSError:
                                pass

        except Exception:
            pass

        if binary_paths:
            return {
                "paths": binary_paths[:5],  # 상위 5개만
                "last_access": last_access,
                "timestamp": timestamp
            }
        return None

    async def load_binary_atimes_for_packages(self, package_names: List[str]):
        """특정 패키지들의 바이너리 최근 실행 시간을 한번에 수집 (CVE 발견된 패키지만)
        
        스캔 완료 후 호출.
        1단계: dpkg -L로 패키지별 실제 설치 파일 목록 조회 (SSH 1회)
        2단계: 실행파일 경로들의 atime 조회 (SSH 1회)
        => 패키지명↔바이너리명 불일치 문제 완전 해결
        """
        if not package_names:
            return
        
        print(f"[실행시간] CVE 발견된 {len(package_names)}개 패키지의 바이너리 최근 실행 시간 수집 중...")
        
        # === 1단계: dpkg -L로 패키지별 실제 실행파일 경로 조회 (SSH 1회) ===
        pkg_to_binaries = await self._resolve_package_binaries(package_names)
        
        # 발견된 모든 실행파일 경로
        all_binary_paths = set()
        for paths in pkg_to_binaries.values():
            all_binary_paths.update(paths)
        
        # dpkg -L로 못 찾은 패키지는 기존 매핑/이름 추론 폴백
        for pkg in package_names:
            if pkg not in pkg_to_binaries or not pkg_to_binaries[pkg]:
                fallback_exes = self._get_executables_for_package(pkg)
                fallback_paths = []
                for exe in fallback_exes:
                    for prefix in ['/usr/bin/', '/usr/sbin/', '/bin/', '/sbin/']:
                        path = prefix + exe
                        all_binary_paths.add(path)
                        fallback_paths.append(path)
                # 폴백 경로도 pkg_to_binaries에 등록 (3단계에서 패키지명 키로 등록하기 위해)
                if fallback_paths:
                    pkg_to_binaries[pkg] = fallback_paths
        
        if not all_binary_paths:
            print(f"[실행시간] 실행파일 없음")
            return
        
        # === 2단계: 실행파일들의 atime 한번에 조회 (SSH 1회) ===
        await self._load_atimes_for_paths(list(all_binary_paths))
        
        # === 3단계: 패키지→바이너리 매핑으로 캐시 보강 ===
        # dpkg -L 결과를 _binary_atime_cache에 패키지명으로도 접근 가능하게
        # 패키지의 여러 바이너리 중 가장 최근에 사용된 것을 등록
        for pkg, paths in pkg_to_binaries.items():
            pkg_lower = pkg.lower()
            best_cached = None
            all_paths = []
            
            for p in paths:
                fname = os.path.basename(p)
                # 이미 캐시에 있는지 확인
                if fname in self._binary_atime_cache:
                    cached = self._binary_atime_cache[fname]
                    all_paths.append(cached['path'])
                    
                    # 가장 최근 것 선택
                    if best_cached is None or cached['timestamp'] > best_cached['timestamp']:
                        best_cached = cached
            
            # 패키지명 키로 가장 최근 바이너리 정보 등록 (모든 경로 포함)
            if best_cached:
                self._binary_atime_cache[pkg_lower] = {
                    'timestamp': best_cached['timestamp'],
                    'last_access': best_cached['last_access'],
                    'path': best_cached['path'],
                    'all_paths': all_paths[:5]  # 최대 5개
                }
        
        # 매칭 카운트
        matched = 0
        for pkg in package_names:
            if self._get_binary_atime_from_cache(pkg):
                matched += 1
        print(f"[실행시간] {matched}/{len(package_names)}개 패키지 매칭 완료")

    async def _resolve_package_binaries(self, package_names: List[str]) -> Dict[str, List[str]]:
        """dpkg -L (또는 rpm -ql / apk info -L)로 패키지별 실제 실행파일 경로를 조회
        
        SSH 1회로 모든 패키지의 파일 목록을 가져와서 /usr/bin, /usr/sbin, /bin, /sbin
        안에 있는 실행파일만 필터링.
        """
        pkg_to_binaries: Dict[str, List[str]] = {}
        bin_dirs = {'/usr/bin', '/usr/sbin', '/bin', '/sbin'}
        
        # 각 패키지별로 구분 가능하게 separator 출력
        # exit code 항상 0으로 보장 (echo __DONE__ 마커)
        pkg_list_str = ' '.join(f'"{p}"' for p in package_names)
        cmd = (
            f"for p in {pkg_list_str}; do "
            f"echo \"__PKG__:$p\"; "
            f"dpkg -L \"$p\" 2>/dev/null || "
            f"rpm -ql \"$p\" 2>/dev/null || "
            f"apk info -L \"$p\" 2>/dev/null || "
            f"true; "
            f"done; echo __DONE__"
        )
        
        try:
            if self._ssh_executor:
                result = await self._ssh_executor.execute(cmd, timeout=30)
                stdout = result.stdout if result.stdout else ''
                # success 체크 안 함 - __DONE__ 마커로 확인
            else:
                proc = await asyncio.create_subprocess_shell(
                    cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout_bytes, _ = await proc.communicate()
                stdout = stdout_bytes.decode()
            
            if not stdout or not stdout.strip():
                print(f"[dpkg -L] 응답 없음")
                return pkg_to_binaries
            
            current_pkg = None
            for line in stdout.strip().split('\n'):
                line = line.strip()
                if not line or line == '__DONE__':
                    continue
                
                if line.startswith('__PKG__:'):
                    current_pkg = line[8:].strip()
                    if current_pkg not in pkg_to_binaries:
                        pkg_to_binaries[current_pkg] = []
                    continue
                
                if current_pkg is None:
                    continue
                
                # /usr/bin/xxx, /usr/sbin/xxx, /bin/xxx, /sbin/xxx 만 필터
                filepath = line
                parent_dir = os.path.dirname(filepath)
                if parent_dir in bin_dirs:
                    pkg_to_binaries[current_pkg].append(filepath)
            
            total_bins = sum(len(v) for v in pkg_to_binaries.values())
            found_pkgs = sum(1 for v in pkg_to_binaries.values() if v)
            print(f"[dpkg -L] {found_pkgs}/{len(package_names)}개 패키지에서 {total_bins}개 실행파일 발견")
            
        except Exception as e:
            print(f"[WARN] dpkg -L 조회 실패: {e}")
        
        return pkg_to_binaries

    async def _load_atimes_for_paths(self, binary_paths: List[str]):
        """실행파일 경로 목록의 atime을 한번에 수집 (SSH 1회)
        
        - for루프로 각 파일 stat → 존재하지 않는 파일은 에러 없이 스킵
        - exit code 항상 0 (success=True 보장)
        - ARG_MAX 문제 없음 (stdin으로 전달)
        """
        if not binary_paths:
            return
        
        # 중복 제거 및 정리
        unique_paths = list(set(p.strip() for p in binary_paths if p.strip()))
        
        # for 루프로 각 파일의 mtime 출력 (존재하지 않으면 skip, exit code 항상 0)
        # 쿼트 문제 없는 포맷
        paths_joined = '\n'.join(unique_paths)
        cmd = (
            f"printf '{paths_joined}\\n' | while IFS= read -r f; do "
            f"[ -f \"$f\" ] && stat -c \"%Y %n\" \"$f\" 2>/dev/null; "
            f"done; echo __DONE__"
        )
        
        try:
            if self._ssh_executor:
                result = await self._ssh_executor.execute(cmd, timeout=30)
                stdout = result.stdout if result.stdout else ''
                # success 체크 안 함 - __DONE__ 마커로 확인
            else:
                proc = await asyncio.create_subprocess_shell(
                    cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout_bytes, _ = await proc.communicate()
                stdout = stdout_bytes.decode()
            
            if not stdout or not stdout.strip():
                print(f"[WARN] atime 수집: 빈 응답")
                return
            
            count = 0
            for line in stdout.strip().split('\n'):
                line = line.strip()
                if not line or line == '__DONE__':
                    continue
                parts = line.split(' ', 1)
                if len(parts) != 2:
                    continue
                try:
                    ts_str, filepath = parts
                    ts = float(ts_str)
                    filename = os.path.basename(filepath.strip())
                    
                    if filename not in self._binary_atime_cache or ts > self._binary_atime_cache[filename]['timestamp']:
                        self._binary_atime_cache[filename] = {
                            'timestamp': ts,
                            'last_access': datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M'),
                            'path': filepath.strip()
                        }
                        count += 1
                except (ValueError, IndexError):
                    continue
            
            print(f"[실행시간] {count}개 실행파일 atime 수집 완료 (대상 {len(unique_paths)}개)")
        except Exception as e:
            print(f"[WARN] atime 수집 실패: {e}")

    async def _preload_binary_atime_cache(self):
        """하위 호환용 - 새 메서드로 대체됨"""
        pass

    def _get_binary_atime_from_cache(self, package_name: str) -> Optional[Dict]:
        """캐시에서 패키지의 바이너리 최근 실행 시간 조회 (즉시 반환, IO 없음)"""
        if not hasattr(self, '_binary_atime_cache') or not self._binary_atime_cache:
            return None
        
        best_ts = None
        best_access = None
        matched_paths = []
        
        # 1순위: dpkg -L로 등록된 패키지명 직접 조회 (pkg_lower 키)
        pkg_lower = package_name.lower()
        cached = self._binary_atime_cache.get(pkg_lower)
        if cached:
            return {
                'paths': cached.get('all_paths', [cached['path']]),
                'last_access': cached['last_access'],
                'timestamp': cached['timestamp']
            }
        
        # 2순위: 바이너리명으로 조회 (기존 매핑 기반)
        executables = self._get_executables_for_package(package_name)
        for exe in executables:
            cached = self._binary_atime_cache.get(exe)
            if cached:
                matched_paths.append(cached['path'])
                if best_ts is None or cached['timestamp'] > best_ts:
                    best_ts = cached['timestamp']
                    best_access = cached['last_access']
        
        # 3순위: 패키지명 부분 매칭 (폴백)
        if not matched_paths:
            pkg_base = package_name.split('-')[0].lower() if '-' in package_name else package_name.lower()
            for filename, cached in self._binary_atime_cache.items():
                if filename == pkg_base:
                    matched_paths.append(cached['path'])
                    if best_ts is None or cached['timestamp'] > best_ts:
                        best_ts = cached['timestamp']
                        best_access = cached['last_access']
                    break
        
        if matched_paths:
            return {
                'paths': matched_paths[:5],
                'last_access': best_access,
                'timestamp': best_ts
            }
        return None

    def _get_executables_for_package(self, package_name: str) -> List[str]:
        """패키지에 해당하는 실행 파일 목록"""
        # 정확한 매핑 확인
        pkg_lower = package_name.lower()
        for pkg_pattern, executables in self.PACKAGE_TO_EXECUTABLES.items():
            if pkg_lower == pkg_pattern or pkg_lower.startswith(pkg_pattern):
                return executables

        # 기본: 패키지명 자체를 실행 파일로 간주
        base_name = package_name.split('-')[0] if '-' in package_name else package_name
        return [package_name, base_name]

    def _get_service_for_package(self, package_name: str) -> Optional[str]:
        """패키지에 해당하는 systemd 서비스명"""
        pkg_lower = package_name.lower()
        for pkg_pattern, service in self.PACKAGE_TO_SERVICES.items():
            if pkg_lower == pkg_pattern or pkg_lower.startswith(pkg_pattern):
                return service
        return None

    def _determine_usage_level(self, result: Dict) -> str:
        """
        사용 수준 결정
        - active: 현재 실행 중이거나 서비스 활성화
        - recent: 최근 24시간 내 사용
        - installed: 설치되어 있지만 사용 안함
        - unused: 장기간 미사용 (30일+)
        """
        import time

        if result["is_running"] or result["service_status"] == "active":
            return "active"

        if result["is_listening"]:
            return "active"

        if result["last_used_timestamp"]:
            days_since_use = (time.time() - result["last_used_timestamp"]) / 86400
            if days_since_use < 1:
                return "recent"
            elif days_since_use < 30:
                return "installed"
            else:
                return "unused"

        return "installed"

    def _calculate_risk_multiplier(self, result: Dict) -> float:
        """
        위험도 가중치 계산
        - 활성 사용 + 네트워크 노출: 2.0x
        - 활성 사용: 1.5x
        - 최근 사용: 1.2x
        - 설치됨: 1.0x
        - 미사용: 0.8x
        """
        base = 1.0

        usage_level = result["usage_level"]
        if usage_level == "active":
            base = 1.5
        elif usage_level == "recent":
            base = 1.2
        elif usage_level == "unused":
            base = 0.8

        # 네트워크 리스닝 시 추가 가중치
        if result["is_listening"]:
            base += 0.5

        # 루트로 실행 중이면 추가 가중치
        for proc in result.get("running_processes", []):
            if proc.get("user") == "root":
                base += 0.3
                break

        return round(min(base, 3.0), 2)  # 최대 3.0x


class AptPatchChecker:
    """apt-cache를 사용한 실시간 패치 가능 여부 확인"""

    async def check_available_update(self, package_name: str) -> Dict:
        """
        패키지의 업데이트 가능 여부 확인

        Returns:
            {
                "package_name": "openssl",
                "installed_version": "3.0.2-0ubuntu1.12",
                "candidate_version": "3.0.2-0ubuntu1.15",
                "has_update": True,
                "is_security_update": True,
                "update_origin": "Ubuntu:22.04/jammy-security"
            }
        """
        result = {
            "package_name": package_name,
            "installed_version": None,
            "candidate_version": None,
            "has_update": False,
            "is_security_update": False,
            "update_origin": None
        }

        try:
            proc = await asyncio.create_subprocess_exec(
                "apt-cache", "policy", package_name,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()

            if proc.returncode == 0:
                output = stdout.decode()

                for line in output.split('\n'):
                    line = line.strip()
                    if line.startswith("Installed:"):
                        result["installed_version"] = line.split(":", 1)[1].strip()
                    elif line.startswith("Candidate:"):
                        result["candidate_version"] = line.split(":", 1)[1].strip()
                    elif "security" in line.lower() and "http" in line:
                        result["update_origin"] = line.strip()
                        result["is_security_update"] = True

                # 업데이트 가능 여부 확인
                if (result["installed_version"] and
                    result["candidate_version"] and
                    result["installed_version"] != result["candidate_version"] and
                    result["candidate_version"] != "(none)"):
                    result["has_update"] = True

        except Exception as e:
            pass

        return result

    async def check_multiple_packages(self, package_names: List[str]) -> Dict[str, Dict]:
        """여러 패키지의 업데이트 가능 여부 일괄 확인"""
        tasks = [self.check_available_update(pkg) for pkg in package_names]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        return {
            pkg: res if not isinstance(res, Exception) else {"error": str(res)}
            for pkg, res in zip(package_names, results)
        }

    async def get_upgradable_packages(self) -> List[Dict]:
        """업그레이드 가능한 전체 패키지 목록"""
        packages = []

        try:
            # apt list --upgradable
            proc = await asyncio.create_subprocess_exec(
                "apt", "list", "--upgradable",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()

            if proc.returncode == 0:
                for line in stdout.decode().split('\n')[1:]:  # 첫 줄 "Listing..." 제외
                    if not line.strip():
                        continue

                    # Format: package/origin version arch [upgradable from: old_version]
                    parts = line.split()
                    if len(parts) >= 2:
                        pkg_origin = parts[0].split('/')
                        packages.append({
                            "name": pkg_origin[0],
                            "origin": pkg_origin[1] if len(pkg_origin) > 1 else "",
                            "new_version": parts[1] if len(parts) > 1 else "",
                            "is_security": "security" in line.lower()
                        })

        except Exception:
            pass

        return packages
