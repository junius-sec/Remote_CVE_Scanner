"""Patch recommendation system with rollback support"""
from typing import Dict, List, Optional
from ..models.schemas import Package, CVE, Finding, Host
from sqlalchemy.ext.asyncio import AsyncSession


class PatchAdvisor:
    """Generate patch recommendations and rollback commands"""

    def generate_patch_recommendation(
        self,
        package: Package,
        host: Host,
        findings: List[Finding]
    ) -> Dict:
        """Generate patch recommendation with rollback strategy"""

        os_type = host.os_type.lower()
        pkg_name = package.name
        current_version = package.version

        if os_type in ["ubuntu", "debian"]:
            return self._debian_patch_recommendation(pkg_name, current_version, findings)
        elif os_type in ["centos", "rhel", "fedora"]:
            return self._redhat_patch_recommendation(pkg_name, current_version, findings)
        else:
            return {"error": "Unsupported OS type"}

    def _debian_patch_recommendation(
        self,
        pkg_name: str,
        current_version: str,
        findings: List[Finding]
    ) -> Dict:
        """Generate Debian/Ubuntu patch commands"""

        cve_count = len(findings)
        max_cvss = max([f.cve.cvss_v3_score or 0 for f in findings])

        return {
            "package": pkg_name,
            "current_version": current_version,
            "vulnerability_summary": {
                "total_cves": cve_count,
                "max_cvss_score": max_cvss,
                "cve_ids": [f.cve.cve_id for f in findings[:5]]
            },
            "patch_commands": {
                "check_updates": [
                    {
                        "command": f"apt-cache policy {pkg_name}",
                        "description": "현재 설치된 버전과 사용 가능한 업데이트 확인"
                    }
                ],
                "backup_current": [
                    {
                        "command": f"dpkg -l {pkg_name} > /tmp/{pkg_name}_backup_$(date +%Y%m%d).txt",
                        "description": "현재 패키지 정보 백업"
                    },
                    {
                        "command": f"sudo apt-mark showhold > /tmp/apt_hold_backup_$(date +%Y%m%d).txt",
                        "description": "현재 hold 상태 패키지 목록 백업"
                    }
                ],
                "update_package": [
                    {
                        "command": "sudo apt update",
                        "description": "패키지 목록 업데이트"
                    },
                    {
                        "command": f"sudo apt install --only-upgrade {pkg_name}",
                        "description": f"{pkg_name} 패키지만 업그레이드"
                    }
                ],
                "verify_fix": [
                    {
                        "command": f"dpkg -l {pkg_name}",
                        "description": "업데이트된 버전 확인"
                    },
                    {
                        "command": f"systemctl status {self._guess_service_name(pkg_name)}",
                        "description": "서비스 정상 작동 확인 (해당되는 경우)"
                    }
                ]
            },
            "rollback_commands": {
                "method_1_apt_downgrade": [
                    {
                        "command": f"sudo apt install {pkg_name}={current_version}",
                        "description": f"특정 버전({current_version})으로 다운그레이드",
                        "warning": "⚠️ 해당 버전이 레포지토리에 있어야 합니다"
                    },
                    {
                        "command": f"sudo apt-mark hold {pkg_name}",
                        "description": "패키지 자동 업데이트 방지 (hold 설정)"
                    }
                ],
                "method_2_snapshot": [
                    {
                        "command": "sudo timeshift --list",
                        "description": "Timeshift 스냅샷 목록 확인 (설치된 경우)"
                    },
                    {
                        "command": "sudo timeshift --restore",
                        "description": "시스템 스냅샷으로 복원"
                    }
                ],
                "method_3_cache": [
                    {
                        "command": f"ls -lh /var/cache/apt/archives/{pkg_name}*.deb",
                        "description": "캐시된 이전 버전 .deb 파일 확인"
                    },
                    {
                        "command": f"sudo dpkg -i /var/cache/apt/archives/{pkg_name}*{current_version}*.deb",
                        "description": "캐시된 .deb 파일로 수동 설치"
                    }
                ]
            },
            "dependency_warnings": [
                "⚠️ 패키지 업데이트 시 의존성이 함께 업데이트될 수 있습니다",
                "⚠️ 중요 시스템: 업데이트 전 시스템 스냅샷 생성 권장",
                "⚠️ 프로덕션 환경: 테스트 환경에서 먼저 검증 후 적용",
                f"⚠️ {pkg_name} 업데이트로 인해 연관 서비스 재시작이 필요할 수 있습니다",
                "⚠️ 다운그레이드는 의존성 충돌을 일으킬 수 있으므로 신중히 진행하세요"
            ],
            "best_practices": [
                "1. 백업: 업데이트 전 전체 시스템 백업 또는 스냅샷 생성",
                "2. 테스트: 가능하다면 동일 환경에서 먼저 테스트",
                "3. 모니터링: 업데이트 후 애플리케이션 로그 및 동작 확인",
                "4. 문서화: 변경 사항 기록 (날짜, 버전, 이유)",
                "5. 점진적 적용: 여러 서버가 있다면 단계적으로 롤아웃"
            ]
        }

    def _redhat_patch_recommendation(
        self,
        pkg_name: str,
        current_version: str,
        findings: List[Finding]
    ) -> Dict:
        """Generate RedHat/CentOS/Fedora patch commands"""

        cve_count = len(findings)
        max_cvss = max([f.cve.cvss_v3_score or 0 for f in findings])

        return {
            "package": pkg_name,
            "current_version": current_version,
            "vulnerability_summary": {
                "total_cves": cve_count,
                "max_cvss_score": max_cvss,
                "cve_ids": [f.cve.cve_id for f in findings[:5]]
            },
            "patch_commands": {
                "check_updates": [
                    {
                        "command": f"yum info {pkg_name}",
                        "description": "패키지 정보 및 사용 가능한 버전 확인"
                    }
                ],
                "backup_current": [
                    {
                        "command": f"rpm -qa {pkg_name} > /tmp/{pkg_name}_backup_$(date +%Y%m%d).txt",
                        "description": "현재 패키지 정보 백업"
                    }
                ],
                "update_package": [
                    {
                        "command": "sudo yum check-update",
                        "description": "사용 가능한 업데이트 확인"
                    },
                    {
                        "command": f"sudo yum update {pkg_name}",
                        "description": f"{pkg_name} 패키지 업데이트"
                    }
                ],
                "verify_fix": [
                    {
                        "command": f"rpm -q {pkg_name}",
                        "description": "업데이트된 버전 확인"
                    }
                ]
            },
            "rollback_commands": {
                "method_1_yum_downgrade": [
                    {
                        "command": f"sudo yum downgrade {pkg_name}-{current_version}",
                        "description": f"특정 버전({current_version})으로 다운그레이드"
                    },
                    {
                        "command": f"sudo yum versionlock add {pkg_name}",
                        "description": "패키지 버전 고정 (yum-plugin-versionlock 필요)"
                    }
                ],
                "method_2_snapshot": [
                    {
                        "command": "sudo snapper list",
                        "description": "Snapper 스냅샷 목록 확인"
                    },
                    {
                        "command": "sudo snapper rollback <snapshot_number>",
                        "description": "특정 스냅샷으로 롤백"
                    }
                ]
            },
            "dependency_warnings": [
                "⚠️ 패키지 업데이트 시 의존성이 함께 업데이트될 수 있습니다",
                "⚠️ 중요 시스템: 업데이트 전 시스템 스냅샷 생성 권장",
                "⚠️ 프로덕션 환경: 테스트 환경에서 먼저 검증 후 적용",
                "⚠️ 다운그레이드는 의존성 충돌을 일으킬 수 있으므로 신중히 진행하세요"
            ],
            "best_practices": [
                "1. 백업: 업데이트 전 전체 시스템 백업 또는 스냅샷 생성",
                "2. 테스트: 가능하다면 동일 환경에서 먼저 테스트",
                "3. 모니터링: 업데이트 후 애플리케이션 로그 및 동작 확인",
                "4. 문서화: 변경 사항 기록 (날짜, 버전, 이유)",
                "5. 점진적 적용: 여러 서버가 있다면 단계적으로 롤아웃"
            ]
        }

    def _guess_service_name(self, pkg_name: str) -> str:
        """Guess systemd service name from package name"""
        # Common package to service mappings
        service_map = {
            "apache2": "apache2",
            "nginx": "nginx",
            "mysql-server": "mysql",
            "mariadb-server": "mariadb",
            "postgresql": "postgresql",
            "openssh-server": "ssh",
            "docker": "docker",
            "redis-server": "redis",
            "mongodb": "mongod"
        }

        return service_map.get(pkg_name, pkg_name)
