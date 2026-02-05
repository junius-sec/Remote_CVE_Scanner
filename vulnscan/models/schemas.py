from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, Text, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime, timezone, timedelta

# KST timezone
KST = timezone(timedelta(hours=9))

def get_kst_now():
    return datetime.now(KST)

Base = declarative_base()


class Host(Base):
    """호스트/자산 정보 (allowlist 기반)"""
    __tablename__ = "hosts"

    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String(255), unique=True, nullable=False, index=True)
    ip_address = Column(String(45), nullable=False)
    zone = Column(String(50), nullable=False)
    os_type = Column(String(50), nullable=False)
    os_version = Column(String(100))
    created_at = Column(DateTime, default=get_kst_now)
    updated_at = Column(DateTime, default=get_kst_now, onupdate=get_kst_now)
    last_scan = Column(DateTime)
    status = Column(String(20), default="active")
    
    # === 신규 필드: Allowlist 및 원격 접속 정보 ===
    is_allowed = Column(Boolean, default=True, index=True)  # allowlist 등록 여부 (True여야만 스캔 가능)
    ssh_port = Column(Integer, default=22)  # SSH 포트
    ssh_username = Column(String(100), default="root")  # SSH 사용자명
    auth_method = Column(String(20), default="key")  # key, password
    ssh_key_path = Column(String(500))  # SSH 키 경로 (서버 로컬)
    ssh_password = Column(String(500))  # SSH 비밀번호 (암호화 권장)
    tags = Column(String(500))  # 태그 (comma-separated: "production,web,critical")
    owner = Column(String(100))  # 자산 소유자/관리자
    description = Column(Text)  # 자산 설명
    
    # 원격 스캔 관련
    last_discovery = Column(DateTime)  # 마지막 discovery 시간
    distro_id = Column(String(50))  # alpine, debian, ubuntu, poky, openwrt 등
    pkg_manager = Column(String(20))  # apk, dpkg, rpm, opkg, none
    arch = Column(String(20))  # x86_64, aarch64, armv7l 등
    kernel_version = Column(String(100))  # 커널 버전
    is_busybox = Column(Boolean, default=False)  # BusyBox 환경 여부
    has_systemd = Column(Boolean, default=True)  # systemd 존재 여부

    packages = relationship("Package", back_populates="host", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="host", cascade="all, delete-orphan")
    scan_history = relationship("ScanHistory", back_populates="host", cascade="all, delete-orphan")
    scan_jobs = relationship("ScanJob", back_populates="host", cascade="all, delete-orphan")
    asset_snapshots = relationship("AssetSnapshot", back_populates="host", cascade="all, delete-orphan")


class Package(Base):
    __tablename__ = "packages"

    id = Column(Integer, primary_key=True, index=True)
    host_id = Column(Integer, ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False)
    scan_id = Column(Integer, ForeignKey("scan_history.id", ondelete="CASCADE"), nullable=True, index=True)  # 스캔별 분리
    name = Column(String(255), nullable=False, index=True)
    version = Column(String(100), nullable=False)
    architecture = Column(String(50))
    package_manager = Column(String(50))
    discovered_at = Column(DateTime, default=get_kst_now)

    host = relationship("Host", back_populates="packages")
    findings = relationship("Finding", back_populates="package")


class CVE(Base):
    __tablename__ = "cves"

    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String(50), unique=True, nullable=False, index=True)
    description = Column(Text)
    published_date = Column(DateTime)
    last_modified = Column(DateTime)
    # === 통합 CVSS (우선순위: v4 > v3.1 > v3.0 > v2) ===
    cvss_score = Column(Float)  # 최종 CVSS 점수 (표시용)
    cvss_severity = Column(String(20))  # 최종 Severity
    cvss_vector = Column(String(255))  # 최종 Vector
    cvss_version = Column(String(10))  # 사용된 CVSS 버전 ("4.0", "3.1", "3.0", "2.0")
    # === CVSS v4.0 ===
    cvss_v4_score = Column(Float)
    cvss_v4_vector = Column(String(255))
    cvss_v4_severity = Column(String(20))
    # === CVSS v3.x (v3.0 또는 v3.1) ===
    cvss_v3_score = Column(Float)
    cvss_v3_vector = Column(String(255))
    cvss_v3_severity = Column(String(20))
    # === CVSS v2 (오래된 CVE용) ===
    cvss_v2_score = Column(Float)
    cvss_v2_vector = Column(String(255))
    cvss_v2_severity = Column(String(20))
    attack_vector = Column(String(50))
    attack_complexity = Column(String(50))
    privileges_required = Column(String(50))
    user_interaction = Column(String(50))
    scope = Column(String(50))
    confidentiality_impact = Column(String(50))
    integrity_impact = Column(String(50))
    availability_impact = Column(String(50))
    cpe_list = Column(Text)
    references = Column(Text)
    # EPSS (Exploit Prediction Scoring System) 점수
    epss_score = Column(Float)  # 0.0 ~ 1.0 (실제 익스플로잇 확률)
    epss_percentile = Column(Float)  # 백분위 (다른 CVE 대비 순위)
    # KEV (Known Exploited Vulnerabilities) 정보
    is_kev = Column(Boolean, default=False)  # CISA KEV 등재 여부
    kev_date_added = Column(String(20))  # KEV 등재일
    kev_due_date = Column(String(20))  # 조치 기한
    kev_ransomware = Column(Boolean, default=False)  # 랜섬웨어 사용 여부
    # Exploit/PoC 정보
    has_exploit = Column(Boolean, default=False)  # Exploit/PoC 존재 여부
    exploit_count = Column(Integer, default=0)  # 공개된 exploit 수
    exploit_sources = Column(String(255))  # exploit 출처 (github,exploitdb,metasploit 등)
    exploit_urls = Column(Text)  # exploit URL 목록 (JSON)
    exploit_last_checked = Column(DateTime)  # 마지막 확인 시간
    created_at = Column(DateTime, default=get_kst_now)

    findings = relationship("Finding", back_populates="cve")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    host_id = Column(Integer, ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False)
    package_id = Column(Integer, ForeignKey("packages.id", ondelete="CASCADE"), nullable=False)
    cve_id = Column(Integer, ForeignKey("cves.id"), nullable=False)
    scan_id = Column(Integer, ForeignKey("scan_history.id", ondelete="CASCADE"), nullable=True, index=True)  # 스캔별 분리
    discovered_at = Column(DateTime, default=get_kst_now)
    status = Column(String(20), default="open")
    risk_level = Column(String(20))
    is_unauthorized_access = Column(Boolean, default=False)
    notes = Column(Text)

    # 패키지 사용 상태 정보
    pkg_is_running = Column(Boolean, default=False)  # 현재 실행 중
    pkg_is_service = Column(Boolean, default=False)  # systemd 서비스 여부
    pkg_is_listening = Column(Boolean, default=False)  # 네트워크 리스닝
    pkg_listening_ports = Column(String(100))  # 리스닝 포트 목록
    pkg_usage_level = Column(String(20))  # active, recent, installed, unused
    pkg_last_used = Column(String(30))  # 마지막 사용 시간

    # 패치 정보
    has_patch_available = Column(Boolean, default=False)  # 패치 가능 여부
    patch_version = Column(String(100))  # 패치 가능 버전
    confidence_level = Column(String(20), default="confirmed")  # confirmed, potential

    # 종합 우선순위
    priority_score = Column(Float)  # 0-100 종합 점수
    priority_level = Column(String(20))  # CRITICAL, HIGH, MEDIUM, LOW

    # 권한 상승 관련
    is_privilege_escalation = Column(Boolean, default=False)  # 권한 상승 취약점 여부
    privesc_reason = Column(String(255))  # 권한 상승 판정 근거

    # 커널 관련
    is_kernel_cve = Column(Boolean, default=False)  # 커널 CVE 여부
    
    # === 신규 필드: 원격 스캔 지원 ===
    collector_mode = Column(String(20), default="local")  # local, pkg, binary, kernel, banner
    evidence = Column(Text)  # 수집 근거 (예: "apk info -v output", "openssl version output")
    data_confidence = Column(String(20), default="high")  # high, medium, low (버전 정보 신뢰도)

    host = relationship("Host", back_populates="findings")
    package = relationship("Package", back_populates="findings")
    cve = relationship("CVE", back_populates="findings")
    scan = relationship("ScanHistory", back_populates="findings")


class ScanHistory(Base):
    __tablename__ = "scan_history"

    id = Column(Integer, primary_key=True, index=True)
    host_id = Column(Integer, ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False)
    scan_started = Column(DateTime, default=get_kst_now)
    scan_completed = Column(DateTime)
    status = Column(String(20), default="running")
    packages_found = Column(Integer, default=0)
    cves_found = Column(Integer, default=0)
    high_risk_count = Column(Integer, default=0)
    error_message = Column(Text)
    current_package = Column(String(255))
    progress_percent = Column(Integer, default=0)
    estimated_time_remaining = Column(Integer, default=0)

    host = relationship("Host", back_populates="scan_history")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")


class ScanJob(Base):
    """스캔 작업 관리 (비동기 작업 상태 추적)"""
    __tablename__ = "scan_jobs"

    id = Column(Integer, primary_key=True, index=True)
    host_id = Column(Integer, ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False, index=True)
    
    # 작업 상태
    status = Column(String(20), default="pending", index=True)  # pending, running, completed, failed, cancelled
    preset = Column(String(20), default="standard")  # fast, standard, deep
    
    # 시간 정보
    created_at = Column(DateTime, default=get_kst_now)
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    
    # 실행자 정보
    initiated_by = Column(String(100), default="system")  # 요청자 (API 키, 사용자명 등)
    
    # 진행 상황
    current_phase = Column(String(50))  # discovery, deepscan, cve_analysis, complete
    progress_percent = Column(Integer, default=0)
    progress_message = Column(String(500))
    
    # 결과 요약
    discovery_result = Column(Text)  # JSON: discovery 결과
    packages_found = Column(Integer, default=0)
    binaries_found = Column(Integer, default=0)
    cves_found = Column(Integer, default=0)
    high_risk_count = Column(Integer, default=0)
    
    # 에러/로그
    error_message = Column(Text)
    log_summary = Column(Text)  # 실행 로그 요약
    
    # 연관 데이터
    scan_history_id = Column(Integer, ForeignKey("scan_history.id", ondelete="SET NULL"))
    snapshot_id = Column(Integer, ForeignKey("asset_snapshots.id", ondelete="SET NULL"))

    host = relationship("Host", back_populates="scan_jobs")


class AssetSnapshot(Base):
    """자산 스냅샷 (Discovery 결과 및 패키지 목록 해시)"""
    __tablename__ = "asset_snapshots"

    id = Column(Integer, primary_key=True, index=True)
    host_id = Column(Integer, ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False, index=True)
    created_at = Column(DateTime, default=get_kst_now)
    
    # Discovery 결과
    os_family = Column(String(20), default="linux")  # linux 고정
    distro_id = Column(String(50))  # alpine, debian, ubuntu, poky, openwrt, unknown
    distro_version = Column(String(50))
    pkg_manager = Column(String(20))  # apk, dpkg, rpm, opkg, none
    arch = Column(String(20))  # x86_64, aarch64, armv7l
    kernel_version = Column(String(100))
    is_busybox = Column(Boolean, default=False)
    has_systemd = Column(Boolean, default=True)
    capabilities = Column(Text)  # JSON: 사용 가능한 명령/경로 목록
    confidence_discovery = Column(String(20), default="high")  # high, medium, low
    raw_os_release = Column(Text)  # /etc/os-release 원본
    
    # 수집 데이터 해시 (캐시 키)
    packages_hash = Column(String(64), index=True)  # SHA256(packages_json)
    binaries_hash = Column(String(64))  # SHA256(binaries_json)
    
    # 수집 데이터 (JSON)
    packages_json = Column(Text)  # 패키지 목록 JSON
    binaries_json = Column(Text)  # 바이너리 버전 정보 JSON
    kernel_modules_json = Column(Text)  # 커널 모듈 목록 JSON
    
    # 수집 메타데이터
    collector_mode = Column(String(20))  # pkg, binary, kernel
    collection_duration_sec = Column(Float)  # 수집 소요 시간
    evidence_summary = Column(Text)  # 수집 근거 요약

    host = relationship("Host", back_populates="asset_snapshots")


class AuditLog(Base):
    """감사 로그 (누가/언제/무엇을/어떻게)"""
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=get_kst_now, index=True)
    
    # 행위자
    actor = Column(String(100), nullable=False)  # 사용자명, API 키, system
    actor_ip = Column(String(45))  # 요청자 IP
    
    # 행위
    action = Column(String(50), nullable=False, index=True)  # scan_start, scan_complete, host_add, host_delete, config_change
    
    # 대상
    target_type = Column(String(50))  # host, scan_job, config
    target_id = Column(Integer)  # 대상 ID (host_id, job_id 등)
    target_name = Column(String(255))  # 대상 이름 (hostname 등)
    
    # 상세 정보
    details = Column(Text)  # JSON: 상세 파라미터/결과
    preset = Column(String(20))  # 스캔 프리셋
    
    # 결과
    result = Column(String(20))  # success, failure, partial
    error_message = Column(Text)
