# VulnScan 기술 문서

## 목차
1. [아키텍처 개요](#아키텍처-개요)
2. [전체 스캔 로직 흐름](#전체-스캔-로직-흐름)
3. [핵심 모듈별 기능](#핵심-모듈별-기능)
4. [데이터베이스 스키마](#데이터베이스-스키마)
5. [성능 최적화](#성능-최적화)
6. [확장 가능성](#확장-가능성)

---

## 아키텍처 개요

### 시스템 구성

```
┌─────────────────────────────────────────────────────────────┐
│                     웹 브라우저 (UI)                         │
│                   http://localhost:8000                     │
└─────────────────────┬───────────────────────────────────────┘
                      │ HTTP/WebSocket
┌─────────────────────▼───────────────────────────────────────┐
│              FastAPI 서버 (main.py)                         │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  API Routes                                          │   │
│  │  - /api/remote/* (원격 스캔)                         │   │
│  │  - /api/local/*  (로컬 스캔)                         │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│                VulnScan Core Engine                         │
│  ┌──────────────┐  ┌──────────────┐  ┌─────────────────┐   │
│  │  Scanner     │  │   Matcher    │  │  NVD Client     │   │
│  │  (수집)      │  │  (CVE 매칭)  │  │  (CVE 데이터)   │   │
│  └──────┬───────┘  └──────┬───────┘  └────────┬────────┘   │
│         │                 │                    │            │
│  ┌──────▼───────┐  ┌──────▼───────┐  ┌────────▼────────┐   │
│  │ Collectors   │  │ OS Matcher   │  │  EPSS/KEV      │   │
│  │ (SSH/로컬)   │  │ (보안 권고)  │  │  (악용 정보)   │   │
│  └──────┬───────┘  └──────────────┘  └─────────────────┘   │
│         │                                                   │
│  ┌──────▼───────────────────────────────────────────────┐   │
│  │         Parsers (dpkg/rpm/apk)                       │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│                 데이터 저장소                               │
│  ┌──────────────┐  ┌──────────────┐  ┌─────────────────┐   │
│  │ vulnscan.db  │  │nvd_cache.db  │  │ 보안 캐시 JSON  │   │
│  │ (스캔 결과)  │  │(NVD CVE)     │  │ (KEV/Exploit)   │   │
│  └──────────────┘  └──────────────┘  └─────────────────┘   │
└───────────────────────────────────────────────────────────────┘
```

### 주요 디자인 패턴

1. **비동기 I/O**: asyncio 기반으로 SSH, DB, HTTP 모두 non-blocking
2. **배치 처리**: 패키지를 50개씩 묶어서 병렬 처리 (Semaphore로 동시성 제어)
3. **캐시 우선**: NVD, EPSS, KEV 데이터를 로컬 캐시하여 API 호출 최소화
4. **세션 관리**: SQLAlchemy async session with rollback recovery

---

## 전체 스캔 로직 흐름

### 1. 스캔 시작 (Remote Scan)

```
사용자 → [스캔 시작] 버튼 클릭
  ├─ POST /api/remote/scan
  │   └─ Body: { host_id, preset, cve_years }
  │
  ├─ JobRunner.create_job() - 작업 생성 (상태: pending)
  │   └─ DB: Job 레코드 생성
  │
  └─ asyncio.create_task(run_scan_job()) - 백그라운드 실행
```

### 2. 데이터 수집 단계 (Discovery)

```python
# vulnscan/services/remote_scanner.py: RemoteScanner._run_discovery()

SSH 연결
  │
  ├─ 1) OS 정보 수집
  │   ├─ /etc/os-release 파싱
  │   └─ uname -r (커널 버전)
  │
  ├─ 2) 패키지 관리자 탐지
  │   ├─ dpkg --version → DpkgParser
  │   ├─ rpm --version → RpmParser
  │   └─ apk --version → ApkParser
  │
  └─ 3) 패키지 목록 수집
      ├─ dpkg -l (Debian/Ubuntu)
      ├─ rpm -qa (RHEL/CentOS)
      └─ apk info -v (Alpine)
      
결과: List[PackageInfo] (1000-3000개)
```

### 3. 심층 스캔 단계 (Deep Scan)

```python
# vulnscan/collectors/deepscan.py: DeepScanner.scan()

병렬 수집 (asyncio.gather):
  │
  ├─ A) 프로세스 정보 (ps aux)
  │   └─ 실행 중인 패키지 식별
  │
  ├─ B) 네트워크 포트 (ss -tuln)
  │   └─ 리스닝 포트 매칭
  │
  ├─ C) systemd 서비스 (systemctl list-units)
  │   └─ 활성 서비스 매칭
  │
  └─ D) 바이너리 실행 시간 (아직 수집 안 함, CVE 발견 후 수집)

결과: PackageUsageAnalyzer.analyze_package()로 전달
```

### 4. CVE 매칭 단계 (NVD Pipeline)

```python
# vulnscan/core/matcher.py: VulnerabilityMatcher._match_packages_fast()

for batch in packages (50개씩):
    asyncio.gather(
        _process_single_package(pkg1),
        _process_single_package(pkg2),
        ...
    )
    
_process_single_package(pkg):
  │
  ├─ 1) NVD 검색
  │   ├─ CPE Index 조회 (in-memory)
  │   │   └─ "apache2" → cpe:2.3:a:apache:http_server:*
  │   │
  │   ├─ 버전 매칭 (CPE 2.3 matching spec)
  │   │   └─ 2.4.52 in range [2.4.0, 2.4.54) → MATCH
  │   │
  │   └─ 결과: List[CVE]
  │
  ├─ 2) OS CVE 매칭 (옵션)
  │   ├─ Debian Security Tracker
  │   └─ Ubuntu Security Tracker
  │
  ├─ 3) 패치 정보 확인
  │   └─ DSA/USN에 fix 버전 있는지 체크
  │
  └─ 4) Finding 레코드 생성
      └─ DB: Package + CVE → Finding
```

### 5. CVE 발견된 패키지 실행 시간 수집 (Post-scan)

```python
# vulnscan/core/matcher.py: _update_usage_for_cve_packages()

1) CVE 있는 패키지 목록 추출
   └─ SELECT DISTINCT package_name FROM findings WHERE scan_id = ?

2) SSH 1회: dpkg -L로 실제 바이너리 경로 조회
   └─ for pkg in packages:
        dpkg -L pkg | grep -E '^/(usr/)?s?bin/'
        
   결과: {"apache2": ["/usr/sbin/apache2", "/usr/bin/apachectl"]}

3) SSH 1회: stat로 모든 바이너리 atime 수집
   └─ for path in all_binary_paths:
        [ -f "$path" ] && stat -c "%Y %n" "$path"
        
   결과: {"/usr/sbin/apache2": {"timestamp": 1707123456, "last_access": "2024-02-05 14:30"}}

4) Finding 업데이트
   └─ UPDATE findings SET pkg_last_used = ? WHERE package_name = ?
```

### 6. EPSS/KEV 업데이트 (Post-scan)

```python
# vulnscan/core/matcher.py: _batch_update_epss_kev()

1) 현재 스캔의 모든 CVE 추출
2) 배치로 EPSS 점수 조회 (100개씩)
   └─ EPSS API: https://api.first.org/data/v1/epss?cve=CVE-2024-1234,CVE-2024-5678
3) KEV 캐시에서 조회
4) CVE 레코드 업데이트
```

### 7. 결과 저장 및 응답

```
ScanHistory 업데이트
  ├─ total_packages
  ├─ cves_found
  ├─ high_risk_count
  └─ status: completed

JobRunner 상태 업데이트
  └─ status: completed, progress: 100%

웹소켓 or 폴링으로 UI 업데이트
```

---

## 핵심 모듈별 기능

### 📁 main.py
- **역할**: FastAPI 앱 초기화 및 라우트 등록
- **주요 기능**:
  - CORS 설정
  - Static 파일 서빙 (CSS/JS)
  - 템플릿 렌더링 (Jinja2)
  - DB 초기화 (startup event)

### 📁 vulnscan/api/

#### remote_routes.py
- **역할**: 원격 스캔 API 엔드포인트
- **주요 엔드포인트**:
  - `POST /api/remote/hosts` - 호스트 등록
  - `POST /api/remote/scan` - 스캔 시작
  - `GET /api/remote/jobs` - 작업 목록
  - `POST /api/remote/jobs/{job_id}/cancel` - 스캔 취소
  - `GET /api/remote/hosts/{host_id}/findings` - 취약점 조회
  - `GET /api/remote/hosts/{host_id}/scan-history` - 스캔 이력

#### routes.py
- **역할**: 로컬 스캔 및 공통 API
- **주요 엔드포인트**:
  - `POST /api/scan` - 로컬 스캔
  - `GET /api/findings` - 취약점 목록 (정렬/필터)
  - `GET /api/cve/{cve_id}` - CVE 상세 정보
  - `POST /api/poc-search` - PoC 검색

### 📁 vulnscan/core/

#### scanner.py (2127 lines)
- **역할**: 로컬 스캔 오케스트레이터
- **주요 클래스**: `VulnerabilityScanner`
- **핵심 메서드**:
  - `scan_system()` - 전체 스캔 실행
  - `_collect_packages()` - 패키지 수집
  - `_analyze_usage()` - 사용 상태 분석
  - `_run_cve_pipeline()` - CVE 매칭 파이프라인

#### matcher.py (2050 lines)
- **역할**: CVE 매칭 엔진
- **주요 클래스**: `VulnerabilityMatcher`
- **핵심 메서드**:
  - `match_packages()` - NVD 기반 CVE 매칭
  - `_match_packages_fast()` - 배치 병렬 처리
  - `_process_single_package()` - 단일 패키지 CVE 검색
  - `_update_usage_for_cve_packages()` - 실행 시간 수집
  - `_batch_update_epss_kev()` - EPSS/KEV 업데이트
- **성능 최적화**:
  - Semaphore(15): 동시 처리 제한
  - batch_size=50: 50개씩 묶음 처리
  - 200ms sleep: 배치 간 대기

#### nvd_client.py
- **역할**: NVD 데이터베이스 인터페이스
- **주요 기능**:
  - CPE 인덱스 in-memory 로딩
  - 키워드 기반 CVE 검색
  - CPE 2.3 버전 매칭 (versionStartIncluding, versionEndExcluding)
  - NVD API 호출 (API 키 있으면 빠름)

#### os_cve_matcher.py
- **역할**: OS별 보안 권고 매칭
- **지원 OS**:
  - Debian: Debian Security Tracker
  - Ubuntu: Ubuntu Security Notices (USN)
- **기능**:
  - 패키지별 CVE 조회
  - Fix 버전 확인 (패치 가용 여부)

#### kernel_analyzer.py
- **역할**: 커널 CVE 분석
- **기능**:
  - 커널 버전 파싱 (5.15.0-91-generic)
  - 커널 CVE 검색 (linux_kernel CPE)
  - 권한 상승 CVE 식별

#### package_usage_analyzer.py (821 lines)
- **역할**: 패키지 사용 상태 분석
- **주요 기능**:
  - 프로세스 캐시 (ps aux)
  - 바이너리 실행 시간 (stat atime)
  - systemd 서비스 상태
  - 네트워크 리스닝 포트
- **핵심 메서드**:
  - `analyze_package()` - 패키지 사용 분석
  - `load_binary_atimes_for_packages()` - CVE 패키지 실행 시간 수집
  - `_resolve_package_binaries()` - dpkg -L로 바이너리 경로 조회
  - `_load_atimes_for_paths()` - stat로 atime 수집

#### epss_client.py
- **역할**: EPSS (Exploit Prediction Scoring System) 조회
- **데이터 소스**: FIRST.org EPSS API
- **기능**: CVE별 실제 악용 가능성 점수 (0-1)

#### kev_client.py
- **역할**: CISA KEV (Known Exploited Vulnerabilities) 조회
- **데이터 소스**: CISA KEV 카탈로그
- **기능**: 실제 악용된 CVE 식별

#### exploit_client.py
- **역할**: 공개 PoC/Exploit 검색
- **데이터 소스**:
  - ExploitDB 캐시
  - GitHub 검색 (실시간)
- **기능**: CVE별 공개 익스플로잇 개수 및 링크

### 📁 vulnscan/collectors/

#### ssh_exec.py (443 lines)
- **역할**: SSH 명령 실행 추상화
- **주요 클래스**: `SSHExecutor`
- **기능**:
  - 시스템 ssh 우선 사용 (asyncio subprocess)
  - 비밀번호 인증 (sshpass)
  - SSH 키 인증
  - 타임아웃 및 재시도

#### discovery.py
- **역할**: 원격 시스템 정보 탐지
- **수집 항목**:
  - OS 정보 (/etc/os-release)
  - 커널 버전 (uname -r)
  - 패키지 관리자 (dpkg/rpm/apk)
  - 아키텍처 (x86_64/arm64)

#### deepscan.py
- **역할**: 시스템 심층 분석
- **수집 항목**:
  - 실행 중인 프로세스 (ps aux)
  - 네트워크 연결 (ss -tuln)
  - systemd 서비스 (systemctl list-units)
  - 환경 변수 (선택적)

### 📁 vulnscan/parsers/

#### base.py
- **역할**: 패키지 파서 베이스 클래스
- **인터페이스**: `parse_packages()` 추상 메서드

#### dpkg.py
- **역할**: Debian/Ubuntu 패키지 파싱
- **명령**: `dpkg -l`
- **파싱**: 패키지명, 버전, 아키텍처, 설명

#### rpm.py
- **역할**: RHEL/CentOS/Fedora 패키지 파싱
- **명령**: `rpm -qa --queryformat ...`

#### apk.py
- **역할**: Alpine Linux 패키지 파싱
- **명령**: `apk info -v`

### 📁 vulnscan/services/

#### remote_scanner.py (632 lines)
- **역할**: 원격 스캔 오케스트레이터
- **주요 클래스**: `RemoteScanner`
- **스캔 단계**:
  1. Discovery (OS/패키지 정보)
  2. Deep Scan (프로세스/네트워크)
  3. CVE Pipeline (매칭 + EPSS/KEV)
- **취소 지원**: `_check_cancelled()` 주기적 체크

#### job_runner.py (247 lines)
- **역할**: 백그라운드 작업 관리
- **주요 클래스**: `JobRunner`
- **기능**:
  - 작업 생성/취소
  - 진행률 업데이트
  - 동시 작업 수 제한
  - 작업 상태 추적 (pending/running/completed/failed)

### 📁 vulnscan/models/

#### schemas.py
- **역할**: SQLAlchemy ORM 모델
- **주요 테이블**:
  - `Host` - 원격 호스트 정보
  - `ScanHistory` - 스캔 이력
  - `Package` - 패키지 정보
  - `CVE` - CVE 상세 정보
  - `Finding` - 패키지-CVE 매칭 결과
  - `Job` - 백그라운드 작업

#### database.py
- **역할**: DB 연결 및 세션 관리
- **설정**:
  - SQLite + aiosqlite
  - WAL mode (동시성)
  - timeout=60s
  - PRAGMAs 최적화

---

## 데이터베이스 스키마

### ERD (주요 테이블)

```
┌─────────────┐       ┌──────────────┐       ┌─────────────┐
│    Host     │       │ ScanHistory  │       │   Package   │
├─────────────┤       ├──────────────┤       ├─────────────┤
│ id (PK)     │◄──────│ id (PK)      │       │ id (PK)     │
│ hostname    │       │ host_id (FK) │       │ host_id (FK)│
│ ip_address  │       │ scan_date    │       │ name        │
│ ssh_config  │       │ total_pkgs   │       │ version     │
└─────────────┘       │ cves_found   │       │ ...         │
                      │ status       │       └──────┬──────┘
                      └──────┬───────┘              │
                             │                      │
                             │      ┌───────────────▼──────┐
                             │      │     Finding          │
                             │      ├──────────────────────┤
                             └─────►│ id (PK)              │
                                    │ scan_id (FK)         │
                                    │ package_id (FK)      │
                                    │ cve_id (FK)          │◄───┐
                                    │ cvss_score           │    │
                                    │ pkg_is_running       │    │
                                    │ pkg_last_used ★      │    │
                                    │ pkg_usage_level      │    │
                                    └──────────────────────┘    │
                                                                │
                                    ┌──────────────────────┐    │
                                    │        CVE           │    │
                                    ├──────────────────────┤    │
                                    │ id (PK)              │────┘
                                    │ cve_id (UNIQUE)      │
                                    │ cvss_score           │
                                    │ epss_score           │
                                    │ is_kev               │
                                    │ description          │
                                    └──────────────────────┘
```

### 주요 컬럼 설명

**Finding 테이블** (취약점 매칭 결과):
- `pkg_is_running`: 현재 실행 중인지 (Boolean)
- `pkg_last_used`: 최근 실행 시간 (String, "2024-02-12 14:30")
- `pkg_usage_level`: 사용 수준 (recent/installed/unused)
- `pkg_listening_ports`: 리스닝 포트 (쉼표 구분)
- `collector_mode`: 수집 방식 (ssh/local/kernel)
- `data_confidence`: 매칭 신뢰도 (high/medium/low)
- `has_patch_available`: 패치 존재 여부
- `patch_version`: 패치 버전

---

## 성능 최적화

### 1. CVE 매칭 성능

**문제**: 1700개 패키지 × NVD API = 수 시간

**해결책**:
```python
# 1) In-memory CPE Index
nvd_client.load_cpe_index()  # 1회 로딩, 메모리 ~200MB
→ 키워드 검색: O(1)

# 2) 배치 병렬 처리
for batch in chunks(packages, 50):
    asyncio.gather(*[process(pkg) for pkg in batch])
→ 1700개 → 34개 배치

# 3) Semaphore로 동시성 제어
async with semaphore(15):
    ...
→ 동시 15개 제한으로 시스템 부하 방지

# 4) 배치 간 sleep
await asyncio.sleep(0.2)
→ API rate limit 회피
```

**결과**: 1700 패키지 스캔 시간 **~10초** (NVD 캐시 활용)

### 2. 실행 시간 수집 성능

**문제**: 1700개 패키지 각각 SSH 호출 = 수천 번

**해결책**:
```python
# 1) CVE 있는 패키지만 수집
cve_packages = SELECT DISTINCT package_name 
                FROM findings WHERE scan_id = ?
→ 1700개 → 50-200개

# 2) dpkg -L 1회 호출
for p in packages:
    echo "__PKG__:$p"
    dpkg -L "$p" | grep bin/
done
→ SSH 1회로 모든 패키지 바이너리 경로 수집

# 3) stat 1회 호출
for path in all_paths:
    [ -f "$path" ] && stat -c "%Y %n" "$path"
done
→ SSH 1회로 모든 atime 수집
```

**결과**: SSH 호출 **2회**로 모든 실행 시간 수집

### 3. DB 동시성

**문제**: SQLite database locked

**해결책**:
```python
# 1) WAL mode
PRAGMA journal_mode=WAL
→ 읽기/쓰기 동시 가능

# 2) busy_timeout
PRAGMA busy_timeout=60000
→ 60초 대기

# 3) Session rollback recovery
try:
    await session.commit()
except:
    await session.rollback()
→ 에러 시 자동 복구
```

### 4. 캐시 전략

| 데이터 | 캐시 위치 | 갱신 주기 | 크기 |
|--------|-----------|-----------|------|
| NVD CVE | SQLite DB | 일 1회 | 1.1GB |
| EPSS | DB 컬럼 | 스캔 후 | - |
| KEV | JSON 파일 | 주 1회 | 1.1MB |
| ExploitDB | JSON 파일 | 주 1회 | 192KB |
| OS Security | JSON 파일 | 일 1회 | ~100MB |

---

## 확장 가능성

### 1. 새로운 패키지 관리자 추가

```python
# vulnscan/parsers/pacman.py (예시)
class PacmanParser(BaseParser):
    async def parse_packages(self, raw_output):
        # pacman -Q 파싱
        ...
        return [PackageInfo(...)]
```

### 2. 새로운 OS 보안 권고 추가

```python
# vulnscan/core/redhat_security_client.py (예시)
class RedHatSecurityClient:
    async def get_cves_for_package(self, package_name):
        # Red Hat OVAL 파싱
        ...
```

### 3. 커스텀 CVE 소스 추가

```python
# vulnscan/core/custom_cve_client.py
class CustomCVEClient:
    async def search_cve(self, package_name, version):
        # 내부 CVE 데이터베이스 조회
        ...
```

### 4. 알림 시스템 추가

```python
# vulnscan/services/notifier.py
class VulnNotifier:
    async def notify_high_risk(self, findings):
        # Slack/Email/Webhook 알림
        ...
```

### 5. 스케줄링

```python
# vulnscan/services/scheduler.py
from apscheduler.schedulers.asyncio import AsyncIOScheduler

scheduler = AsyncIOScheduler()
scheduler.add_job(scan_all_hosts, 'cron', hour=2)  # 매일 새벽 2시
```

---

## 디버깅 및 로깅

### 로그 레벨

```python
# main.py
import logging
logging.basicConfig(level=logging.INFO)

# 상세 로그
logging.basicConfig(level=logging.DEBUG)
```

### 주요 로그 출처

- `[실행시간]` - package_usage_analyzer.py
- `[dpkg -L]` - package_usage_analyzer.py
- `[CVE 매칭]` - matcher.py
- `[EPSS]` / `[KEV]` - matcher.py
- `[커널]` - kernel_analyzer.py

### 디버그 팁

1. **스캔 속도 느림**: 
   - NVD_API_KEY 설정 확인
   - Semaphore 값 조정 (15 → 10)

2. **DB 잠금**:
   - `cleanup_stuck_scans.py` 실행
   - WAL checkpoint: `PRAGMA wal_checkpoint(TRUNCATE)`

3. **실행 시간 안 나옴**:
   - SSH 연결 확인
   - dpkg 설치 확인
   - 로그에서 `[실행시간]` 출력 확인

---

## 코드 컨벤션

### 파일명
- Snake case: `package_usage_analyzer.py`
- 모듈별 디렉토리: `vulnscan/core/`, `vulnscan/api/`

### 클래스명
- Pascal case: `VulnerabilityMatcher`

### 함수명
- Snake case: `match_packages()`
- Private: `_process_single_package()`

### 비동기
- 모든 I/O는 async/await
- 동기 블로킹 함수는 `asyncio.to_thread()` 사용

### 타입 힌트
```python
async def match_packages(
    self,
    session: AsyncSession,
    packages: List[Dict],
    host_id: int
) -> Dict[str, int]:
    ...
```

---

## 테스트

### 단위 테스트 예시

```python
# tests/test_matcher.py
import pytest
from vulnscan.core.matcher import VulnerabilityMatcher

@pytest.mark.asyncio
async def test_version_matching():
    matcher = VulnerabilityMatcher(...)
    result = matcher._check_version_range("2.4.52", "2.4.0", "2.4.54")
    assert result == True
```

### 통합 테스트

```bash
# 로컬 스캔 테스트
curl -X POST http://localhost:8000/api/scan

# 원격 스캔 테스트
curl -X POST http://localhost:8000/api/remote/scan \
  -H "Content-Type: application/json" \
  -d '{"host_id": 1}'
```

---

## 참고 자료

- **NVD API**: https://nvd.nist.gov/developers
- **EPSS**: https://www.first.org/epss/
- **CISA KEV**: https://www.cisa.gov/known-exploited-vulnerabilities
- **Debian Security**: https://security-tracker.debian.org/
- **Ubuntu Security**: https://ubuntu.com/security/notices
- **CPE 2.3**: https://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir7695.pdf
