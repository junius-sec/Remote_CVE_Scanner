# VulnScan 사용 설명서

리눅스 시스템의 CVE 취약점을 원격으로 스캔하는 도구입니다. 에이전트 설치 없이 SSH로 연결하여 패키지 정보를 수집하고, NVD(National Vulnerability Database) 데이터를 기반으로 취약점을 탐지합니다.

---

## 목차

1. [시작하기](#시작하기)
2. [Docker로 실행](#docker로-실행)
3. [로컬 환경에서 실행](#로컬-환경에서-실행)
4. [기본 사용법](#기본-사용법)
5. [고급 기능](#고급-기능)
6. [문제 해결](#문제-해결)
7. [FAQ](#faq)

---

## 시작하기

### 필요한 것

- **서버 환경**:
  - Python 3.11 이상 또는 Docker
  - 메모리: 최소 2GB (권장 4GB)
  - 디스크: 최소 2GB (NVD 캐시 포함)

- **스캔 대상 시스템**:
  - Linux 배포판 (Debian, Ubuntu, CentOS, Alpine 등)
  - SSH 접근 가능 (포트 22 또는 커스텀 포트)
  - 패키지 관리자: dpkg, rpm, apk 중 하나

- **선택 사항**:
  - NVD API 키 (발급: https://nvd.nist.gov/developers/request-an-api-key)
    - 없으면: 6.5초/CVE
    - 있으면: 0.6초/CVE

---

## Docker로 실행

### 1단계: 이미지 빌드

```bash
# 저장소 클론 (또는 소스코드 다운로드)
cd vulnscan

# Docker 이미지 빌드 (최초 1회, 2-3분 소요)
docker compose build
```

**이미지 크기**: 약 1.7GB
- Python 런타임: ~400MB
- NVD 데이터베이스: ~1.1GB
- 보안 캐시 (KEV, ExploitDB 등): ~100MB

### 2단계: 환경 설정

```bash
# .env 파일 생성 (이미 있으면 스킵)
cp .env.example .env

# NVD API 키 입력 (선택, 권장)
nano .env
```

`.env` 파일 예시:
```env
NVD_API_KEY=여기에_발급받은_키_입력
```

### 3단계: 서버 시작

```bash
# 백그라운드로 시작
docker compose up -d

# 로그 확인
docker compose logs -f

# 서버 중지
docker compose down
```

### 4단계: 웹 접속

브라우저에서 http://localhost:8000 열기

---

## 로컬 환경에서 실행

### 1단계: Python 가상환경 설정

```bash
# Python 3.11+ 설치 확인
python3 --version

# 가상환경 생성
python3 -m venv env

# 가상환경 활성화
source env/bin/activate  # Linux/Mac
# 또는
env\Scripts\activate  # Windows
```

### 2단계: 의존성 설치

```bash
# Python 패키지 설치
pip install -r requirements.txt

# 시스템 패키지 설치 (SSH 원격 스캔용)
sudo apt install openssh-client sshpass  # Debian/Ubuntu
# 또는
sudo yum install openssh-clients sshpass  # RHEL/CentOS
```

### 3단계: 환경 설정

```bash
# .env 파일 생성
cp .env.example .env

# NVD API 키 설정 (선택)
nano .env
```

### 4단계: 서버 실행

```bash
# 방법 1: start.sh 스크립트
./start.sh

# 방법 2: 직접 실행
python main.py

# 방법 3: uvicorn으로 실행
uvicorn main:app --host 0.0.0.0 --port 8000
```

서버가 시작되면 http://localhost:8000 접속

---

## 기본 사용법

### 1️⃣ 원격 호스트 등록

1. 웹 대시보드 접속 (http://localhost:8000)
2. 좌측 사이드바 **"+ 호스트 추가"** 버튼 클릭
3. SSH 연결 정보 입력:

   | 항목 | 설명 | 예시 |
   |------|------|------|
   | 호스트명 | 표시 이름 | `Production Server` |
   | IP/호스트 | SSH 접속 주소 | `192.168.1.100` |
   | 포트 | SSH 포트 (기본 22) | `22` |
   | 사용자명 | SSH 로그인 계정 | `root` 또는 `ubuntu` |
   | 인증 방식 | SSH 키 / 비밀번호 | `SSH 키` (권장) |

4. **SSH 키 인증 사용 시**:
   ```bash
   # 키 생성 (없으면)
   ssh-keygen -t rsa -b 4096
   
   # 공개키 복사
   ssh-copy-id user@192.168.1.100
   
   # 키 경로 입력
   # 예: /home/user/.ssh/id_rsa
   ```

5. **비밀번호 인증 사용 시**:
   - 비밀번호 입력
   - `sshpass` 패키지 필요

6. **"저장"** 클릭

### 2️⃣ 스캔 실행

1. 등록된 호스트 목록에서 대상 선택
2. 우측 패널 상단 **"스캔 시작"** 버튼 클릭
3. 스캔 옵션 선택:

   **CVE 조회 년도**:
   - `모든 년도` (기본): 전체 NVD 데이터베이스 검색
   - `2020년부터`: 2020년 이후 CVE만 검색 (빠름)
   - 최근 데이터만 필요하면 년도 제한 권장

4. 스캔 진행 상태 확인:
   ```
   ┌─────────────────────────────────┐
   │ 스캔 진행 중... 75%              │
   │ ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓░░░░░             │
   │ 단계: CVE 매칭 중 (1200/1700)   │
   └─────────────────────────────────┘
   ```

5. 스캔 시간:
   - 패키지 1000개 기준: 약 5-10초
   - 패키지 3000개 기준: 약 15-30초

### 3️⃣ 결과 확인

스캔 완료 후 **취약점 목록** 테이블에 결과 표시:

| 패키지 | 버전 | CVE ID | CVSS | EPSS | KEV | PoC | 실행상태 |
|--------|------|--------|------|------|-----|-----|----------|
| apache2 | 2.4.52 | CVE-2024-1234 | 9.8 | 0.85% | - | 3 | 2024-02-10 14:30 |
| openssl | 1.1.1f | CVE-2023-5678 | 7.5 | 2.3% | KEV | 1 | 실행중 |

**컬럼 설명**:
- **CVSS**: 취약점 심각도 (0-10, 높을수록 위험)
  - 9.0-10.0: Critical (빨강)
  - 7.0-8.9: High (주황)
  - 4.0-6.9: Medium (노랑)
  - 0.1-3.9: Low (회색)

- **EPSS**: 30일 내 실제 악용 확률 (0-100%)
  - 높을수록 위험

- **KEV**: CISA Known Exploited Vulnerabilities
  - 실제 공격에 사용된 CVE

- **PoC**: 공개 익스플로잇 코드 개수
  - 클릭하면 GitHub, ExploitDB 링크 표시

- **실행상태**:
  - `실행중`: 현재 프로세스 실행 중
  - `2024-02-10 14:30`: 최근 실행 시간
  - `-`: 실행 정보 없음 (라이브러리 패키지)

### 4️⃣ 상세 정보 보기

1. CVE ID 클릭 → CVE 상세 팝업
   - 설명 (Description)
   - 영향받는 제품 (Affected Products)
   - 참조 링크 (References)
   - CWE 정보

2. **PoC 검색** 버튼:
   - ExploitDB 검색 결과
   - GitHub 저장소 링크
   - Metasploit 모듈 (있으면)

### 5️⃣ 결과 내보내기

1. 우측 상단 **"CSV 내보내기"** 버튼 클릭
2. `scan_results_20240212.csv` 다운로드
3. Excel, Google Sheets로 열어서 분석 가능

---

## 고급 기능

### 정렬 및 필터링

**정렬**:
- 테이블 헤더 클릭으로 정렬
  - CVSS 내림차순 (기본)
  - EPSS 내림차순
  - 패키지명 오름차순

**필터**:
- 상단 필터 버튼:
  - `HIGH`: CVSS 7.0 이상
  - `MED`: CVSS 4.0-6.9
  - `LOW`: CVSS 0.1-3.9

### 스캔 히스토리

1. 좌측 사이드바 **"스캔 이력"** 클릭
2. 과거 스캔 결과 목록:
   - 날짜/시간
   - 발견된 CVE 개수
   - 고위험 CVE 개수
   - 스캔 시간

3. 이력 클릭 → 해당 시점 결과 조회

### 통계 대시보드

상단 통계 카드:
```
┌──────────────┬──────────────┬──────────────┬──────────────┐
│ 전체 패키지   │ 취약점 발견   │ 고위험 (>7.0) │ KEV CVE      │
│    1,723     │     142      │      23      │      5       │
└──────────────┴──────────────┴──────────────┴──────────────┘
```

### 스캔 취소

스캔 중 **"취소"** 버튼 클릭:
- 진행 중인 CVE 매칭 중단
- 이미 수집된 데이터는 유지
- 부분 결과 확인 가능

### 여러 호스트 관리

1. 호스트별 독립적인 스캔 이력 유지
2. 호스트 그룹핑 (추후 지원 예정)
3. 일괄 스캔 (추후 지원 예정)

---

## 문제 해결

### SSH 연결 실패

**증상**: "SSH 연결 실패" 오류

**해결**:
1. 대상 시스템 SSH 접속 테스트:
   ```bash
   ssh user@192.168.1.100
   ```

2. SSH 키 권한 확인:
   ```bash
   chmod 600 ~/.ssh/id_rsa
   ls -la ~/.ssh/id_rsa
   # -rw------- 1 user user (올바른 권한)
   ```

3. 방화벽 확인:
   ```bash
   # 대상 시스템에서
   sudo ufw status
   sudo firewall-cmd --list-all
   ```

4. sshd 실행 확인:
   ```bash
   # 대상 시스템에서
   sudo systemctl status sshd
   ```

### 스캔이 매우 느림

**증상**: 1000개 패키지 스캔에 5분 이상 소요

**원인**: NVD API 키 미설정

**해결**:
1. `.env` 파일 확인:
   ```bash
   cat .env | grep NVD_API_KEY
   ```

2. API 키 발급:
   - https://nvd.nist.gov/developers/request-an-api-key
   - 이메일로 즉시 발급

3. `.env` 파일 업데이트:
   ```env
   NVD_API_KEY=abcd1234-xxxx-yyyy-zzzz-123456789abc
   ```

4. 서버 재시작:
   ```bash
   docker compose restart  # Docker
   # 또는
   ./start.sh  # 로컬
   ```

### "Database is locked" 오류

**증상**: SQLite database locked 에러

**해결**:
```bash
# 방법 1: cleanup 스크립트 실행
python3 cleanup_stuck_scans.py

# 방법 2: 서버 재시작
docker compose restart

# 방법 3: DB 체크포인트 (고급)
sqlite3 vulnscan.db "PRAGMA wal_checkpoint(TRUNCATE);"
```

### 실행 시간이 모두 "-"로 표시

**증상**: 모든 패키지의 "실행상태" 컬럼이 `-`

**원인**: dpkg/stat 명령 실패 또는 라이브러리 패키지

**확인**:
1. 대상 시스템에 dpkg 설치 여부:
   ```bash
   ssh user@host "which dpkg"
   ```

2. 로그 확인:
   ```bash
   docker compose logs -f | grep "실행시간"
   ```

   정상 출력 예시:
   ```
   [실행시간] CVE 발견된 45개 패키지의 바이너리 최근 실행 시간 수집 중...
   [dpkg -L] 42/45개 패키지에서 128개 실행파일 발견
   [실행시간] 128개 실행파일 atime 수집 완료
   [실행시간] 38/45개 패키지 매칭 완료
   ```

3. 라이브러리 패키지는 정상:
   - `libssl3`: 실행파일 없음 → `-` 정상
   - `apache2`: 실행파일 있음 → 시간 표시되어야 함

### Docker 빌드 실패

**증상**: `COPY` 실패 또는 파일 없음

**해결**:
1. 필수 파일 확인:
   ```bash
   ls -lh nvd_cache.db kev_cache.json exploit_cache.json
   ```

2. 빌드 캐시 삭제 후 재시도:
   ```bash
   docker compose build --no-cache
   ```

3. 디스크 공간 확인:
   ```bash
   df -h
   # 최소 3GB 필요
   ```

### 포트 충돌

**증상**: "Address already in use" 에러

**해결**:
1. 8000 포트 사용 중인 프로세스 확인:
   ```bash
   sudo lsof -i :8000
   # 또는
   sudo netstat -tulpn | grep :8000
   ```

2. 포트 변경:
   ```yaml
   # docker-compose.yml
   ports:
     - "8080:8000"  # 호스트 포트를 8080으로 변경
   ```

   접속: http://localhost:8080

---

## FAQ

### Q1. NVD API 키가 없어도 되나요?

**A**: 네, 작동합니다. 하지만 스캔 속도가 매우 느립니다.
- API 키 없음: 6.5초/CVE (rate limit)
- API 키 있음: 0.6초/CVE
- 1000개 패키지 스캔 시간: 없음(60분) vs 있음(5분)

### Q2. Raspberry Pi 같은 ARM 시스템도 스캔 가능한가요?

**A**: 네, 가능합니다. 대상 시스템 아키텍처는 상관없습니다.
- x86_64, ARM64, ARMv7 모두 지원
- 패키지 관리자(dpkg/rpm/apk)만 있으면 됨

### Q3. 여러 시스템을 동시에 스캔할 수 있나요?

**A**: 현재는 순차 스캔만 지원합니다.
- 호스트별로 개별 스캔 실행
- 동시 스캔 기능은 추후 업데이트 예정

### Q4. 스캔 결과는 어디에 저장되나요?

**A**: SQLite 데이터베이스에 저장됩니다.
- 파일: `vulnscan.db` (또는 `/app/data/vulnscan.db` in Docker)
- Docker: 볼륨 마운트로 호스트에 유지
- 백업: `cp vulnscan.db vulnscan_backup_20240212.db`

### Q5. 패치 정보는 제공하나요?

**A**: 일부 OS에서 제공합니다.
- Debian: Debian Security Tracker (DSA)
- Ubuntu: Ubuntu Security Notices (USN)
- RHEL/CentOS: 추후 지원 예정
- 패치 버전 표시 (있으면)

### Q6. CVSS 점수가 여러 버전(v2, v3, v4)이 있는데 어떤 것을 사용하나요?

**A**: 우선순위:
1. CVSS v4.0 (최신, 있으면)
2. CVSS v3.1/v3.0
3. CVSS v2.0 (fallback)

테이블에는 가장 높은 버전 점수를 표시합니다.

### Q7. KEV(Known Exploited Vulnerabilities)는 무엇인가요?

**A**: CISA에서 관리하는 "실제로 공격에 사용된 CVE" 목록입니다.
- 출처: https://www.cisa.gov/known-exploited-vulnerabilities
- KEV 배지가 있으면 우선 패치 권장
- 약 1000개 CVE 등록 (계속 업데이트)

### Q8. EPSS 점수는 어떻게 활용하나요?

**A**: 악용 가능성 예측 점수입니다.
- 범위: 0-100%
- 높을수록 30일 내 악용될 확률이 높음
- CVSS는 심각도, EPSS는 악용 가능성
- 둘 다 높으면 최우선 패치

### Q9. 커널 취약점도 탐지하나요?

**A**: 네, 지원합니다.
- `uname -r`로 커널 버전 수집
- linux_kernel CPE로 매칭
- 권한 상승(privilege escalation) CVE 식별
- 커널 업데이트 권장 사항 표시

### Q10. 오프라인 환경에서도 사용 가능한가요?

**A**: 가능하지만 제한적입니다.
- NVD 캐시 DB는 이미지에 포함 (오프라인 OK)
- EPSS/KEV 업데이트 불가 (캐시 사용)
- PoC 실시간 검색 불가
- 초기 NVD 캐시만 있으면 기본 스캔 가능

### Q11. 스캔 시 대상 시스템에 부하가 가나요?

**A**: 매우 적습니다.
- SSH 명령: 3-5회
  - `dpkg -l` (1회)
  - `ps aux` (1회)
  - `dpkg -L + stat` (CVE 있으면 2회)
- 네트워크: 수백 KB
- CPU: 거의 없음 (단순 파일 읽기)

### Q12. Windows 서버도 스캔할 수 있나요?

**A**: 아니요, Linux 전용입니다.
- Windows는 패키지 관리자 구조가 다름
- Windows 지원은 별도 프로젝트 필요

### Q13. 스캔 스케줄링(자동 스캔)이 가능한가요?

**A**: 현재는 수동 실행만 지원합니다.
- cron + API 호출로 간접 구현 가능:
  ```bash
  # crontab -e
  0 2 * * * curl -X POST http://localhost:8000/api/remote/scan -d '{"host_id": 1}'
  ```
- 내장 스케줄러는 추후 업데이트 예정

### Q14. 알림(Slack, Email) 기능이 있나요?

**A**: 현재는 없습니다. 추후 업데이트 예정입니다.
- Webhook API는 제공 가능:
  ```python
  # 스캔 완료 후 webhook 호출
  POST https://your-webhook.com/vulnscan
  Body: { "host_id": 1, "cves_found": 142, "high_risk": 23 }
  ```

### Q15. 라이선스는 무엇인가요?

**A**: MIT License (오픈소스)
- 상업적 사용 가능
- 수정/배포 자유
- 저작권 표시만 유지

---

## 추가 도움말

### 로그 확인

**Docker:**
```bash
# 전체 로그
docker compose logs

# 실시간 로그
docker compose logs -f

# 최근 100줄
docker compose logs --tail=100
```

**로컬:**
```bash
# 서버 로그
tail -f server.log

# 또는 직접 실행 시 터미널 출력
```

### 데이터 백업

```bash
# DB 백업
cp vulnscan.db vulnscan_backup_$(date +%Y%m%d).db

# Docker 볼륨 백업
docker compose down
tar -czf vulnscan_backup.tar.gz vulnscan.db nvd_cache.db *.json
docker compose up -d
```

### 성능 튜닝

`vulnscan/core/matcher.py` 수정:
```python
# 동시 처리 수 조정 (기본 15)
self.max_concurrent = 10  # 느린 네트워크면 줄임

# 배치 크기 조정 (기본 50)
batch_size = 30  # 메모리 부족하면 줄임
```

### API 직접 사용

```bash
# 호스트 목록
curl http://localhost:8000/api/remote/hosts

# 스캔 시작
curl -X POST http://localhost:8000/api/remote/scan \
  -H "Content-Type: application/json" \
  -d '{"host_id": 1, "preset": "deep"}'

# 취약점 조회
curl http://localhost:8000/api/remote/hosts/1/findings

# CVE 상세
curl http://localhost:8000/api/cve/CVE-2024-1234
```

### 커뮤니티

- **GitHub Issues**: 버그 리포트 및 기능 요청
- **문서**: `/docs` 엔드포인트 (FastAPI 자동 생성)
- **API 문서**: http://localhost:8000/docs

---

## 버전 히스토리

### v1.0.0 (2024-02-12)
- 원격 SSH 스캔
- NVD CVE 매칭
- EPSS/KEV 통합
- PoC 검색
- 패키지 실행 시간 추적
- Docker 지원
- 웹 대시보드

### 향후 계획
- 스캔 스케줄링
- 알림 시스템 (Slack, Email)
- 일괄 스캔
- 보고서 생성 (PDF)
- RHEL/CentOS 보안 권고 지원
- 컨테이너 이미지 스캔

---

**문의**: GitHub Issues 또는 프로젝트 관리자
