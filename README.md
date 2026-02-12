# VulnScan

리눅스 시스템의 CVE 취약점을 원격으로 스캔하는 도구입니다. 에이전트 설치 없이 SSH로 연결하여 패키지 정보를 수집하고, NVD(National Vulnerability Database) 데이터를 기반으로 취약점을 탐지합니다.

## 주요 기능

- 원격 SSH 스캔 (에이전트 불필요)
- NVD CVE 매칭 (1.1GB 로컬 캐시 포함)
- EPSS/KEV 악용 가능성 분석
- 공개 PoC/Exploit 검색
- 패키지 실행 시간 추적 (dpkg -L 기반)
- Docker 지원 (1.7GB 올인원 이미지)
- 웹 대시보드

## 빠른 시작

### Docker로 실행 (권장)

```bash
# 저장소 클론
git clone <repository-url>
cd vulnscan

# 환경 변수 설정 (선택)
cp .env.example .env
# .env 파일에서 NVD_API_KEY 설정 (권장)

# Docker 실행
docker compose up -d

# 브라우저에서 접속
# http://localhost:8000
```

### 로컬 환경에서 실행

```bash
# Python 가상환경 생성
python3 -m venv env
source env/bin/activate

# 의존성 설치
pip install -r requirements.txt
sudo apt install openssh-client sshpass  # SSH 스캔용

# 서버 실행
./start.sh
```

## 시스템 요구사항

- Python 3.11 이상 또는 Docker
- 메모리: 최소 2GB (권장 4GB)
- 디스크: 최소 2GB (NVD 캐시 포함)

## 문서

- [사용 설명서](USER_GUIDE.md): 설치, 사용법, 문제 해결
- [기술 문서](TECHNICAL.md): 아키텍처, 스캔 흐름, 확장 가이드

## 라이선스

MIT License
