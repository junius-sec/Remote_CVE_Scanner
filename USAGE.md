# SSH CVE Scanner – 사용 가이드

> **Agentless SSH 기반 Linux 취약점 스캐너**
> 원격 호스트에 SSH로 접속하여 패키지 목록을 수집하고, NVD/EPSS/KEV 데이터와 매칭하여 CVE 취약점을 분석합니다.

---

## 📋 목차

1. [사전 요구사항](#사전-요구사항)
2. [🐳 Docker로 실행 (권장)](#-docker로-실행-권장)
3. [🐍 Python3로 직접 실행](#-python3로-직접-실행)
4. [⚙️ 환경 변수 설정](#️-환경-변수-설정)
5. [🌐 웹 대시보드 접속](#-웹-대시보드-접속)
6. [❓ FAQ / 트러블슈팅](#-faq--트러블슈팅)

---

## 사전 요구사항

| 항목 | Docker 방식 | Python 직접 실행 |
|------|------------|-----------------|
| OS | Windows / Linux / macOS | Linux (권장) / macOS |
| Docker | ✅ 필수 (Docker Desktop 또는 Docker Engine) | ❌ 불필요 |
| Python | ❌ 불필요 | ✅ Python 3.10 이상 |
| Git LFS | ✅ 클론 시 필요 | ✅ 클론 시 필요 |
| NVD API Key | 선택 (없어도 동작) | 선택 (없어도 동작) |

---

## 🐳 Docker로 실행 (권장)

**가장 간단한 방법입니다. OS에 관계없이 동일하게 동작합니다.**

### 1단계: 저장소 클론

```bash
# Git LFS가 설치되어 있어야 합니다
git lfs install
git clone https://github.com/junius-sec/ssh_cve_scanner.git
cd ssh_cve_scanner
```

### 2단계: 환경 변수 설정

```bash
# .env.example을 복사하여 .env 파일 생성
cp .env.example .env

# .env 파일을 열어 NVD API Key 입력 (선택사항)
# NVD_API_KEY=your_key_here
```

> 💡 **NVD API Key가 없어도 동작합니다.** 다만 NVD 데이터 업데이트 시 속도 제한이 있을 수 있습니다.
> API Key는 [NVD 공식 사이트](https://nvd.nist.gov/developers/request-an-api-key)에서 무료로 발급받을 수 있습니다.

### 3단계: 실행 (딸깍!)

```bash
docker compose up -d
```

끝입니다! 🎉

### 접속

브라우저에서 **http://localhost:8000** 으로 접속하세요.

### 종료

```bash
docker compose down
```

### 로그 확인

```bash
docker compose logs -f
```

### 업데이트

```bash
git pull
docker compose up -d --build
```

---

## 🐍 Python3로 직접 실행

**Linux 환경에서 Docker 없이 직접 실행하는 방법입니다.**

### 1단계: 저장소 클론

```bash
git lfs install
git clone https://github.com/junius-sec/ssh_cve_scanner.git
cd ssh_cve_scanner
```

### 2단계: 시스템 패키지 설치

```bash
# Debian / Ubuntu
sudo apt-get update
sudo apt-get install -y sshpass

# RHEL / CentOS / Fedora
sudo yum install -y sshpass
# 또는
sudo dnf install -y sshpass
```

### 3단계: Python 가상환경 구성

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 4단계: 환경 변수 설정

```bash
cp .env.example .env
# .env 파일을 편집하여 NVD_API_KEY 입력 (선택사항)
```

### 5단계: 실행

```bash
# 방법 1: start.sh 사용
chmod +x start.sh
./start.sh

# 방법 2: 직접 실행
python3 main.py
```

### 접속

브라우저에서 **http://localhost:8000** 으로 접속하세요.

> ⚠️ **참고:** Python 직접 실행 시 기본 바인딩은 `127.0.0.1` (로컬 전용)입니다.
> 외부에서 접근하려면 환경변수를 설정하세요:
> ```bash
> HOST=0.0.0.0 python3 main.py
> ```

---

## ⚙️ 환경 변수 설정

| 변수명 | 기본값 | 설명 |
|--------|--------|------|
| `NVD_API_KEY` | (없음) | NVD API 키 – 데이터 업데이트 속도 향상 |
| `HOST` | `127.0.0.1` | 서버 바인딩 주소 (Docker는 자동으로 `0.0.0.0`) |
| `PORT` | `8000` | 서버 포트 번호 |

---

## 🌐 웹 대시보드 접속

실행 후 브라우저에서 아래 주소로 접속하세요:

```
http://localhost:8000
```

주요 기능:
- 🔍 **원격 호스트 SSH 스캔** – SSH 정보 입력만으로 취약점 분석
- 📊 **CVE 대시보드** – CVSS, EPSS, KEV 기반 위험도 시각화
- 📄 **PDF 리포트** – 스캔 결과 PDF 다운로드

---

## ❓ FAQ / 트러블슈팅

### Q: `git clone` 시 대용량 파일이 다운로드되지 않아요

```bash
# Git LFS 설치 확인
git lfs install

# LFS 파일만 별도 다운로드
git lfs pull
```

### Q: Docker 빌드가 너무 오래 걸려요

최초 빌드 시 NVD 캐시 DB(~1.1GB)를 이미지에 포함하므로 시간이 걸릴 수 있습니다.
이후 재빌드는 Docker 레이어 캐싱으로 빠르게 완료됩니다.

### Q: Windows에서 `Permission denied` 오류가 발생해요

Docker Desktop의 Settings → Resources → File sharing에서 프로젝트 폴더가 공유되어 있는지 확인하세요.

### Q: 포트 8000이 이미 사용 중이에요

```bash
# Docker 방식 – docker-compose.yml에서 포트 변경
# ports: "9000:8000" 으로 수정 후 docker compose up -d

# Python 방식
PORT=9000 python3 main.py
```

### Q: Linux에서 SQLite DB 관련 오류가 발생해요

Docker 사용을 권장합니다. Docker 이미지에는 호환성이 검증된 SQLite 버전이 포함되어 있습니다.
Python 직접 실행 시에는 아래 명령으로 시스템 SQLite를 업데이트하세요:

```bash
sudo apt-get install -y sqlite3 libsqlite3-dev
```

### Q: 스캔 결과 데이터는 어디에 저장되나요?

| 실행 방식 | 저장 위치 |
|-----------|----------|
| Docker | Docker Volume (`scanner-data`) – 컨테이너 재시작해도 유지 |
| Python | 프로젝트 디렉터리의 `vulnscan.db` |
