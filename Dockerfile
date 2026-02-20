# ──────────────────────────────────────────────
# SSH CVE Scanner – Docker Build
# 지원: linux/amd64, linux/arm64 (Windows Docker Desktop 포함)
# ──────────────────────────────────────────────
FROM python:3.11-slim-bookworm

LABEL maintainer="junius-sec"
LABEL description="Agentless SSH CVE Vulnerability Scanner"

# ── 환경 변수 ──
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOST=0.0.0.0 \
    PORT=8000 \
    DEBIAN_FRONTEND=noninteractive

# ── OS 의존성 설치 ──
# sshpass: 원격 SSH 스캔에 필요
# sqlite3: DB 디버깅 / 호환성
# lsof: 포트 정리(start.sh)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    sshpass \
    openssh-client \
    sqlite3 \
    lsof \
    curl \
    && rm -rf /var/lib/apt/lists/*

# ── 작업 디렉터리 ──
WORKDIR /app

# ── Python 의존성 (레이어 캐싱 활용) ──
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── 애플리케이션 소스 복사 ──
COPY main.py .
COPY vulnscan/ ./vulnscan/
COPY static/ ./static/
COPY templates/ ./templates/
COPY start.sh .
COPY .env .

# ── 캐시/DB 파일은 포함하지 않음 ──
# nvd_cache.db, *_security_cache.json, exploit_cache.json, kev_cache.json 등
# → 실행 시 자동 생성되며, NVD/Debian/CISA 등에서 자동 다운로드됩니다.

# ── 엔트리포인트 권한 설정 (CRLF → LF 변환 포함) ──
COPY entrypoint.sh /entrypoint.sh
RUN sed -i 's/\r$//' /entrypoint.sh && chmod +x /entrypoint.sh
RUN sed -i 's/\r$//' start.sh && chmod +x start.sh

# ── 데이터 볼륨 (스캔 결과 DB 영속화) ──
VOLUME ["/app/data"]

EXPOSE 8000

ENTRYPOINT ["/entrypoint.sh"]
