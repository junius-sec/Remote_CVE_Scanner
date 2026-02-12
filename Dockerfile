# ============================================
# VulnScan Server - Docker Image
# ============================================
# 경량 Python 이미지 기반 + SSH 원격 스캔 지원
# ============================================

FROM python:3.11-slim

LABEL maintainer="vulnscan"
LABEL description="Linux CVE Vulnerability Scanner (Agentless SSH)"

# ── 1) 시스템 패키지 설치 ──
# sshpass: 패스워드 방식 SSH 인증에 필요
# openssh-client: SSH 키 방식 원격 접속에 필요
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    sshpass \
    openssh-client \
    && rm -rf /var/lib/apt/lists/*

# ── 2) 작업 디렉토리 ──
WORKDIR /app

# ── 3) Python 의존성 설치 (캐시 레이어 활용) ──
# requirements.txt가 변경되지 않으면 이 레이어는 캐시됨
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── 4) 소스 코드 복사 ──
COPY main.py .
COPY vulnscan/ ./vulnscan/
COPY static/ ./static/
COPY templates/ ./templates/

# ── 5) 환경변수 파일 복사 (기본값) ──
# .env.example을 .env로 복사 (빌드 시 실제 .env가 없어도 작동)
COPY .env.example .env

# ── 6) 데이터 디렉토리 생성 ──
RUN mkdir -p /app/data /app/vulnscan/cache

# ── 7) NVD 캐시 및 보안 데이터 복사 (선택적) ──
# 캐시 파일이 있으면 복사 (없으면 최초 실행 시 자동 생성)
# 파일이 있으면 즉시 사용 가능, 없으면 약 30-60분 소요
COPY nvd_cache.db* /app/data/ 2>/dev/null || true
COPY kev_cache.json* /app/ 2>/dev/null || true
COPY exploit_cache.json* /app/ 2>/dev/null || true
COPY debian_security_cache.json* /app/ 2>/dev/null || true
COPY ubuntu_security_cache.json* /app/ 2>/dev/null || true

# ── 8) 환경변수 기본값 ──
ENV HOST=0.0.0.0
ENV PORT=8000
ENV DATA_DIR=/app/data

# ── 9) 포트 노출 ──
EXPOSE 8000

# ── 10) 헬스체크 ──
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/docs')" || exit 1

# ── 11) 서버 실행 ──
# uvicorn으로 직접 실행 (0.0.0.0 바인딩 = 컨테이너 외부 접근 허용)
CMD ["python", "-m", "uvicorn", "main:app", \
    "--host", "0.0.0.0", \
    "--port", "8000", \
    "--log-level", "warning", \
    "--no-access-log"]
