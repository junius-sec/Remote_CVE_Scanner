#!/bin/bash
set -e

# ──────────────────────────────────────────────
# SSH CVE Scanner – Docker Entrypoint
# ──────────────────────────────────────────────

DATA_DIR="/app/data"

# ── 데이터 디렉터리 초기화 ──
mkdir -p "$DATA_DIR"

# ── vulnscan.db 심볼릭 링크 (영속 저장소 → 앱 디렉터리) ──
# Docker 재시작해도 스캔 결과가 유지되도록 /app/data/ 에 저장
if [ ! -f "$DATA_DIR/vulnscan.db" ]; then
    echo "[entrypoint] 새 vulnscan.db 생성 예정 (/app/data/vulnscan.db)"
fi

# 기존 vulnscan.db가 앱 디렉터리에 있으면 데이터 디렉터리로 이동
if [ -f /app/vulnscan.db ] && [ ! -L /app/vulnscan.db ]; then
    echo "[entrypoint] vulnscan.db를 데이터 디렉터리로 이동..."
    mv /app/vulnscan.db "$DATA_DIR/vulnscan.db"
fi

# 심볼릭 링크 생성
if [ ! -L /app/vulnscan.db ]; then
    ln -sf "$DATA_DIR/vulnscan.db" /app/vulnscan.db
fi

echo "================================================"
echo "  SSH CVE Scanner"
echo "  http://localhost:${PORT:-8000}"
echo "================================================"

# ── 서버 시작 ──
exec python3 main.py
