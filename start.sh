#!/bin/bash

# 8000 포트 사용 중인 프로세스 강제 종료
echo "포트 8000 정리 중..."
lsof -ti:8000 | xargs -r kill -9 2>/dev/null

# 잠시 대기
sleep 1

# 서버 시작
echo "서버 시작 중..."
python3 main.py
