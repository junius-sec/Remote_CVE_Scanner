from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.requests import Request
from fastapi.responses import HTMLResponse
from contextlib import asynccontextmanager
from dotenv import load_dotenv
import logging
import asyncio

# Load environment variables from .env file
load_dotenv()

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(message)s'
)
# 외부 라이브러리 로그 줄이기
logging.getLogger("aiosqlite").setLevel(logging.WARNING)
logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)

from vulnscan.api.routes import router
from vulnscan.api.remote_routes import router as remote_router
from vulnscan.models.database import init_db, migrate_db, migrate_cve_cvss_data
from vulnscan.services.job_runner import init_job_runner, get_job_runner


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    await migrate_db()  # Add missing columns to existing tables
    
    # CVSS 마이그레이션을 백그라운드로 실행하여 서버 시작 속도 개선
    asyncio.create_task(migrate_cve_cvss_data())
    
    # JobRunner 초기화 (백그라운드 스캔 작업 처리)
    print("[시스템] JobRunner 초기화 중...")
    await init_job_runner()
    job_runner = get_job_runner()
    print(f"[시스템] JobRunner 초기화 완료")
    
    # Clean up old scan data on startup
    await cleanup_old_data()
    yield
    
    # 종료 시 JobRunner 정리
    print("[시스템] JobRunner 종료 중...")
    if job_runner:
        await job_runner.stop()


async def cleanup_old_data():
    """Note: Scan history is now preserved for comparison feature"""
    # Scan history is no longer deleted automatically
    # Users can manually delete scan records through the UI
    print("[시스템] 스캔 히스토리 보존 모드")


app = FastAPI(
    title="Linux CVE Vulnerability Dashboard",
    version="2.0.0",
    description="Agentless CVE Scanner with Remote Host Support",
    lifespan=lifespan
)

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# 기존 라우터
app.include_router(router)

# 원격 스캔 라우터 (신규)
app.include_router(remote_router)


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/favicon.ico")
async def favicon():
    # 간단한 1x1 투명 favicon 반환 (404 에러 방지)
    from fastapi.responses import Response
    import base64
    
    # 1x1 투명 PNG
    transparent_png = base64.b64decode(
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
    )
    return Response(content=transparent_png, media_type="image/png")


if __name__ == "__main__":
    import uvicorn
    # 127.0.0.1 = localhost 전용 (외부 접근 차단)
    uvicorn.run(
        app, 
        host="127.0.0.1", 
        port=8000,
        log_level="warning",  # HTTP 요청 로그 숨기기
        access_log=False  # access log 완전히 끄기
    )
