from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from .schemas import Base
import os

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./vulnscan.db")

# Configure SQLite for better concurrency
engine = create_async_engine(
    DATABASE_URL,
    echo=False,
    future=True,
    connect_args={
        "timeout": 30,  # Increase timeout to 30 seconds
        "check_same_thread": False,
    }
)

async_session_maker = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False
)


async def init_db():
    async with engine.begin() as conn:
        # Enable WAL mode for better concurrency
        await conn.execute(text("PRAGMA journal_mode=WAL"))
        await conn.execute(text("PRAGMA synchronous=NORMAL"))
        await conn.execute(text("PRAGMA cache_size=-64000"))  # 64MB cache
        await conn.execute(text("PRAGMA busy_timeout=30000"))  # 30 second timeout

        await conn.run_sync(Base.metadata.create_all)


async def get_db():
    async with async_session_maker() as session:
        try:
            yield session
        finally:
            await session.close()


async def migrate_cve_cvss_data():
    """Migrate CVE CVSS data from nvd_cache.db to vulnscan.db"""
    import sqlite3
    import json
    from pathlib import Path
    
    # Check if migration was already completed
    migration_flag = Path(".cvss_migration_done")
    if migration_flag.exists():
        return  # Already migrated
    
    # Check if nvd_cache.db exists
    nvd_cache_path = Path("nvd_cache.db")
    if not nvd_cache_path.exists():
        return
    
    print("[Background] Checking CVE CVSS data migration...")
    
    # Connect to both databases
    nvd_conn = sqlite3.connect('nvd_cache.db')
    nvd_cursor = nvd_conn.cursor()
    vuln_conn = sqlite3.connect('vulnscan.db')
    vuln_cursor = vuln_conn.cursor()
    
    try:
        # Check how many CVEs need updating
        vuln_cursor.execute("SELECT COUNT(*) FROM cves WHERE cvss_score IS NULL")
        null_count = vuln_cursor.fetchone()[0]
        
        if null_count == 0:
            print("[Background] All CVEs already have CVSS scores, skipping migration")
            # Create migration flag file
            from pathlib import Path
            Path(".cvss_migration_done").touch()
            return
        
        print(f"[Background] Found {null_count} CVEs with missing CVSS scores, updating...")
        
        # Get all CVEs that need updating
        vuln_cursor.execute("SELECT cve_id FROM cves WHERE cvss_score IS NULL")
        null_cves = {row[0] for row in vuln_cursor.fetchall()}
        
        # Load all CVE data from nvd_cache
        all_cve_data = {}
        nvd_cursor.execute("SELECT keyword, cves FROM nvd_cache WHERE keyword LIKE '__year_%'")
        for keyword, cves_json in nvd_cursor.fetchall():
            cves = json.loads(cves_json)
            for cve in cves:
                cve_id = cve.get('cve_id')
                if cve_id and cve_id in null_cves:
                    all_cve_data[cve_id] = cve
        
        # Update CVEs
        updated = 0
        for cve_id, cve_data in all_cve_data.items():
            cvss_score = cve_data.get('cvss_score') or cve_data.get('cvss_v3_score') or cve_data.get('cvss_v2_score')
            
            if cvss_score:
                vuln_cursor.execute("""
                    UPDATE cves SET 
                        cvss_score = ?,
                        cvss_severity = ?,
                        cvss_vector = ?,
                        cvss_version = ?,
                        cvss_v4_score = ?,
                        cvss_v4_severity = ?,
                        cvss_v4_vector = ?,
                        cvss_v3_score = ?,
                        cvss_v3_severity = ?,
                        cvss_v3_vector = ?,
                        cvss_v2_score = ?,
                        cvss_v2_severity = ?,
                        cvss_v2_vector = ?
                    WHERE cve_id = ?
                """, (
                    cvss_score,
                    cve_data.get('cvss_severity') or cve_data.get('cvss_v3_severity') or cve_data.get('cvss_v2_severity'),
                    cve_data.get('cvss_vector') or cve_data.get('cvss_v3_vector') or cve_data.get('cvss_v2_vector'),
                    cve_data.get('cvss_version'),
                    cve_data.get('cvss_v4_score'),
                    cve_data.get('cvss_v4_severity'),
                    cve_data.get('cvss_v4_vector'),
                    cve_data.get('cvss_v3_score'),
                    cve_data.get('cvss_v3_severity'),
                    cve_data.get('cvss_v3_vector'),
                    cve_data.get('cvss_v2_score'),
                    cve_data.get('cvss_v2_severity'),
                    cve_data.get('cvss_v2_vector'),
                    cve_id
                ))
                updated += 1
        
        vuln_conn.commit()
        print(f"[Background] CVE CVSS migration completed: {updated} CVEs updated")
        
        # Create migration flag file
        from pathlib import Path
        Path(".cvss_migration_done").touch()
        
    finally:
        nvd_conn.close()
        vuln_conn.close()


async def migrate_db():
    """Add missing columns to existing tables"""
    async with engine.begin() as conn:
        # List of columns to add to hosts table with their SQL definitions
        host_columns = [
            ("is_allowed", "BOOLEAN DEFAULT 1"),
            ("ssh_port", "INTEGER DEFAULT 22"),
            ("ssh_username", "VARCHAR"),
            ("auth_method", "VARCHAR DEFAULT 'key'"),
            ("ssh_key_path", "VARCHAR"),
            ("ssh_password", "VARCHAR"),
            ("tags", "VARCHAR"),
            ("owner", "VARCHAR"),
            ("description", "VARCHAR"),
            ("last_discovery", "DATETIME"),
            ("distro_id", "VARCHAR"),
            ("pkg_manager", "VARCHAR"),
            ("arch", "VARCHAR"),
            ("kernel_version", "VARCHAR"),
            ("is_busybox", "BOOLEAN DEFAULT 0"),
            ("has_systemd", "BOOLEAN DEFAULT 1"),
            ("network_segment", "VARCHAR DEFAULT 'isolated'"),  # isolated, internal, external
            ("scan_allowed", "BOOLEAN DEFAULT 1"),
        ]
        
        for column_name, column_type in host_columns:
            try:
                await conn.execute(
                    text(f"ALTER TABLE hosts ADD COLUMN {column_name} {column_type}")
                )
            except Exception:
                pass  # Column already exists
        
        # List of columns to add to findings table
        findings_columns = [
            ("collector_mode", "VARCHAR DEFAULT 'local'"),
            ("evidence", "TEXT"),
            ("data_confidence", "VARCHAR DEFAULT 'high'"),
        ]
        
        for column_name, column_type in findings_columns:
            try:
                await conn.execute(
                    text(f"ALTER TABLE findings ADD COLUMN {column_name} {column_type}")
                )
            except Exception:
                pass  # Column already exists
        
        # Add scan_id to packages table for scan-specific package tracking
        packages_columns = [
            ("scan_id", "INTEGER"),
        ]
        
        for column_name, column_type in packages_columns:
            try:
                await conn.execute(
                    text(f"ALTER TABLE packages ADD COLUMN {column_name} {column_type}")
                )
            except Exception:
                pass  # Column already exists
        
        # Add columns to scans table for scope control
        scans_columns = [
            ("scan_scope", "VARCHAR DEFAULT 'safe'"),  # safe, aggressive, stealth
            ("network_segment", "VARCHAR DEFAULT 'isolated'"),
            ("rate_limit", "INTEGER DEFAULT 100"),  # requests per second
        ]
        
        for column_name, column_type in scans_columns:
            try:
                await conn.execute(
                    text(f"ALTER TABLE scans ADD COLUMN {column_name} {column_type}")
                )
            except Exception:
                pass  # Column already exists
