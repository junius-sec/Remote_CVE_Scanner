from pydantic import BaseModel
from typing import Optional
from datetime import datetime

# ...existing code...

class HostResponse(BaseModel):
    id: int
    hostname: str
    ip_address: str
    zone: Optional[str] = None
    os_type: Optional[str] = None
    os_version: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    last_scan: Optional[datetime] = None
    status: Optional[str] = None
    is_allowed: Optional[bool] = True
    ssh_port: Optional[int] = 22
    ssh_username: Optional[str] = None  # Allow None
    auth_method: Optional[str] = "key"
    ssh_key_path: Optional[str] = None  # Allow None
    tags: Optional[str] = None  # Allow None
    owner: Optional[str] = None  # Allow None
    description: Optional[str] = None  # Allow None
    last_discovery: Optional[datetime] = None
    distro_id: Optional[str] = None
    pkg_manager: Optional[str] = None
    arch: Optional[str] = None
    kernel_version: Optional[str] = None
    is_busybox: Optional[bool] = False
    has_systemd: Optional[bool] = True

    class Config:
        from_attributes = True  # For SQLAlchemy ORM compatibility

# ...existing code...