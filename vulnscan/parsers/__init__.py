"""
Parsers 패키지

패키지 매니저별 출력 파싱 및 버전 정규화
"""

from .base import BaseParser, PackageData
from .apk import ApkParser
from .dpkg import DpkgParser
from .rpm import RpmParser
from .opkg import OpkgParser
from .binary import BinaryParser
from .version_normalizer import VersionNormalizer

__all__ = [
    "BaseParser",
    "PackageData",
    "ApkParser",
    "DpkgParser",
    "RpmParser",
    "OpkgParser",
    "BinaryParser",
    "VersionNormalizer",
    "get_parser_for_pkg_manager",
]


def get_parser_for_pkg_manager(pkg_manager: str) -> BaseParser:
    """패키지 매니저에 맞는 파서 반환"""
    parsers = {
        "apk": ApkParser,
        "dpkg": DpkgParser,
        "rpm": RpmParser,
        "opkg": OpkgParser,
    }
    
    parser_class = parsers.get(pkg_manager)
    if parser_class:
        return parser_class()
    
    raise ValueError(f"Unknown package manager: {pkg_manager}")
