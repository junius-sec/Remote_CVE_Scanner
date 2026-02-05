import asyncio
import subprocess
from typing import List, Dict, Optional
import re
import os


class PackageScanner:
    """Scan Linux packages on local or remote systems"""

    def __init__(self):
        self.supported_os = ["ubuntu", "debian", "centos", "rhel", "fedora"]

    async def scan_local_packages(self, os_type: str) -> List[Dict]:
        """Scan packages on the local system"""
        os_type = os_type.lower()

        if os_type in ["ubuntu", "debian"]:
            return await self._scan_dpkg()
        elif os_type in ["centos", "rhel", "fedora"]:
            return await self._scan_rpm()
        else:
            raise ValueError(f"Unsupported OS type: {os_type}")

    async def _scan_dpkg(self) -> List[Dict]:
        """Scan packages using dpkg (Debian/Ubuntu)"""
        try:
            result = await asyncio.create_subprocess_exec(
                "dpkg-query", "-W", "-f=${Package}\t${Version}\t${Architecture}\n",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await result.communicate()

            if result.returncode != 0:
                print(f"dpkg-query error: {stderr.decode()}")
                return []

            packages = []
            for line in stdout.decode().strip().split("\n"):
                if not line:
                    continue

                parts = line.split("\t")
                if len(parts) >= 2:
                    packages.append({
                        "name": parts[0],
                        "version": parts[1],
                        "architecture": parts[2] if len(parts) > 2 else "unknown",
                        "package_manager": "dpkg"
                    })

            return packages

        except Exception as e:
            print(f"Error scanning dpkg packages: {e}")
            return []

    async def _scan_rpm(self) -> List[Dict]:
        """Scan packages using rpm (CentOS/RHEL/Fedora)"""
        try:
            result = await asyncio.create_subprocess_exec(
                "rpm", "-qa", "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await result.communicate()

            if result.returncode != 0:
                print(f"rpm error: {stderr.decode()}")
                return []

            packages = []
            for line in stdout.decode().strip().split("\n"):
                if not line:
                    continue

                parts = line.split("\t")
                if len(parts) >= 2:
                    packages.append({
                        "name": parts[0],
                        "version": parts[1],
                        "architecture": parts[2] if len(parts) > 2 else "unknown",
                        "package_manager": "rpm"
                    })

            return packages

        except Exception as e:
            print(f"Error scanning rpm packages: {e}")
            return []

    async def detect_os_version(self) -> Dict[str, str]:
        """Detect OS type and version on local system"""
        try:
            if os.path.exists("/etc/os-release"):
                result = await asyncio.create_subprocess_exec(
                    "cat", "/etc/os-release",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await result.communicate()

                os_info = {}
                for line in stdout.decode().strip().split("\n"):
                    if "=" in line:
                        key, value = line.split("=", 1)
                        os_info[key] = value.strip('"')

                os_type = os_info.get("ID", "unknown").lower()
                os_version = os_info.get("VERSION_ID", "unknown")

                return {
                    "os_type": os_type,
                    "os_version": os_version,
                    "os_name": os_info.get("NAME", "Unknown")
                }

        except Exception as e:
            print(f"Error detecting OS: {e}")

        return {
            "os_type": "unknown",
            "os_version": "unknown",
            "os_name": "Unknown"
        }

    def get_package_categories(self) -> Dict[str, List[str]]:
        """Get package categories for filtering"""
        return {
            "system": [
                "linux-image", "linux-headers", "kernel", "linux-firmware",
                "sudo", "systemd", "bash", "glibc", "libc6", "coreutils", "util-linux"
            ],
            "web": [
                "apache", "nginx", "httpd", "lighttpd", "apache2", "tomcat"
            ],
            "database": [
                "mysql", "mariadb", "postgresql", "mongodb", "redis", "sqlite"
            ],
            "programming": [
                "python3", "python2", "python", "php", "ruby", "nodejs", "node",
                "openjdk", "java", "perl", "gcc", "g++"
            ],
            "security": [
                "openssh", "ssh", "openssl", "libssl", "gnutls", "libgnutls",
                "krb5", "libkrb"
            ],
            "network": [
                "curl", "wget", "bind", "dnsmasq", "net-tools", "iproute2",
                "iptables", "nftables"
            ],
            "libraries": [
                "zlib", "libz", "bzip2", "xz-utils", "libarchive",
                "libpng", "libjpeg", "libwebp", "imagemagick", "ffmpeg",
                "libxml", "expat", "json-c", "libjson"
            ],
            "desktop": [
                "xorg", "x11", "mesa", "gtk", "qt", "webkit", "gnome", "kde"
            ]
        }

    def count_packages_by_category(self, packages: List[Dict]) -> Dict[str, int]:
        """Count packages in each category"""
        categories = self.get_package_categories()
        counts = {cat: 0 for cat in categories.keys()}
        counts["other"] = 0

        for pkg in packages:
            pkg_name_lower = pkg["name"].lower()
            matched = False

            for category, keywords in categories.items():
                for keyword in keywords:
                    if pkg_name_lower == keyword or pkg_name_lower.startswith(keyword + "-") or pkg_name_lower.startswith(keyword):
                        counts[category] += 1
                        matched = True
                        break
                if matched:
                    break

            if not matched:
                counts["other"] += 1

        return counts

    def filter_critical_packages(self, packages: List[Dict], selected_categories: List[str] = None) -> List[Dict]:
        """Filter packages by selected categories"""
        if not selected_categories or "all" in selected_categories:
            # Return all packages
            packages.sort(key=lambda x: x["name"])
            print(f"스캔 대상: 전체 {len(packages)}개 패키지 (필터링 없음)")
            return packages

        categories = self.get_package_categories()
        filtered = []
        seen = set()

        for pkg in packages:
            pkg_name_lower = pkg["name"].lower()

            for category in selected_categories:
                if category == "other":
                    # Check if package doesn't match any category
                    matched_any = False
                    for cat_keywords in categories.values():
                        for keyword in cat_keywords:
                            if pkg_name_lower == keyword or pkg_name_lower.startswith(keyword + "-") or pkg_name_lower.startswith(keyword):
                                matched_any = True
                                break
                        if matched_any:
                            break

                    if not matched_any and pkg_name_lower not in seen:
                        filtered.append(pkg)
                        seen.add(pkg_name_lower)
                        break
                elif category in categories:
                    for keyword in categories[category]:
                        if pkg_name_lower == keyword or pkg_name_lower.startswith(keyword + "-") or pkg_name_lower.startswith(keyword):
                            if pkg_name_lower not in seen:
                                filtered.append(pkg)
                                seen.add(pkg_name_lower)
                            break

        filtered.sort(key=lambda x: x["name"])
        print(f"스캔 대상: {len(filtered)}개 패키지 (카테고리: {', '.join(selected_categories)})")

        if len(filtered) > 0:
            print(f"패키지 목록 샘플 (처음 10개):")
            for i, pkg in enumerate(filtered[:10], 1):
                print(f"   {i}. {pkg['name']} ({pkg['version']})")

        return filtered
